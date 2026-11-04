package com.nonroot.firewall

import android.content.Intent
import android.net.VpnService
import android.os.Build
import androidx.test.platform.app.InstrumentationRegistry
import org.junit.Assert.*
import org.junit.Assume.assumeTrue
import org.junit.Test
import java.net.DatagramPacket
import java.net.DatagramSocket
import java.net.InetSocketAddress
import java.net.Socket
import java.net.SocketTimeoutException

/** Explicit emulator-only second stage. Run ONLY after the no-VPN suite succeeds. */
class VpnAcceptanceTest {
    @Test fun tunTcpUdpAttributionAndRuleRevocation() {
        val instrumentation=InstrumentationRegistry.getInstrumentation()
        assumeTrue(InstrumentationRegistry.getArguments().getString("vpnAcceptance")=="true")
        check(Build.FINGERPRINT.contains("generic", ignoreCase=true) ||
            Build.MODEL.contains("sdk", ignoreCase=true) ||
            Build.MODEL.contains("emulator", ignoreCase=true) ||
            Build.HARDWARE in listOf("ranchu","goldfish")) {
            "Explicit VPN acceptance requires emulator: model=${Build.MODEL}, hardware=${Build.HARDWARE}"
        }
        // Packet forwarding/return path is verified before permission or TUN activation.
        EngineSelfTest.verify({ Socket() },{ DatagramSocket(null) })
        val context=instrumentation.targetContext
        val appStore=AppRuleStore(context,RuleChangeBus::notifySaved)
        val ipStore=RuleStore(context,RuleChangeBus::notifySaved)
        val savedApps=appStore.load(); val savedIps=ipStore.load()
        fun shell(command: String): String = android.os.ParcelFileDescriptor.AutoCloseInputStream(instrumentation.uiAutomation.executeShellCommand(command)).use {
            String(it.readBytes(),Charsets.UTF_8)
        }
        val activity=instrumentation.startActivitySync(Intent(context,MainActivity::class.java).addFlags(Intent.FLAG_ACTIVITY_NEW_TASK))
        try {
            shell("appops set ${context.packageName} ACTIVATE_VPN allow")
            assertNull(VpnService.prepare(context))
            assertTrue(ipStore.save(emptyList()))
            assertTrue(appStore.save(listOf(AppRule(context.packageName,null,Decision.ALLOW))))
            context.startForegroundService(Intent(context,FirewallVpnService::class.java))
            val deadline=android.os.SystemClock.elapsedRealtimeNanos()+java.util.concurrent.TimeUnit.SECONDS.toNanos(30)
            while(EngineEvents.status!="RUNNING" && android.os.SystemClock.elapsedRealtimeNanos()<deadline) Thread.sleep(100)
            assertEquals(EngineEvents.snapshot().take(5).toString(),"RUNNING",EngineEvents.status)
            repeat(3) { context.startForegroundService(Intent(context,FirewallVpnService::class.java)) }
            Thread.sleep(250)
            assertEquals("RUNNING",EngineEvents.status)
            val probePackage="com.nonroot.firewall.probe"
            assertTrue(appStore.save(listOf(AppRule(probePackage,null,Decision.ALLOW))))
            var peakPss=android.os.Debug.getPss()
            fun probe(mode: String, onReady: ()->Unit = {}): String {
                val descriptor=instrumentation.uiAutomation.executeShellCommand(
                    "am instrument -w -e mode $mode -e durationSeconds 3600 $probePackage/.ProbeInstrumentation")
                val output=StringBuilder()
                android.os.ParcelFileDescriptor.AutoCloseInputStream(descriptor).bufferedReader().use { reader ->
                    while(true) {
                        val line=reader.readLine() ?: break
                        if(!line.contains("heartbeat=") && !line.contains("INSTRUMENTATION_STATUS_CODE")) output.append(line).append('\n')
                        if(line.contains("heartbeat=")) {
                            val memory=android.os.Debug.getPss(); peakPss=maxOf(peakPss,memory)
                            println("TUN_HEARTBEAT $line enginePssKiB=$memory activeFlows=${EngineEvents.liveConnections().size}")
                        }
                        if(line.contains("phase=READY")) onReady()
                    }
                }
                return output.toString()
            }
            val allowed=probe("allow")
            assertTrue(allowed.replace("\n"," | ")+" events="+EngineEvents.snapshot().take(12),allowed.contains("status=OK"))
            val events=EngineEvents.snapshot()
            for(port in listOf(28080,28081,28082,28083)) {
                assertTrue("Missing real probe transport on port $port: "+events.take(12),events.any {
                    it.connection?.packageName==probePackage && it.connection.port==port && it.result=="QUEUED"
                })
            }
            assertTrue("TCP payload did not traverse the TUN return path: "+events.take(12),events.any {
                it.connection?.packageName==probePackage && it.connection.port==28080 &&
                    it.result.startsWith("REPLY ") &&
                    (it.result.removePrefix("REPLY ").substringBefore(' ').toIntOrNull() ?: 0)>64
            })
            val systemDns=probe("system_dns")
            val systemDnsSupported=systemDns.contains("status=OK")
            val dnsIdentityEvidence=EngineEvents.snapshot().filter { it.result.contains(":53") }.take(8).toString()
            println("TUN_SYSTEM_DNS "+(if(systemDnsSupported) "PASS" else "FAIL")+" "+systemDns.replace("\n"," | ")+" "+dnsIdentityEvidence)
            if(systemDnsSupported) assertTrue("Missing per-app system DNS",EngineEvents.snapshot().any {
                it.connection?.packageName==probePackage && it.connection.port==53 && it.result=="QUEUED"
            })
            // Keep independent failures until the end so numeric transport/lifecycle diagnostics still execute.
            val halfClose=probe("half_close")
            val halfClosePassed=halfClose.contains("status=OK")
            println("TUN_CLIENT_FIRST_HALF_CLOSE "+(if(halfClosePassed) "PASS" else "FAIL")+" "+halfClose.replace("\n"," | "))
            if(InstrumentationRegistry.getArguments().getString("loadAcceptance")=="true") {
                val cpu=android.os.Process.getElapsedCpuTime(); val memory=android.os.Debug.getPss()
                val stress=probe(if(Build.VERSION.SDK_INT<30) "stress_payload" else "stress")
                assertTrue(stress.replace("\n"," | ")+" / events="+EngineEvents.snapshot().take(25),stress.contains("status=OK"))
                println("TUN_STRESS "+stress.replace("\n"," | ")+" engineCpuMs=${android.os.Process.getElapsedCpuTime()-cpu} enginePssBeforeKiB=$memory enginePssAfterKiB=${android.os.Debug.getPss()}")
            }
            if(InstrumentationRegistry.getArguments().getString("soakAcceptance")=="true") {
                val begin=android.os.SystemClock.elapsedRealtimeNanos(); val cpu=android.os.Process.getElapsedCpuTime(); val memory=android.os.Debug.getPss()
                val wake=context.getSystemService(android.os.PowerManager::class.java).newWakeLock(android.os.PowerManager.PARTIAL_WAKE_LOCK,"NonRootFirewallTest:soak")
                wake.acquire(java.util.concurrent.TimeUnit.MINUTES.toMillis(70))
                val soak=try {
                    shell("input keyevent 223"); Thread.sleep(500)
                    assertTrue("Screen did not enter sleep",shell("dumpsys power").contains("mWakefulness=Asleep"))
                    probe("soak")
                } finally { if(wake.isHeld) wake.release(); shell("input keyevent 224") }
                assertTrue(soak.replace("\n"," | "),soak.contains("status=OK"))
                assertTrue(java.util.concurrent.TimeUnit.NANOSECONDS.toMinutes(android.os.SystemClock.elapsedRealtimeNanos()-begin)>=60)
                println("TUN_SOAK enginePssPeakKiB=$peakPss screenOffAtStart=true "+soak.replace("\n"," | ")+" engineCpuMs=${android.os.Process.getElapsedCpuTime()-cpu} enginePssBeforeKiB=$memory enginePssAfterKiB=${android.os.Debug.getPss()}")
            }
            var sawReady=false
            val revoked=probe("tcp_hold") {
                sawReady=true
                assertTrue(ipStore.save(listOf(IpRule(null,"10.0.2.2/32",null,Decision.BLOCK,28080))))
            }
            assertTrue("Probe never confirmed an established echo connection: "+revoked.replace("\n"," | "),sawReady)
            assertTrue(revoked.replace("\n"," | "),revoked.contains("status=BLOCKED"))
            assertTrue(appStore.save(emptyList()))
            assertTrue(ipStore.save(emptyList()))
            val unknown=probe("udp_block")
            assertTrue(unknown.replace("\n"," | "),unknown.contains("status=BLOCKED"))
            assertTrue("Expected exact UDP Pending request: "+EngineEvents.pending.snapshot()+" / "+EngineEvents.snapshot().take(12),
                EngineEvents.pending.snapshot().any { it.connection.packageName==probePackage && it.connection.ip=="10.0.2.2" && it.connection.port==28081 })
            if(systemDnsSupported) {
                val deniedDns=probe("dns_block")
                assertTrue(deniedDns.replace("\n"," | "),deniedDns.contains("status=BLOCKED"))
                assertTrue("DNS did not reach exact per-app Pending policy",EngineEvents.pending.snapshot().any { it.connection.packageName==probePackage && it.connection.port==53 })
                println("TUN_DNS_DEFAULT_DENY PASS")
            } else println("TUN_DNS_DEFAULT_DENY NOT_TESTED_PER_APP; shared resolver remained blocked")
            // Toggle only emulator networking. Reconnect must rebuild DNS/routes while old TUN blocks.
            assertTrue(appStore.save(listOf(AppRule(probePackage,null,Decision.ALLOW))))
            try {
                shell("svc data enable"); shell("svc wifi disable")
                var limit=android.os.SystemClock.elapsedRealtimeNanos()+java.util.concurrent.TimeUnit.SECONDS.toNanos(30)
                while(EngineEvents.network==NetworkKind.WIFI && android.os.SystemClock.elapsedRealtimeNanos()<limit) Thread.sleep(100)
                assertNotEquals("Wi-Fi loss callback not observed",NetworkKind.WIFI,EngineEvents.network)
                if(EngineEvents.network==NetworkKind.MOBILE) {
                    while(EngineEvents.status!="RUNNING" && android.os.SystemClock.elapsedRealtimeNanos()<limit) Thread.sleep(100)
                    val mobile=probe("allow_mobile"); assertTrue(mobile.replace("\n"," | "),mobile.contains("status=OK"))
                    val mobileDns=probe("system_dns_mobile")
                    assertTrue(mobileDns.replace("\n"," | "),mobileDns.contains("status=OK"))
                    assertTrue("Mobile system DNS was not attributed",EngineEvents.snapshot().any { it.connection?.packageName==probePackage && it.connection.port==53 && it.connection.network==NetworkKind.MOBILE && it.result=="QUEUED" })
                    println("TUN_HANDOVER WIFI_TO_MOBILE PASS")
                } else {
                    while(EngineEvents.status=="RUNNING" && android.os.SystemClock.elapsedRealtimeNanos()<limit) Thread.sleep(100)
                    assertTrue("Offline gate not retained",EngineEvents.status.startsWith("WAITING"))
                    assertTrue(EngineEvents.liveConnections().isEmpty())
                    println("TUN_HANDOVER WIFI_TO_OFFLINE PASS; WIFI_TO_MOBILE NOT_TESTED (no cellular path)")
                }
            } finally { shell("svc wifi enable"); shell("svc data disable") }
            var limit=android.os.SystemClock.elapsedRealtimeNanos()+java.util.concurrent.TimeUnit.SECONDS.toNanos(45)
            while((EngineEvents.network!=NetworkKind.WIFI || EngineEvents.status!="RUNNING") && android.os.SystemClock.elapsedRealtimeNanos()<limit) Thread.sleep(100)
            assertEquals(NetworkKind.WIFI,EngineEvents.network); assertEquals("RUNNING",EngineEvents.status)
            val reconnect=probe("allow"); assertTrue(reconnect.replace("\n"," | "),reconnect.contains("status=OK"))
            println("TUN_RECONNECT WIFI_TCP_UDP_DNS PASS")
            repeat(2) {
                context.stopService(Intent(context,FirewallVpnService::class.java))
                limit=android.os.SystemClock.elapsedRealtimeNanos()+java.util.concurrent.TimeUnit.SECONDS.toNanos(10)
                while(EngineEvents.status!="OFF" && android.os.SystemClock.elapsedRealtimeNanos()<limit) Thread.sleep(50)
                assertEquals("OFF",EngineEvents.status); assertTrue(EngineEvents.liveConnections().isEmpty())
                context.startForegroundService(Intent(context,FirewallVpnService::class.java))
                limit=android.os.SystemClock.elapsedRealtimeNanos()+java.util.concurrent.TimeUnit.SECONDS.toNanos(30)
                while(EngineEvents.status!="RUNNING" && android.os.SystemClock.elapsedRealtimeNanos()<limit) Thread.sleep(100)
                assertEquals("RUNNING",EngineEvents.status)
                val restarted=probe("allow"); assertTrue(restarted.replace("\n"," | "),restarted.contains("status=OK"))
            }
            println("TUN_REPEATED_START_STOP PASS")
            context.stopService(Intent(context,FirewallVpnService::class.java))
            limit=android.os.SystemClock.elapsedRealtimeNanos()+java.util.concurrent.TimeUnit.SECONDS.toNanos(10)
            while(EngineEvents.status!="OFF" && android.os.SystemClock.elapsedRealtimeNanos()<limit) Thread.sleep(50)
            assertEquals("OFF",EngineEvents.status)
            val corrupt="[{\"cidr\":\"invalid\",\"decision\":\"BLOCK\"}]"
            val prefs=context.getSharedPreferences("firewall_rules",0)
            assertTrue(prefs.edit().putString("ip_rules",corrupt).commit())
            context.startForegroundService(Intent(context,FirewallVpnService::class.java))
            limit=android.os.SystemClock.elapsedRealtimeNanos()+java.util.concurrent.TimeUnit.SECONDS.toNanos(30)
            while(!EngineEvents.status.startsWith("ERROR") && android.os.SystemClock.elapsedRealtimeNanos()<limit) Thread.sleep(100)
            assertTrue("Corrupt bootstrap did not close policy",EngineEvents.status.startsWith("ERROR"))
            assertEquals(corrupt,prefs.getString("ip_rules",null))
            assertFalse(ipStore.save(emptyList()))
            val corruptBlocked=probe("udp_block")
            assertTrue(corruptBlocked.replace("\n"," | "),corruptBlocked.contains("status=BLOCKED"))
            assertTrue(RuleBackup.apply(context,RuleBackup.Data(emptyList(),listOf(AppRule(probePackage,null,Decision.ALLOW)))))
            limit=android.os.SystemClock.elapsedRealtimeNanos()+java.util.concurrent.TimeUnit.SECONDS.toNanos(10)
            while(EngineEvents.status!="RUNNING" && android.os.SystemClock.elapsedRealtimeNanos()<limit) Thread.sleep(50)
            assertEquals("RUNNING",EngineEvents.status)
            val repaired=probe("allow")
            assertTrue(repaired.replace("\n"," | "),repaired.contains("status=OK"))
            println("TUN_CORRUPT_BOOTSTRAP_AND_EXPLICIT_REPAIR PASS")

            assertTrue("System DNS attribution unsupported/failed: "+systemDns.replace("\n"," | ")+" "+dnsIdentityEvidence,systemDnsSupported)
            assertTrue("Clean client-first half-close failed (compare independent controls): "+halfClose.replace("\n"," | "),halfClosePassed)
        } finally {
            shell("svc wifi enable"); shell("svc data disable")
            context.stopService(Intent(context,FirewallVpnService::class.java))
            assertTrue(RuleBackup.apply(context,RuleBackup.Data(savedIps,savedApps)))
            shell("appops set ${context.packageName} ACTIVATE_VPN default")
            instrumentation.runOnMainSync { activity.finish() }
        }
    }
}
