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
        fun shell(command: String) {
            android.os.ParcelFileDescriptor.AutoCloseInputStream(instrumentation.uiAutomation.executeShellCommand(command)).use {
                it.readBytes()
            }
        }
        val activity=instrumentation.startActivitySync(Intent(context,MainActivity::class.java).addFlags(Intent.FLAG_ACTIVITY_NEW_TASK))
        try {
            shell("appops set ${context.packageName} ACTIVATE_VPN allow")
            assertNull(VpnService.prepare(context))
            assertTrue(ipStore.save(emptyList()))
            assertTrue(appStore.save(listOf(AppRule(context.packageName,null,Decision.ALLOW))))
            context.startForegroundService(Intent(context,FirewallVpnService::class.java))
            val deadline=System.nanoTime()+java.util.concurrent.TimeUnit.SECONDS.toNanos(30)
            while(EngineEvents.status!="RUNNING" && System.nanoTime()<deadline) Thread.sleep(100)
            assertEquals(EngineEvents.snapshot().take(5).toString(),"RUNNING",EngineEvents.status)
            val probePackage="com.nonroot.firewall.probe"
            assertTrue(appStore.save(listOf(AppRule(probePackage,null,Decision.ALLOW))))
            fun probe(mode: String, onReady: ()->Unit = {}): String {
                val descriptor=instrumentation.uiAutomation.executeShellCommand(
                    "am instrument -w -e mode $mode -e durationSeconds 3600 $probePackage/.ProbeInstrumentation")
                val output=StringBuilder()
                android.os.ParcelFileDescriptor.AutoCloseInputStream(descriptor).bufferedReader().use { reader ->
                    while(true) {
                        val line=reader.readLine() ?: break
                        output.append(line).append('\n')
                        if(line.contains("phase=READY")) onReady()
                    }
                }
                return output.toString()
            }
            val allowed=probe("allow")
            assertTrue(allowed.replace("\n"," | ")+" events="+EngineEvents.snapshot().take(12),allowed.contains("status=OK"))
            val events=EngineEvents.snapshot()
            for(port in listOf(28080,28081)) {
                assertTrue("Missing real probe transport on port $port: "+events.take(12),events.any {
                    it.connection?.packageName==probePackage && it.connection.port==port && it.result=="QUEUED"
                })
            }
            assertTrue("TCP payload did not traverse the TUN return path: "+events.take(12),events.any {
                it.connection?.packageName==probePackage && it.connection.port==28080 &&
                    it.result.startsWith("REPLY ") &&
                    (it.result.removePrefix("REPLY ").substringBefore(' ').toIntOrNull() ?: 0)>64
            })
            if(InstrumentationRegistry.getArguments().getString("loadAcceptance")=="true") {
                val cpu=android.os.Process.getElapsedCpuTime(); val memory=android.os.Debug.getPss()
                val stress=probe("stress")
                assertTrue(stress.replace("\n"," | "),stress.contains("status=OK"))
                println("TUN_STRESS "+stress.replace("\n"," | ")+" engineCpuMs=${android.os.Process.getElapsedCpuTime()-cpu} enginePssBeforeKiB=$memory enginePssAfterKiB=${android.os.Debug.getPss()}")
            }
            if(InstrumentationRegistry.getArguments().getString("soakAcceptance")=="true") {
                val begin=System.nanoTime(); val cpu=android.os.Process.getElapsedCpuTime(); val memory=android.os.Debug.getPss()
                val soak=probe("soak")
                assertTrue(soak.replace("\n"," | "),soak.contains("status=OK"))
                assertTrue(java.util.concurrent.TimeUnit.NANOSECONDS.toMinutes(System.nanoTime()-begin)>=60)
                println("TUN_SOAK "+soak.replace("\n"," | ")+" engineCpuMs=${android.os.Process.getElapsedCpuTime()-cpu} enginePssBeforeKiB=$memory enginePssAfterKiB=${android.os.Debug.getPss()}")
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
        } finally {
            context.stopService(Intent(context,FirewallVpnService::class.java))
            appStore.save(savedApps); ipStore.save(savedIps)
            shell("appops set ${context.packageName} ACTIVATE_VPN default")
            instrumentation.runOnMainSync { activity.finish() }
        }
    }
}
