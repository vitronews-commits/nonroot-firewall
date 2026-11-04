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
        assumeTrue(Build.FINGERPRINT.contains("generic") || Build.MODEL.contains("sdk"))
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
                    "am instrument -w -e mode $mode $probePackage/.ProbeInstrumentation")
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
            assertTrue(allowed+"\n"+EngineEvents.snapshot().take(12),allowed.contains("status=OK"))
            assertTrue("Separate-UID attribution did not reach engine: "+EngineEvents.snapshot().take(12),EngineEvents.snapshot().any {
                it.connection?.packageName==probePackage && it.result=="FORWARDED"
            })
            val revoked=probe("tcp_hold") {
                assertTrue(ipStore.save(listOf(IpRule(null,"10.0.2.2/32",null,Decision.BLOCK,28080))))
            }
            assertTrue(revoked,revoked.contains("status=BLOCKED"))
            assertTrue(appStore.save(emptyList()))
            assertTrue(ipStore.save(emptyList()))
            val unknown=probe("udp_block")
            assertTrue(unknown,unknown.contains("status=BLOCKED"))
            assertTrue(EngineEvents.pending.snapshot().any { it.connection.packageName==probePackage })
        } finally {
            context.stopService(Intent(context,FirewallVpnService::class.java))
            appStore.save(savedApps); ipStore.save(savedIps)
            shell("appops set ${context.packageName} ACTIVATE_VPN default")
            instrumentation.runOnMainSync { activity.finish() }
        }
    }
}
