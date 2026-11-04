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
            val payload="verified-through-real-TUN".toByteArray()
            Socket().use { socket ->
                socket.soTimeout=5000
                socket.connect(InetSocketAddress("10.0.2.2",28080),5000)
                socket.getOutputStream().write(payload)
                val received=ByteArray(payload.size)
                java.io.DataInputStream(socket.getInputStream()).readFully(received)
                assertArrayEquals(payload,received)
                DatagramSocket().use { udp ->
                    udp.soTimeout=5000
                    udp.connect(InetSocketAddress("10.0.2.2",28081))
                    udp.send(DatagramPacket(payload,payload.size))
                    val reply=DatagramPacket(ByteArray(128),128); udp.receive(reply)
                    assertArrayEquals(payload,reply.data.copyOf(reply.length))
                }
                assertTrue("UID attribution did not reach engine",EngineEvents.snapshot().any {
                    it.connection?.packageName==context.packageName && it.result=="FORWARDED"
                })
                assertTrue(ipStore.save(listOf(IpRule(null,"10.0.2.2/32",null,Decision.BLOCK,28080))))
                socket.getOutputStream().write(payload)
                try { assertEquals(-1,socket.getInputStream().read()) } catch(_: SocketTimeoutException) { }
            }
            assertTrue(appStore.save(emptyList()))
            assertTrue(ipStore.save(emptyList()))
            DatagramSocket().use { udp ->
                udp.soTimeout=1000; udp.connect(InetSocketAddress("10.0.2.2",28081))
                udp.send(DatagramPacket(payload,payload.size))
                try { udp.receive(DatagramPacket(ByteArray(128),128)); fail("Unknown app traffic escaped policy") }
                catch(_: SocketTimeoutException) { }
            }
            assertTrue(EngineEvents.pending.snapshot().any { it.connection.packageName==context.packageName })
        } finally {
            context.stopService(Intent(context,FirewallVpnService::class.java))
            appStore.save(savedApps); ipStore.save(savedIps)
            shell("appops set ${context.packageName} ACTIVATE_VPN default")
            instrumentation.runOnMainSync { activity.finish() }
        }
    }
}
