package com.nonroot.firewall

import org.junit.Assert.*
import java.net.DatagramSocket
import java.net.InetSocketAddress
import org.junit.Test

class UdpPacketPipelineTest {
    private fun packet(): ByteArray = UdpResponsePacket.build(
        UdpDatagram.Parsed("1.1.1.1", "10.0.0.2", 53, 12345, byteArrayOf(42)),
        byteArrayOf(42)
    )!!

    @Test fun missingOwnerCannotForward() {
        UdpRelay({ error("socket must not open") }, {}).use { relay ->
            val pipeline = UdpPacketPipeline(RuleEngine(), relay) { true }
            assertEquals(UdpPacketPipeline.Status.UNATTRIBUTED,
                pipeline.accept(packet(), null, NetworkKind.WIFI))
        }
    }

    @Test fun blockedAppCannotForward() {
        val engine = RuleEngine()
        engine.appRules.add(AppRule("blocked.app", NetworkKind.WIFI, Decision.BLOCK))
        UdpRelay({ error("socket must not open") }, {}).use { relay ->
            val pipeline = UdpPacketPipeline(engine, relay) { true }
            assertEquals(UdpPacketPipeline.Status.BLOCKED,
                pipeline.accept(packet(), listOf("blocked.app"), NetworkKind.WIFI))
        }
    }

    @Test fun allowRequiresTransportReady() {
        val engine = RuleEngine()
        engine.appRules.add(AppRule("allowed.app", NetworkKind.WIFI, Decision.ALLOW))
        UdpRelay({ error("socket must not open") }, {}).use { relay ->
            val pipeline = UdpPacketPipeline(engine, relay) { false }
            assertEquals(UdpPacketPipeline.Status.NOT_READY,
                pipeline.accept(packet(), listOf("allowed.app"), NetworkKind.WIFI))
        }
    }

    @Test fun persistentManagerStillHonorsTransportGate() {
        var opened = 0
        val engine = RuleEngine()
        engine.appRules.add(AppRule("allowed.app", NetworkKind.WIFI, Decision.ALLOW))
        UdpRelay({ error("legacy relay must not open") }, {}).use { relay ->
            UdpSessionManager({
                opened++
                DatagramSocket(null).apply { bind(InetSocketAddress(0)) }
            }, {}).use { manager ->
                val pipeline = UdpPacketPipeline(engine, relay, manager) { false }
                assertEquals(UdpPacketPipeline.Status.NOT_READY,
                    pipeline.accept(packet(), listOf("allowed.app"), NetworkKind.WIFI))
                assertEquals(0, opened)
            }
        }
    }

    @Test fun malformedUdpCannotForward() {
        UdpRelay({ error("socket must not open") }, {}).use { relay ->
            val pipeline = UdpPacketPipeline(RuleEngine(), relay) { true }
            assertEquals(UdpPacketPipeline.Status.UNSUPPORTED,
                pipeline.accept(packet().copyOf(25), listOf("app"), NetworkKind.WIFI))
        }
    }
}
