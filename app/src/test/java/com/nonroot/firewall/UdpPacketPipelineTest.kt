package com.nonroot.firewall

import org.junit.Assert.*
import org.junit.Test

class UdpPacketPipelineTest {
    private fun packet(): ByteArray = ByteArray(29).apply {
        this[0] = 0x45
        this[3] = 29
        this[9] = 17
        this[12] = 10
        this[15] = 2
        this[16] = 1
        this[19] = 1
        this[20] = 0x30
        this[21] = 0x39
        this[23] = 53
        this[25] = 9
        this[28] = 42
    }

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

    @Test fun malformedUdpCannotForward() {
        UdpRelay({ error("socket must not open") }, {}).use { relay ->
            val pipeline = UdpPacketPipeline(RuleEngine(), relay) { true }
            assertEquals(UdpPacketPipeline.Status.UNSUPPORTED,
                pipeline.accept(packet().copyOf(25), listOf("app"), NetworkKind.WIFI))
        }
    }
}
