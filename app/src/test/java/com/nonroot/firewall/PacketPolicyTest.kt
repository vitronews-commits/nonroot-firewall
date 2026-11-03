package com.nonroot.firewall

import org.junit.Assert.*
import org.junit.Test

class PacketPolicyTest {
    private fun ipv6(): ByteArray = ByteArray(44).apply {
        this[0] = 0x60
        this[5] = 4
        this[6] = 17
        this[8] = 0x20
        this[9] = 0x01
        this[10] = 0x0d
        this[11] = (0xb8).toByte()
        this[23] = 1
        this[24] = 0x20
        this[25] = 0x01
        this[26] = 0x0d
        this[27] = (0xb8).toByte()
        this[39] = 2
        this[40] = 0x30
        this[41] = 0x39
        this[42] = 0x01
        this[43] = (0xbb).toByte()
    }
    @Test fun ipv6UdpHeaderAndPorts() {
        val h = PacketParser.parse(ipv6())!!
        assertEquals(17, h.protocol)
        assertEquals(12345, h.sourcePort)
        assertEquals(443, h.destinationPort)
        assertTrue(h.destination.contains("2001:db8"))
    }
    @Test fun rejectsTruncatedIpv6Payload() {
        assertNull(PacketParser.parse(ipv6().copyOf(43)))
    }
    @Test fun unknownOwnerNeverInheritsAnotherAppsRule() {
        val engine = RuleEngine()
        engine.appRules.add(AppRule("example.app", NetworkKind.WIFI, Decision.ALLOW))
        assertEquals(PacketPolicy.Result.UNATTRIBUTED,
            PacketPolicy.evaluate(PacketParser.parse(ipv6()), null, NetworkKind.WIFI, engine))
    }
    @Test fun attributedAppDecisionIsApplied() {
        val engine = RuleEngine()
        engine.appRules.add(AppRule("example.app", NetworkKind.WIFI, Decision.BLOCK))
        assertEquals(PacketPolicy.Result.BLOCK,
            PacketPolicy.evaluate(PacketParser.parse(ipv6()), "example.app", NetworkKind.WIFI, engine))
    }
    @Test fun sharedUidDoesNotInheritOnePackagesAllowRule() {
        val engine = RuleEngine()
        engine.appRules.add(AppRule("trusted.app", NetworkKind.WIFI, Decision.ALLOW))
        val result = PacketPolicy.evaluateWithOwner(
            PacketParser.parse(ipv6()), listOf("trusted.app", "untrusted.app"), NetworkKind.WIFI, engine
        )
        assertEquals(PacketPolicy.Result.UNATTRIBUTED, result)
    }

    @Test fun singleOwnerCanUseAppRule() {
        val engine = RuleEngine()
        engine.appRules.add(AppRule("trusted.app", NetworkKind.WIFI, Decision.BLOCK))
        val result = PacketPolicy.evaluateWithOwner(
            PacketParser.parse(ipv6()), listOf("trusted.app"), NetworkKind.WIFI, engine
        )
        assertEquals(PacketPolicy.Result.BLOCK, result)
    }
}
