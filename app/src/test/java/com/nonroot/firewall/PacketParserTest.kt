package com.nonroot.firewall

import org.junit.Assert.*
import org.junit.Test

class PacketParserTest {
    private fun packet(): ByteArray = ByteArray(24).apply {
        this[0] = 0x45
        this[2] = 0
        this[3] = 24
        this[9] = 6
        this[12] = 10
        this[13] = 1
        this[14] = 2
        this[15] = 3
        this[16] = 8
        this[17] = 8
        this[18] = 8
        this[19] = 8
        this[20] = 0x30
        this[21] = 0x39
        this[22] = 1
        this[23] = (0xbb).toByte()
    }
    @Test fun parsesIpv4TcpPorts() {
        val parsed = PacketParser.parseIpv4(packet())!!
        assertEquals("10.1.2.3", parsed.source)
        assertEquals("8.8.8.8", parsed.destination)
        assertEquals(6, parsed.protocol)
        assertEquals(12345, parsed.sourcePort)
        assertEquals(443, parsed.destinationPort)
    }
    @Test fun rejectsTruncatedPackets() {
        assertNull(PacketParser.parseIpv4(packet().copyOf(19)))
        assertNull(PacketParser.parseIpv4(packet().copyOf(23)))
    }
    @Test fun nonInitialFragmentDoesNotClaimPorts() {
        val bytes = packet()
        bytes[7] = 1
        val parsed = PacketParser.parseIpv4(bytes)!!
        assertTrue(parsed.fragmented)
        assertNull(parsed.destinationPort)
    }
    @Test fun rejectsInvalidHeaderLength() {
        val bytes = packet()
        bytes[0] = 0x44
        assertNull(PacketParser.parseIpv4(bytes))
    }
}
