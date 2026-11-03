package com.nonroot.firewall

import org.junit.Assert.*
import org.junit.Test

class UdpDatagramTest {
    private fun datagram(): ByteArray = ByteArray(32).apply {
        this[0] = 0x45
        this[2] = 0
        this[3] = 32
        this[9] = 17
        this[12] = 10
        this[15] = 2
        this[16] = 1
        this[19] = 1
        this[20] = 0x30
        this[21] = 0x39
        this[22] = 0
        this[23] = 53
        this[24] = 0
        this[25] = 12
        this[28] = 1
        this[29] = 2
        this[30] = 3
        this[31] = 4
    }
    @Test fun extractsPayloadAndPorts() {
        val parsed = UdpDatagram.parseIpv4(datagram())!!
        assertEquals(12345, parsed.sourcePort)
        assertEquals(53, parsed.destinationPort)
        assertArrayEquals(byteArrayOf(1, 2, 3, 4), parsed.payload)
    }
    @Test fun rejectsTruncatedUdpHeader() {
        assertNull(UdpDatagram.parseIpv4(datagram().copyOf(23)))
    }
    @Test fun rejectsIncorrectUdpLength() {
        val bytes = datagram()
        bytes[25] = 11
        assertNull(UdpDatagram.parseIpv4(bytes))
    }
    @Test fun rejectsFragmentedUdp() {
        val bytes = datagram()
        bytes[6] = 0x20
        assertNull(UdpDatagram.parseIpv4(bytes))
    }
    @Test fun rejectsTcp() {
        val bytes = datagram()
        bytes[9] = 6
        assertNull(UdpDatagram.parseIpv4(bytes))
    }
}
