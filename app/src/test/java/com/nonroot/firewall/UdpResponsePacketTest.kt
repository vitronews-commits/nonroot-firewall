package com.nonroot.firewall

import org.junit.Assert.*
import org.junit.Test

class UdpResponsePacketTest {
    private val request = UdpDatagram.Parsed("10.0.0.2", "1.1.1.1", 43210, 53, byteArrayOf(1))
    private fun word(b: ByteArray, at: Int) =
        ((b[at].toInt() and 255) shl 8) or (b[at + 1].toInt() and 255)
    private fun checksum(b: ByteArray): Int {
        var sum = 0L
        for (i in b.indices step 2) {
            sum += (b[i].toInt() and 255) shl 8
            if (i + 1 < b.size) sum += b[i + 1].toInt() and 255
        }
        while (sum ushr 16 != 0L) sum = (sum and 65535L) + (sum ushr 16)
        return sum.toInt() and 65535
    }
    @Test fun replyReversesAddressesAndPorts() {
        val bytes = UdpResponsePacket.build(request, byteArrayOf(7, 8, 9))!!
        val parsed = UdpDatagram.parseIpv4(bytes)!!
        assertEquals("1.1.1.1", parsed.sourceIp)
        assertEquals("10.0.0.2", parsed.destinationIp)
        assertEquals(53, parsed.sourcePort)
        assertEquals(43210, parsed.destinationPort)
        assertArrayEquals(byteArrayOf(7, 8, 9), parsed.payload)
        assertEquals(31, bytes.size)
    }
    @Test fun ipv4HeaderChecksumIsValid() {
        val bytes = UdpResponsePacket.build(request, byteArrayOf(7))!!
        assertEquals(65535, checksum(bytes.copyOfRange(0, 20)))
        assertNotEquals(0, word(bytes, 26))
    }
    @Test fun rejectsOversizedResponse() {
        assertNull(UdpResponsePacket.build(request, ByteArray(65508)))
    }
    @Test fun rejectsInvalidAddressesAndPorts() {
        assertNull(UdpResponsePacket.build(request.copy(destinationIp = "example.org"), byteArrayOf(1)))
        assertNull(UdpResponsePacket.build(request.copy(sourcePort = 0), byteArrayOf(1)))
    }
}
