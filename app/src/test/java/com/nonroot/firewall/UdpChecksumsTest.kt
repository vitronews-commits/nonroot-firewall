package com.nonroot.firewall

import org.junit.Assert.*
import org.junit.Test

class UdpChecksumsTest {
    private fun validPacket(): ByteArray = UdpResponsePacket.build(
        UdpDatagram.Parsed("10.0.0.2", "1.1.1.1", 12345, 53, byteArrayOf(1)),
        byteArrayOf(10, 20, 30)
    )!!

    @Test fun acceptsCorrectChecksums() {
        assertTrue(UdpChecksums.verify(validPacket()))
    }

    @Test fun rejectsCorruptIpv4Header() {
        val packet = validPacket()
        packet[8] = (packet[8].toInt() xor 1).toByte()
        assertFalse(UdpChecksums.verify(packet))
    }

    @Test fun rejectsCorruptUdpPayload() {
        val packet = validPacket()
        packet[28] = (packet[28].toInt() xor 1).toByte()
        assertFalse(UdpChecksums.verify(packet))
    }

    @Test fun permitsZeroUdpChecksumOnIpv4() {
        val packet = validPacket()
        packet[26] = 0
        packet[27] = 0
        assertTrue(UdpChecksums.verify(packet))
    }

    @Test fun rejectsTruncatedAndFragmentedPackets() {
        val packet = validPacket()
        assertFalse(UdpChecksums.verify(packet.copyOf(24)))
        packet[6] = 0x20
        assertFalse(UdpChecksums.verify(packet))
    }
}
