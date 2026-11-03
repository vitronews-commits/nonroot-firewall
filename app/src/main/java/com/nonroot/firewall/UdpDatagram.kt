package com.nonroot.firewall

/**
 * Validates a complete unfragmented IPv4 UDP datagram before any forwarding.
 * Pure parser: never creates sockets or changes device connectivity.
 */
object UdpDatagram {
    data class Parsed(
        val sourceIp: String,
        val destinationIp: String,
        val sourcePort: Int,
        val destinationPort: Int,
        val payload: ByteArray
    )
    private fun u8(bytes: ByteArray, index: Int) = bytes[index].toInt() and 255
    private fun u16(bytes: ByteArray, index: Int) = (u8(bytes, index) shl 8) or u8(bytes, index + 1)

    fun parseIpv4(packet: ByteArray): Parsed? {
        val header = PacketParser.parseIpv4(packet) ?: return null
        if (header.protocol != 17 || header.fragmented) return null
        val headerSize = (u8(packet, 0) and 15) * 4
        val ipTotalLength = u16(packet, 2)
        if (headerSize + 8 > ipTotalLength) return null
        val udpLength = u16(packet, headerSize + 4)
        if (udpLength < 8 || udpLength != ipTotalLength - headerSize) return null
        val sourcePort = header.sourcePort ?: return null
        val destinationPort = header.destinationPort ?: return null
        if (sourcePort == 0 || destinationPort == 0) return null
        return Parsed(
            header.source, header.destination, sourcePort, destinationPort,
            packet.copyOfRange(headerSize + 8, headerSize + udpLength)
        )
    }
}
