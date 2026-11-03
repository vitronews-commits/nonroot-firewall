package com.nonroot.firewall

/** Builds a complete IPv4 UDP response for delivery to a TUN interface.
 * No sockets are opened and this does not activate a VPN.
 */
object UdpResponsePacket {
    private fun put16(b: ByteArray, at: Int, value: Int) {
        b[at] = (value ushr 8).toByte()
        b[at + 1] = value.toByte()
    }
    private fun sum16(b: ByteArray, from: Int, to: Int, seed: Long = 0): Long {
        var sum = seed
        var i = from
        while (i + 1 < to) {
            sum += ((b[i].toInt() and 255) shl 8) or (b[i + 1].toInt() and 255)
            i += 2
        }
        if (i < to) sum += (b[i].toInt() and 255) shl 8
        return sum
    }
    private fun checksum(sumValue: Long): Int {
        var sum = sumValue
        while (sum ushr 16 != 0L) sum = (sum and 65535L) + (sum ushr 16)
        return (sum.toInt().inv() and 65535)
    }
    fun build(original: UdpDatagram.Parsed, responsePayload: ByteArray): ByteArray? {
        val source = parseV4(original.destinationIp) ?: return null
        val destination = parseV4(original.sourceIp) ?: return null
        val length = 20 + 8 + responsePayload.size
        if (length > 65535 || original.sourcePort !in 1..65535 ||
            original.destinationPort !in 1..65535) return null
        val packet = ByteArray(length)
        packet[0] = 0x45
        put16(packet, 2, length)
        packet[8] = 64
        packet[9] = 17
        source.copyInto(packet, 12)
        destination.copyInto(packet, 16)
        put16(packet, 20, original.destinationPort)
        put16(packet, 22, original.sourcePort)
        put16(packet, 24, 8 + responsePayload.size)
        responsePayload.copyInto(packet, 28)
        put16(packet, 10, checksum(sum16(packet, 0, 20)))
        // IPv4 pseudo-header: source + destination + zero/protocol + UDP length.
        var pseudo = sum16(packet, 12, 20)
        pseudo += 17 + (8 + responsePayload.size)
        val udpChecksum = checksum(sum16(packet, 20, length, pseudo))
        put16(packet, 26, if (udpChecksum == 0) 65535 else udpChecksum)
        return packet
    }
    private fun parseV4(value: String): ByteArray? {
        val parts = value.split('.')
        if (parts.size != 4) return null
        val values = parts.map { p ->
            if (p.isEmpty() || !p.all { it in '0'..'9' }) return null
            p.toIntOrNull()?.takeIf { it in 0..255 } ?: return null
        }
        return ByteArray(4) { values[it].toByte() }
    }
}
