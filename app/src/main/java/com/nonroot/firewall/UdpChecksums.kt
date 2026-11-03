package com.nonroot.firewall

/** Pure IPv4 UDP integrity checks, without network access. */
object UdpChecksums {
    private fun word(data: ByteArray, index: Int): Int =
        ((data[index].toInt() and 255) shl 8) or (data[index + 1].toInt() and 255)

    private fun sum(data: ByteArray, start: Int, end: Int, seed: Long = 0): Int {
        var value = seed
        var index = start
        while (index + 1 < end) {
            value += word(data, index)
            index += 2
        }
        if (index < end) value += (data[index].toInt() and 255) shl 8
        while (value > 65535) value = (value and 65535) + (value ushr 16)
        return value.toInt()
    }

    fun verify(packet: ByteArray): Boolean {
        if (packet.size < 28 || (packet[0].toInt() and 240) != 64) return false
        val header = (packet[0].toInt() and 15) * 4
        if (header < 20 || header + 8 > packet.size) return false
        val total = word(packet, 2)
        if (total < header + 8 || total > packet.size || packet[9].toInt() != 17) return false
        if ((word(packet, 6) and 0x3fff) != 0) return false
        if (sum(packet, 0, header) != 65535) return false
        val udpLength = word(packet, header + 4)
        if (udpLength != total - header) return false
        if (word(packet, header + 6) == 0) return true
        var pseudo = (17 + udpLength).toLong()
        for (i in 12 until 20 step 2) pseudo += word(packet, i)
        return sum(packet, header, total, pseudo) == 65535
    }
}
