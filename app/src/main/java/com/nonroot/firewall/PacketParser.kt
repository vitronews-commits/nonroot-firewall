package com.nonroot.firewall

/** Parses IPv4 packet headers without establishing or forwarding VPN traffic. */
object PacketParser {
    data class Header(val source: String, val destination: String, val protocol: Int,
                      val sourcePort: Int?, val destinationPort: Int?, val fragmented: Boolean)
    private fun byteAt(data: ByteArray, index: Int) = data[index].toInt() and 255
    private fun word(data: ByteArray, index: Int) = byteAt(data,index)*256+byteAt(data,index+1)
    fun parseIpv4(data: ByteArray): Header? {
        if (data.size < 20 || byteAt(data,0) shr 4 != 4) return null
        val headerSize = (byteAt(data,0) and 15)*4
        if (headerSize < 20 || headerSize > data.size) return null
        val total = word(data,2)
        if (total < headerSize || total > data.size) return null
        val fragment = word(data,6)
        val offset = fragment and 8191
        val fragmented = offset != 0 || fragment and 8192 != 0
        val protocol = byteAt(data,9)
        fun address(start: Int) = (start until start+4).joinToString(".") { byteAt(data,it).toString() }
        val portsPresent = offset == 0 && (protocol == 6 || protocol == 17) && total >= headerSize+4
        return Header(address(12),address(16),protocol,
            if (portsPresent) word(data,headerSize) else null,
            if (portsPresent) word(data,headerSize+2) else null,fragmented)
    }
    /** IPv6 including bounded extension-header traversal. Jumbo payloads are not supported. */
    fun parseIpv6(data: ByteArray): Header? {
        if (data.size < 40 || byteAt(data, 0) shr 4 != 6) return null
        val payload = word(data, 4)
        if (payload == 0 || payload > data.size - 40) return null
        val end = 40 + payload
        var protocol = byteAt(data, 6)
        var cursor = 40
        var fragmented = false
        var laterFragment = false
        var traversed = 0
        while (protocol in listOf(0, 43, 44, 51, 60, 135)) {
            if (++traversed > 12 || cursor + 2 > end) return null
            val next = byteAt(data, cursor)
            val size = when (protocol) {
                44 -> 8
                51 -> (byteAt(data, cursor + 1) + 2) * 4
                else -> (byteAt(data, cursor + 1) + 1) * 8
            }
            if (cursor + size > end) return null
            if (protocol == 44) {
                fragmented = true
                laterFragment = word(data, cursor + 2) and 0xfff8 != 0
            }
            cursor += size
            protocol = next
        }
        fun address(start: Int): String =
            java.net.InetAddress.getByAddress(data.copyOfRange(start, start + 16)).hostAddress ?: ""
        val portsPresent = !laterFragment && (protocol == 6 || protocol == 17) && cursor + 4 <= end
        return Header(address(8), address(24), protocol,
            if (portsPresent) word(data, cursor) else null,
            if (portsPresent) word(data, cursor + 2) else null, fragmented)
    }

    fun parse(data: ByteArray): Header? = when {
        data.isEmpty() -> null
        byteAt(data, 0) shr 4 == 4 -> parseIpv4(data)
        byteAt(data, 0) shr 4 == 6 -> parseIpv6(data)
        else -> null
    }

}
