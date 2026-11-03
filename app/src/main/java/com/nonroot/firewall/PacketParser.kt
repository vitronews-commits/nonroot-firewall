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
}
