package com.nonroot.firewall

import java.net.InetAddress

/** Strict, bounded wire codec. Unsupported IPv6 extension headers fail closed. */
object TransportPacket {
    data class Packet(val header: PacketParser.Header, val payload: ByteArray,
                      val sequence: Long = 0, val acknowledgement: Long = 0,
                      val flags: Int = 0, val window: Int = 0)
    fun u16(b: ByteArray, i: Int) = ((b[i].toInt() and 255) shl 8) or (b[i+1].toInt() and 255)
    private fun u32(b: ByteArray, i: Int) = ((u16(b,i).toLong() shl 16) or u16(b,i+2).toLong())
    fun put16(b: ByteArray, i: Int, v: Int) { b[i]=(v ushr 8).toByte(); b[i+1]=v.toByte() }
    private fun put32(b: ByteArray, i: Int, v: Long) { put16(b,i,(v ushr 16).toInt()); put16(b,i+2,v.toInt()) }
    private fun sum(b: ByteArray, from: Int, end: Int, seed: Long = 0): Long {
        var s=seed; var i=from
        while(i+1<end) { s+=u16(b,i); i+=2 }
        if(i<end) s+=(b[i].toInt() and 255) shl 8
        return s
    }
    private fun fold(value: Long): Int {
        var s=value
        while(s ushr 16 != 0L) s=(s and 65535)+(s ushr 16)
        return s.toInt()
    }
    private fun pseudo(b: ByteArray, offset: Int, length: Int, protocol: Int): Long =
        sum(b,if(offset==20) 12 else 8,if(offset==20) 20 else 40) + length + protocol

    fun parse(b: ByteArray): Packet? {
        val h=PacketParser.parse(b) ?: return null
        if(h.fragmented || h.protocol !in listOf(6,17) || h.sourcePort !in 1..65535 || h.destinationPort !in 1..65535) return null
        val v4=(b[0].toInt() and 240)==64
        // IP options and IPv6 extensions are deliberately unsupported, never bypassed.
        val offset=if(v4) 20 else 40
        if(v4 && (b[0].toInt() and 15)!=5) return null
        if(!v4 && (b[6].toInt() and 255)!=h.protocol) return null
        val total=if(v4) u16(b,2) else 40+u16(b,4)
        if(total!=b.size || total>1500 || (v4 && fold(sum(b,0,20))!=65535)) return null
        val size=total-offset
        if(size < if(h.protocol==6) 20 else 8) return null
        val checksum=u16(b,offset+if(h.protocol==6) 16 else 6)
        if(!v4 && h.protocol==17 && checksum==0) return null
        if(!(v4 && h.protocol==17 && checksum==0) && fold(sum(b,offset,total,pseudo(b,offset,size,h.protocol)))!=65535) return null
        if(h.protocol==17) {
            if(u16(b,offset+4)!=size) return null
            return Packet(h,b.copyOfRange(offset+8,total))
        }
        val tcpSize=((b[offset+12].toInt() ushr 4) and 15)*4
        if(tcpSize<20 || tcpSize>size) return null
        return Packet(h,b.copyOfRange(offset+tcpSize,total),u32(b,offset+4),u32(b,offset+8),b[offset+13].toInt() and 255,u16(b,offset+14))
    }

    fun build(h: PacketParser.Header, payload: ByteArray, sequence: Long=0,
              acknowledgement: Long=0, flags: Int=0, window: Int=16384): ByteArray {
        val src=InetAddress.getByName(h.source).address
        val dst=InetAddress.getByName(h.destination).address
        require(src.size==dst.size && h.protocol in listOf(6,17))
        require(h.sourcePort in 1..65535 && h.destinationPort in 1..65535)
        val offset=if(src.size==4) 20 else 40
        val transport=if(h.protocol==6) 20 else 8
        val b=ByteArray(offset+transport+payload.size)
        require(b.size<=1500)
        if(offset==20) {
            b[0]=0x45; put16(b,2,b.size); b[8]=64; b[9]=h.protocol.toByte()
            src.copyInto(b,12); dst.copyInto(b,16)
            put16(b,10,fold(sum(b,0,20)).inv() and 65535)
        } else {
            b[0]=0x60; put16(b,4,b.size-40); b[6]=h.protocol.toByte(); b[7]=64
            src.copyInto(b,8); dst.copyInto(b,24)
        }
        put16(b,offset,h.sourcePort!!); put16(b,offset+2,h.destinationPort!!)
        if(h.protocol==6) {
            put32(b,offset+4,sequence); put32(b,offset+8,acknowledgement)
            b[offset+12]=0x50; b[offset+13]=flags.toByte(); put16(b,offset+14,window)
        } else put16(b,offset+4,transport+payload.size)
        payload.copyInto(b,offset+transport)
        val checksum=fold(sum(b,offset,b.size,pseudo(b,offset,b.size-offset,h.protocol))).inv() and 65535
        put16(b,offset+if(h.protocol==6) 16 else 6,if(checksum==0) 65535 else checksum)
        return b
    }
    fun reverse(h: PacketParser.Header)=PacketParser.Header(h.destination,h.source,h.protocol,h.destinationPort,h.sourcePort,false)
}
