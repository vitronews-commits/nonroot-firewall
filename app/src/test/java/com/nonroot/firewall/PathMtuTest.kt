package com.nonroot.firewall

import org.junit.Assert.*
import org.junit.Test

class PathMtuTest {
    private fun validChecksum(b: ByteArray,from: Int,end: Int,seed: Long=0): Boolean {
        var sum=seed; var i=from
        while(i+1<end) { sum+=TransportPacket.u16(b,i); i+=2 }
        if(i<end) sum+=(b[i].toInt() and 255) shl 8
        while(sum ushr 16!=0L) sum=(sum and 65535)+(sum ushr 16)
        return sum==65535L
    }
    @Test fun ipv4FragmentationNeededQuotesOriginalAndHasIndependentChecksums() {
        val h=PacketParser.Header("10.23.0.2","192.0.2.4",17,1234,443,false)
        val raw=TransportPacket.build(h,ByteArray(1400))
        val error=checkNotNull(PathMtu.response(raw,1280))
        assertEquals(3,error[20].toInt()); assertEquals(4,error[21].toInt()); assertEquals(1280,TransportPacket.u16(error,26))
        assertTrue(validChecksum(error,0,20)); assertTrue(validChecksum(error,20,error.size))
        assertArrayEquals(raw.copyOf(28),error.copyOfRange(28,error.size))
        assertEquals(h.source,PacketParser.parse(error)!!.destination)
    }
    @Test fun ipv6PacketTooBigUsesPseudoHeaderAndFitsMinimumMtu() {
        val h=PacketParser.Header("fd23::2","2001:db8::4",17,1234,443,false)
        val raw=TransportPacket.build(h,ByteArray(1400))
        val error=checkNotNull(PathMtu.response(raw,1280))
        assertEquals(1280,error.size); assertEquals(58,error[6].toInt()); assertEquals(2,error[40].toInt())
        assertEquals(1280,TransportPacket.u16(error,46))
        var pseudo=(error.size-40).toLong()+58
        for(i in 8 until 40 step 2) pseudo+=TransportPacket.u16(error,i)
        assertTrue(validChecksum(error,40,error.size,pseudo))
        assertArrayEquals(raw.copyOf(1232),error.copyOfRange(48,error.size))
    }
    @Test fun malformedSmallAndTcpPacketsDoNotGenerateMtuErrors() {
        assertNull(PathMtu.response(byteArrayOf(1),1280))
        val h=PacketParser.Header("10.23.0.2","192.0.2.4",17,1234,443,false)
        assertNull(PathMtu.response(TransportPacket.build(h,byteArrayOf(1)),1280))
        assertNull(PathMtu.response(TransportPacket.build(h.copy(protocol=6),ByteArray(1400),1,2,24),1280))
    }
    @Test fun deniedUdpCannotProduceIcmpOrAllocateSockets() {
        var outputs=0; var sockets=0
        PacketForwarder({ sockets++; java.net.Socket() },{ sockets++; java.net.DatagramSocket(null) },{ false },{ outputs++ },pathMtu={ 1280 }).use { f ->
            val h=PacketParser.Header("10.23.0.2","192.0.2.4",17,1234,443,false)
            assertFalse(f.accept(TransportPacket.build(h,ByteArray(1400))))
            assertEquals(0,sockets); assertEquals(0,outputs)
        }
    }
}
