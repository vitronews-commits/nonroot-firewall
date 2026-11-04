package com.nonroot.firewall

import org.junit.Assert.*
import org.junit.Test

class TransportMssTest {
    private val h=PacketParser.Header("10.23.0.2","127.0.0.1",6,41000,443,false)
    /** Independent RFC Internet checksums keep malformed-option tests checksum-valid. */
    private fun wire(options: ByteArray, flags: Int=2): ByteArray {
        require(options.size%4==0)
        val b=TransportPacket.build(h,byteArrayOf(),flags=flags).copyOf(40+options.size)
        TransportPacket.put16(b,2,b.size)
        b[32]=(((20+options.size)/4) shl 4).toByte()
        options.copyInto(b,40)
        fun checksum(start: Int, end: Int, seed: Int=0): Int {
            var sum=seed
            for(i in start until end step 2) sum+=TransportPacket.u16(b,i)
            while(sum ushr 16!=0) sum=(sum and 65535)+(sum ushr 16)
            return sum.inv() and 65535
        }
        TransportPacket.put16(b,10,0); TransportPacket.put16(b,10,checksum(0,20))
        TransportPacket.put16(b,36,0)
        var pseudo=6+b.size-20
        for(i in 12 until 20 step 2) pseudo+=TransportPacket.u16(b,i)
        TransportPacket.put16(b,36,checksum(20,b.size,pseudo))
        return b
    }
    @Test fun nopAndEndOfOptionsAreTraversedSafely() {
        assertEquals(512,TransportPacket.parse(wire(byteArrayOf(1,2,4,2,0,0,0,0)))!!.maximumSegmentSize)
        assertNull(TransportPacket.parse(wire(byteArrayOf(0,2,0,0)))!!.maximumSegmentSize)
    }
    @Test fun checksumValidMalformedOptionsAreRejected() {
        for(options in listOf(byteArrayOf(2,0,2,0),byteArrayOf(2,1,2,0),byteArrayOf(2,3,2,0),
            byteArrayOf(2,5,2,0),byteArrayOf(2,4,0,0),byteArrayOf(3,1,0,0),
            byteArrayOf(2,4,2,0,2,4,3,0))) assertNull(TransportPacket.parse(wire(options)))
        assertNull(TransportPacket.parse(wire(byteArrayOf(2,4,2,0),flags=16)))
    }
    @Test fun synMssRoundTripsInBothFamilies() {
        for(header in listOf(h,h.copy(source="fd23:23::2",destination="::1"))) {
            val raw=TransportPacket.build(header,byteArrayOf(),100,0,2,maximumSegmentSize=1400)
            val packet=TransportPacket.parse(raw)!!
            assertEquals(1400,packet.maximumSegmentSize)
            assertTrue(packet.payload.isEmpty())
            assertEquals(100L,packet.sequence)
        }
    }
    @Test fun absentOptionIsNotInvented() {
        assertNull(TransportPacket.parse(TransportPacket.build(h,byteArrayOf(),flags=2))!!.maximumSegmentSize)
    }
    @Test fun normalDataDoesNotGainTcpOptions() {
        val packet=TransportPacket.build(h,ByteArray(1460),flags=24)
        assertEquals(1500,packet.size)
        assertEquals(1460,TransportPacket.parse(packet)!!.payload.size)
    }
    @Test fun builderRejectsMssOutsideSynOrOnUdp() {
        for(header in listOf(h,h.copy(protocol=17))) {
            try { TransportPacket.build(header,byteArrayOf(),flags=16,maximumSegmentSize=1460); fail() }
            catch(_: IllegalArgumentException) {}
        }
    }
    @Test fun builderRejectsInvalidMss() {
        for(mss in listOf(0,-1,65536)) {
            try { TransportPacket.build(h,byteArrayOf(),flags=2,maximumSegmentSize=mss); fail() }
            catch(_: IllegalArgumentException) {}
        }
    }
}
