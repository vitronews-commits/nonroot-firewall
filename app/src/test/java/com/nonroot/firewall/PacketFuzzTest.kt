package com.nonroot.firewall

import org.junit.Assert.*
import org.junit.Test
import kotlin.random.Random

/** Seeded, reproducible generative checks, no network and no permissive parser fallback. */
class PacketFuzzTest {
    @Test fun arbitraryPacketsNeverThrowOrGrowResources() {
        val random=Random(0x4657)
        repeat(25000) {
            val bytes=random.nextBytes(random.nextInt(0,2049))
            PacketParser.parse(bytes)
            TransportPacket.parse(bytes)?.let { p ->
                assertTrue(bytes.size<=1500)
                assertFalse(p.header.fragmented)
                assertTrue(p.header.protocol in listOf(6,17))
                assertTrue(p.header.sourcePort in 1..65535)
                assertTrue(p.header.destinationPort in 1..65535)
            }
        }
    }
    @Test fun generatedWireRoundTripsAndBitCorruptionIsRejected() {
        val random=Random(0x3436)
        repeat(3000) {
            val v6=random.nextBoolean(); val protocol=if(random.nextBoolean()) 6 else 17
            val h=PacketParser.Header(if(v6) "fd23::2" else "10.23.0.2",if(v6) "2001:db8::4" else "192.0.2.4",protocol,random.nextInt(1,65536),random.nextInt(1,65536),false)
            val payload=random.nextBytes(random.nextInt(1,1400))
            val raw=TransportPacket.build(h,payload,random.nextLong() and 0xffffffffL,42,24)
            val p=checkNotNull(TransportPacket.parse(raw)); assertArrayEquals(payload,p.payload)
            val corrupted=raw.copyOf(); val index=random.nextInt(if(v6) 40 else 20,raw.size)
            corrupted[index]=(corrupted[index].toInt() xor (1 shl random.nextInt(8))).toByte()
            assertNull(TransportPacket.parse(corrupted))
        }
    }
    @Test fun validFragmentsAndExtensionsNeverAcquireTransportPermission() {
        val h=PacketParser.Header("fd23::2","2001:db8::4",17,1234,53,false)
        for(extension in listOf(0,43,44,51,60,135)) {
            val b=TransportPacket.build(h,ByteArray(32)); b[6]=extension.toByte()
            assertNull(TransportPacket.parse(b))
        }
    }
}
