package com.nonroot.firewall

import org.junit.Assert.*
import org.junit.Test

class NumericSafetyTest {
    @Test fun unicodeDigitsCannotBecomeDnsNamesInRules() {
        for(cidr in listOf("١٢٧.٠.٠.١/32","１２７.０.０.１/32")) assertFalse(RuleEngine.isValidCidr(cidr))
        assertTrue(RuleEngine.isValidCidr("127.0.0.1/32"))
    }
    @Test fun shortHexHostnamesAreRejectedBeforeAddressResolution() {
        for(name in listOf("face","deadbeef","abc.def")) {
            val h=PacketParser.Header("10.23.0.2",name,17,1234,53,false)
            try { NetworkDestination.resolve(h,null); fail("Hostname accepted: $name") } catch(_: IllegalArgumentException) { }
        }
    }
    @Test fun validChecksumMappedIpv6PacketsCannotChangeWireFamily() {
        val h=PacketParser.Header("fd23::2","2001:db8::4",17,1234,53,false)
        for(start in listOf(8,24)) {
            val raw=TransportPacket.build(h,byteArrayOf(1,3,5))
            val mapped=ByteArray(16); mapped[10]=0xff.toByte(); mapped[11]=0xff.toByte(); mapped[12]=192.toByte(); mapped[14]=2; mapped[15]=4
            mapped.copyInto(raw,start)
            TransportPacket.put16(raw,46,0)
            var sum=(raw.size-40).toLong()+17
            for(i in 8 until 40 step 2) sum+=TransportPacket.u16(raw,i)
            var i=40
            while(i+1<raw.size) { sum+=TransportPacket.u16(raw,i); i+=2 }
            if(i<raw.size) sum+=(raw[i].toInt() and 255) shl 8
            while(sum ushr 16!=0L) sum=(sum and 65535)+(sum ushr 16)
            val checksum=sum.toInt().inv() and 65535
            TransportPacket.put16(raw,46,if(checksum==0) 65535 else checksum)
            assertNull(TransportPacket.parse(raw))
        }
    }
}
