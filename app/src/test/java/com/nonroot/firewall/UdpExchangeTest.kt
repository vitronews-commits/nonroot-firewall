package com.nonroot.firewall

import org.junit.Assert.*
import org.junit.Test

class UdpExchangeTest {
    private val request = UdpDatagram.Parsed("10.0.0.2", "127.0.0.1", 12345, 53, byteArrayOf(1))
    @Test fun blockedPacketNeverOpensSocket() {
        var opened = false
        val exchange = UdpExchange { opened = true; error("must not open") }
        assertSame(UdpExchange.Outcome.Rejected,
            exchange.exchange(request, PacketPolicy.Result.BLOCK))
        assertFalse(opened)
    }
    @Test fun unattributedPacketNeverOpensSocket() {
        var opened = false
        val exchange = UdpExchange { opened = true; error("must not open") }
        assertSame(UdpExchange.Outcome.Rejected,
            exchange.exchange(request, PacketPolicy.Result.UNATTRIBUTED))
        assertFalse(opened)
    }
    @Test fun invalidDestinationNeverOpensSocket() {
        var opened = false
        val exchange = UdpExchange { opened = true; error("must not open") }
        assertSame(UdpExchange.Outcome.Rejected,
            exchange.exchange(request.copy(destinationIp = "example.com"), PacketPolicy.Result.ALLOW))
        assertFalse(opened)
    }
    @Test fun socketFailureIsRejected() {
        val exchange = UdpExchange { throw IllegalStateException("protect failed") }
        assertSame(UdpExchange.Outcome.Rejected,
            exchange.exchange(request, PacketPolicy.Result.ALLOW))
    }
}
