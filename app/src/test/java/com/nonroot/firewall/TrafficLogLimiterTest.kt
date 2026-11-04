package com.nonroot.firewall

import org.junit.Assert.*
import org.junit.Test

class TrafficLogLimiterTest {
    private val h=PacketParser.Header("10.0.0.1","192.0.2.4",6,12000,443,false)
    @Test fun samplesPerFlowAndDirectionWithoutSuppressingFirstReply() {
        val limiter=TrafficLogLimiter()
        assertTrue(limiter.allow(h,0,0)); assertFalse(limiter.allow(h,0,999))
        assertTrue(limiter.allow(h,1,1)); assertTrue(limiter.allow(h,0,1000))
        limiter.clear(); assertTrue(limiter.allow(h,0,1001))
    }
    @Test fun boundedCapacityEvictsOldMetadata() {
        val limiter=TrafficLogLimiter(capacity=2)
        limiter.allow(h,0,0); limiter.allow(h.copy(sourcePort=12001),0,0); limiter.allow(h.copy(sourcePort=12002),0,0)
        assertTrue(limiter.allow(h,0,1))
    }
}
