package com.nonroot.firewall

import org.junit.Assert.*
import org.junit.Test

class TunWriterTest {
    @Test fun transientBackpressureWaitsAndRetriesWholePacket() {
        val packet=byteArrayOf(1,2,3); var attempts=0; var waits=0; var checks=0
        val writer=TunWriter({ assertSame(packet,it); ++attempts>1 },{ waits++ },{ checks++; true })
        assertTrue(writer.write(packet)); assertEquals(2,attempts); assertEquals(1,waits); assertEquals(2,checks)
    }
    @Test fun revocationDuringWaitPreventsRetry() {
        var allowed=true; var attempts=0
        val writer=TunWriter({ attempts++; false },{ allowed=false },{ allowed })
        assertFalse(writer.write(byteArrayOf(1))); assertEquals(1,attempts)
    }
    @Test fun blockedWriterHasBoundedDeadline() {
        var now=0L; var waits=0
        val writer=TunWriter({ false },{ now+=it; waits++ },{ true },{ now },100)
        try { writer.write(byteArrayOf(1)); fail() } catch(_: java.net.SocketTimeoutException) { }
        assertEquals(2,waits)
    }
}
