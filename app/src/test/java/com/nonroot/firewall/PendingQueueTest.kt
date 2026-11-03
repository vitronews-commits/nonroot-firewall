package com.nonroot.firewall

import org.junit.Assert.*
import org.junit.Test

class PendingQueueTest {
    private val a = Connection("com.example.a", "192.0.2.1", 443, NetworkKind.WIFI)
    private val b = Connection("com.example.b", "192.0.2.2", 443, NetworkKind.WIFI)

    @Test fun repeatedRequestDoesNotGrowQueue() {
        val queue = PendingQueue()
        assertTrue(queue.record(a, 10))
        assertFalse(queue.record(a, 20))
        assertEquals(1, queue.size())
        assertEquals(2, queue.snapshot().first().attempts)
        assertEquals(10L, queue.snapshot().first().firstSeenMs)
    }
    @Test fun boundedQueueEvictsOldest() {
        val queue = PendingQueue(1)
        queue.record(a, 1)
        queue.record(b, 2)
        assertEquals(listOf(b), queue.snapshot().map { it.connection })
    }
    @Test fun resolveRemovesOnlyMatchingRequest() {
        val queue = PendingQueue()
        queue.record(a, 1)
        queue.record(b, 2)
        assertNotNull(queue.resolve(a))
        assertNull(queue.resolve(a))
        assertEquals(listOf(b), queue.snapshot().map { it.connection })
    }
    @Test(expected = IllegalArgumentException::class)
    fun rejectsZeroCapacity() { PendingQueue(0) }
}
