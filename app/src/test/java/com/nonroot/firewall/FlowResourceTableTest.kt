package com.nonroot.firewall

import java.io.Closeable
import org.junit.Assert.*
import org.junit.Test

class FlowResourceTableTest {
    private class Resource : Closeable {
        var closes = 0
        override fun close() { closes++ }
    }
    private fun key(port: Int) = FlowKey(17, "10.0.0.2", port, "1.1.1.1", 53, NetworkKind.WIFI)

    @Test fun reusesResourceForSameFlow() {
        val table = FlowResourceTable<Resource>(2, 100)
        val resource = Resource()
        assertTrue(table.add(key(1234), resource, 0))
        assertSame(resource, table.get(key(1234), 50))
        assertFalse(table.add(key(1234), Resource(), 50))
        assertEquals(1, table.size())
        table.close()
        assertEquals(1, resource.closes)
    }

    @Test fun capacityIsBoundedAndIdleResourcesClose() {
        val table = FlowResourceTable<Resource>(1, 100)
        val first = Resource()
        assertTrue(table.add(key(1234), first, 0))
        assertFalse(table.add(key(1235), Resource(), 50))
        assertEquals(1, table.expire(100))
        assertEquals(1, first.closes)
        assertTrue(table.add(key(1235), Resource(), 101))
        table.close()
    }

    @Test fun closeRejectsFurtherWork() {
        val table = FlowResourceTable<Resource>()
        table.close()
        assertFalse(table.add(key(1234), Resource(), 0))
        assertNull(table.get(key(1234), 1))
    }

    @Test fun explicitRemovalClosesExactlyOnce() {
        val table = FlowResourceTable<Resource>(1, 100)
        val resource = Resource()
        assertTrue(table.add(key(1234), resource, 0))
        assertTrue(table.remove(key(1234)))
        assertFalse(table.remove(key(1234)))
        assertEquals(1, resource.closes)
        assertEquals(0, table.size())
        table.close()
        assertEquals(1, resource.closes)
    }

    @Test fun backwardsClockExpiresResources() {
        val table = FlowResourceTable<Resource>(1, 100)
        val resource = Resource()
        assertTrue(table.add(key(1234), resource, 200))
        assertEquals(1, table.expire(100))
        assertEquals(1, resource.closes)
    }
}
