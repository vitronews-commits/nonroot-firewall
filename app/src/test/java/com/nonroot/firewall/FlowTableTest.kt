package com.nonroot.firewall

import org.junit.Assert.*
import org.junit.Test

class FlowTableTest {
    private fun key(port: Int) = FlowKey(17, "10.0.0.2", port, "1.1.1.1", 53, NetworkKind.WIFI)
    @Test fun storesAndExpiresOwner() {
        val table = FlowTable(idleTimeoutMs = 1000)
        table.remember(key(1234), "app.one", 100)
        assertEquals("app.one", table.owner(key(1234), 500))
        assertNull(table.owner(key(1234), 1500))
    }
    @Test fun evictsOldestWhenCapacityReached() {
        val table = FlowTable(maxEntries = 2)
        table.remember(key(1), "app.one", 1)
        table.remember(key(2), "app.two", 2)
        table.remember(key(3), "app.three", 3)
        assertEquals(2, table.size())
        assertNull(table.owner(key(1), 3))
    }
    @Test fun rejectsFragmentsAndMissingPorts() {
        val packet = PacketParser.Header("10.0.0.2", "1.1.1.1", 17, 1234, 53, true)
        assertNull(FlowKey.fromPacket(packet, NetworkKind.WIFI))
        assertNull(FlowKey.fromPacket(packet.copy(fragmented = false, destinationPort = null), NetworkKind.WIFI))
    }
    @Test fun networkIsPartOfFlowIdentity() {
        assertNotEquals(key(1234), key(1234).copy(network = NetworkKind.MOBILE))
    }
}
