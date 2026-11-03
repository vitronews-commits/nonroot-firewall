package com.nonroot.firewall

import org.junit.Assert.*
import org.junit.Test

class UdpRelayTest {
    private val request = UdpDatagram.Parsed(
        "10.0.0.2", "127.0.0.1", 12345, 53, byteArrayOf(1, 2)
    )

    @Test fun deniedPacketsNeverCreateSockets() {
        var sockets = 0
        UdpRelay({ sockets++; error("Unexpected socket") }, {}).use { relay ->
            assertFalse(relay.submit(request, PacketPolicy.Result.BLOCK))
            assertFalse(relay.submit(request, PacketPolicy.Result.PENDING))
            assertFalse(relay.submit(request, PacketPolicy.Result.UNATTRIBUTED))
            assertFalse(relay.submit(request, PacketPolicy.Result.UNSUPPORTED))
        }
        assertEquals(0, sockets)
    }

    @Test fun malformedAddressRejectedBeforeSocketCreation() {
        UdpRelay({ error("Unexpected socket") }, {}).use { relay ->
            assertFalse(relay.submit(request.copy(destinationIp = "example.org"), PacketPolicy.Result.ALLOW))
            assertFalse(relay.submit(request.copy(destinationIp = "999.1.2.3"), PacketPolicy.Result.ALLOW))
            assertFalse(relay.submit(request.copy(destinationPort = 0), PacketPolicy.Result.ALLOW))
        }
    }

    @Test fun closedRelayRejectsNewWork() {
        val relay = UdpRelay({ error("Unexpected socket") }, {})
        relay.close()
        assertFalse(relay.submit(request, PacketPolicy.Result.ALLOW))
        relay.close()
    }
}
