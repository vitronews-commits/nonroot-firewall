package com.nonroot.firewall

import java.net.DatagramSocket
import java.net.InetSocketAddress
import org.junit.Assert.*
import org.junit.Test

class UdpSessionManagerTest {
    private fun request(port: Int = 12000) = UdpDatagram.Parsed(
        "10.0.0.2", "127.0.0.1", port, 53, byteArrayOf(1)
    )
    private fun key(port: Int = 12000) =
        FlowKey(17, "10.0.0.2", port, "127.0.0.1", 53, NetworkKind.WIFI)

    @Test fun pendingNeverOpensSocket() {
        var opened = 0
        UdpSessionManager({
            opened++
            DatagramSocket(null).apply { bind(InetSocketAddress(0)) }
        }, {}).use { manager ->
            assertFalse(manager.submit(key(), request(), PacketPolicy.Result.PENDING))
            assertEquals(0, opened)
            assertEquals(0, manager.activeCount())
        }
    }

    @Test fun mismatchedFlowRejectedBeforeOpeningSocket() {
        var opened = 0
        UdpSessionManager({
            opened++
            DatagramSocket(null).apply { bind(InetSocketAddress(0)) }
        }, {}).use { manager ->
            assertFalse(manager.submit(key(12001), request(), PacketPolicy.Result.ALLOW))
            assertEquals(0, opened)
        }
    }

    @Test fun closedManagerRejectsNewSessions() {
        val manager = UdpSessionManager({
            DatagramSocket(null).apply { bind(InetSocketAddress(0)) }
        }, {})
        manager.close()
        assertFalse(manager.submit(key(), request(), PacketPolicy.Result.ALLOW))
    }
}
