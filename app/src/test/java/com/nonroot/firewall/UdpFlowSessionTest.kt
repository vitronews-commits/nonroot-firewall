package com.nonroot.firewall

import java.net.DatagramSocket
import java.net.InetSocketAddress
import org.junit.Assert.*
import org.junit.Test

class UdpFlowSessionTest {
    private val request = UdpDatagram.Parsed(
        "10.0.0.2", "127.0.0.1", 12000, 53, byteArrayOf(1)
    )

    @Test fun closedSessionRejectsSend() {
        val socket = DatagramSocket(null).apply { bind(InetSocketAddress(0)) }
        val session = UdpFlowSession(request, socket, {})
        session.close()
        assertTrue(socket.isClosed)
        assertFalse(session.send(byteArrayOf(1)))
    }

    @Test fun oversizedDatagramIsRejected() {
        val socket = DatagramSocket(null).apply { bind(InetSocketAddress(0)) }
        UdpFlowSession(request, socket, {}).use { session ->
            assertFalse(session.send(ByteArray(1473)))
        }
    }

    @Test fun sessionExposesClosedState() {
        val socket = DatagramSocket(null).apply { bind(InetSocketAddress(0)) }
        val session = UdpFlowSession(request, socket, {})
        assertFalse(session.isClosed())
        session.close()
        assertTrue(session.isClosed())
    }

    @Test fun invalidRemoteAddressRejected() {
        val socket = DatagramSocket(null).apply { bind(InetSocketAddress(0)) }
        try {
            val invalid = request.copy(destinationIp = "not-an-ip")
            assertThrows(IllegalArgumentException::class.java) {
                UdpFlowSession(invalid, socket, {})
            }
        } finally {
            socket.close()
        }
    }
}
