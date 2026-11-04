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

    @Test fun allowedRequestUsesLocalUdpResponder() {
        DatagramSocket(0, java.net.InetAddress.getByAddress(byteArrayOf(127, 0, 0, 1))).use { server ->
            server.soTimeout = 2000
            val latch = java.util.concurrent.CountDownLatch(1)
            val received = java.util.concurrent.atomic.AtomicReference<ByteArray>()
            val responder = Thread {
                try {
                    val incoming = java.net.DatagramPacket(ByteArray(64), 64)
                    server.receive(incoming)
                    server.send(java.net.DatagramPacket(byteArrayOf(7), 1, incoming.address, incoming.port))
                } catch (_: Exception) { }
            }
            responder.start()
            val req = request().copy(destinationPort = server.localPort)
            val flow = key().copy(destinationPort = server.localPort)
            UdpSessionManager({
                DatagramSocket(null).apply { bind(InetSocketAddress(0)) }
            }, { bytes -> received.set(bytes); latch.countDown() }).use { manager ->
                assertTrue(manager.submit(flow, req, PacketPolicy.Result.ALLOW))
                assertTrue(latch.await(3, java.util.concurrent.TimeUnit.SECONDS))
                assertTrue(UdpChecksums.verify(received.get()))
                assertArrayEquals(byteArrayOf(7), UdpDatagram.parseIpv4(received.get())!!.payload)
            }
            responder.join(1000)
        }
    }

    @Test fun capacityLimitRejectsSecondDistinctFlow() {
        val sockets = mutableListOf<DatagramSocket>()
        UdpSessionManager({
            DatagramSocket(null).apply {
                bind(InetSocketAddress(0))
                sockets.add(this)
            }
        }, {}, capacity = 1).use { manager ->
            assertTrue(manager.submit(key(), request(), PacketPolicy.Result.ALLOW))
            assertFalse(manager.submit(key(12001), request(12001), PacketPolicy.Result.ALLOW))
            assertEquals(1, sockets.size)
            assertEquals(1, manager.activeCount())
        }
        assertTrue(sockets.all { it.isClosed })
    }

    @Test fun sameFlowReusesExistingSocket() {
        var opened = 0
        UdpSessionManager({
            opened++
            DatagramSocket(null).apply { bind(InetSocketAddress(0)) }
        }, {}, capacity = 1).use { manager ->
            assertTrue(manager.submit(key(), request(), PacketPolicy.Result.ALLOW))
            assertTrue(manager.submit(key(), request(), PacketPolicy.Result.ALLOW))
            assertEquals(1, opened)
            assertEquals(1, manager.activeCount())
        }
    }

    @Test fun concurrentSameFlowNeverAllocatesExtraSocket() {
        val opened = java.util.concurrent.atomic.AtomicInteger()
        UdpSessionManager({
            opened.incrementAndGet()
            DatagramSocket(null).apply { bind(InetSocketAddress(0)) }
        }, {}, capacity = 1).use { manager ->
            val start = java.util.concurrent.CountDownLatch(1)
            val done = java.util.concurrent.CountDownLatch(8)
            val results = java.util.concurrent.CopyOnWriteArrayList<Boolean>()
            repeat(8) {
                Thread {
                    try {
                        start.await()
                        results.add(manager.submit(key(), request(), PacketPolicy.Result.ALLOW))
                    } finally {
                        done.countDown()
                    }
                }.start()
            }
            start.countDown()
            assertTrue(done.await(5, java.util.concurrent.TimeUnit.SECONDS))
            assertEquals(8, results.size)
            assertTrue(results.all { it })
            assertEquals(1, opened.get())
        }
    }

    @Test fun blockedRequestCannotReuseAllowedSession() {
        var opened = 0
        UdpSessionManager({
            opened++
            DatagramSocket(null).apply { bind(InetSocketAddress(0)) }
        }, {}, capacity = 1).use { manager ->
            assertTrue(manager.submit(key(), request(), PacketPolicy.Result.ALLOW))
            assertFalse(manager.submit(key(), request(), PacketPolicy.Result.BLOCK))
            assertEquals(1, opened)
        }
    }

    @Test fun bulkRevocationClosesSelectedSessions() {
        val sockets = mutableListOf<DatagramSocket>()
        UdpSessionManager({
            DatagramSocket(null).apply {
                bind(InetSocketAddress(0))
                sockets.add(this)
            }
        }, {}, capacity = 2).use { manager ->
            assertTrue(manager.submit(key(), request(), PacketPolicy.Result.ALLOW))
            assertTrue(manager.submit(key(12001), request(12001), PacketPolicy.Result.ALLOW))
            assertEquals(1, manager.revokeWhere { it.sourcePort == 12000 })
            assertEquals(1, manager.activeCount())
            assertTrue(sockets[0].isClosed)
            assertFalse(sockets[1].isClosed)
        }
        assertTrue(sockets.all { it.isClosed })
    }

    @Test fun ruleChangeInvalidatesAllSessions() {
        val sockets = mutableListOf<DatagramSocket>()
        UdpSessionManager({
            DatagramSocket(null).apply {
                bind(InetSocketAddress(0))
                sockets.add(this)
            }
        }, {}, capacity = 2).use { manager ->
            assertTrue(manager.submit(key(), request(), PacketPolicy.Result.ALLOW))
            assertTrue(manager.submit(key(12001), request(12001), PacketPolicy.Result.ALLOW))
            assertEquals(2, manager.onRulesChanged())
            assertEquals(0, manager.activeCount())
            assertTrue(sockets.all { it.isClosed })
        }
    }

    @Test fun ruleChangeEventClosesActiveSession() {
        val sockets = mutableListOf<DatagramSocket>()
        UdpSessionManager({
            DatagramSocket(null).apply {
                bind(InetSocketAddress(0))
                sockets.add(this)
            }
        }, {}, capacity = 1).use { manager ->
            assertTrue(manager.submit(key(), request(), PacketPolicy.Result.ALLOW))
            RuleChangeBus.notifySaved()
            assertEquals(0, manager.activeCount())
            assertTrue(sockets.all { it.isClosed })
        }
    }

    @Test fun failedExistingSocketCannotBeReused() {
        val sockets = mutableListOf<DatagramSocket>()
        UdpSessionManager({
            DatagramSocket(null).apply {
                bind(InetSocketAddress(0))
                sockets.add(this)
            }
        }, {}, capacity = 1).use { manager ->
            assertTrue(manager.submit(key(), request(), PacketPolicy.Result.ALLOW))
            sockets[0].close()
            assertFalse(manager.submit(key(), request(), PacketPolicy.Result.ALLOW))
            assertEquals(0, manager.activeCount())
            assertEquals(1, sockets.size)
        }
    }

    @Test fun invalidPortsCannotOpenSocket() {
        var opened = 0
        UdpSessionManager({
            opened++
            DatagramSocket(null).apply { bind(InetSocketAddress(0)) }
        }, {}).use { manager ->
            val invalid = request().copy(destinationPort = 0)
            val invalidKey = key().copy(destinationPort = 0)
            assertFalse(manager.submit(invalidKey, invalid, PacketPolicy.Result.ALLOW))
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
