package com.nonroot.firewall

import java.io.Closeable
import java.net.DatagramPacket
import java.net.DatagramSocket
import java.net.InetAddress
import java.net.InetSocketAddress
import java.net.SocketTimeoutException
import java.util.concurrent.Executors
import java.util.concurrent.atomic.AtomicBoolean

/**
 * Experimental asynchronous UDP relay, not wired to TUN or VpnService.
 * A caller MUST supply sockets protected with VpnService.protect() and
 * an already-authorized, unfragmented IPv4 datagram.
 *
 * Each exchange has its own socket, so responses cannot cross flow boundaries.
 * A bounded executor prevents unbounded thread creation under traffic bursts.
 */
class UdpRelay(
    private val socketFactory: () -> DatagramSocket,
    private val onReply: (ByteArray) -> Unit,
    private val timeoutMs: Int = 1500,
    workerCount: Int = 2
) : Closeable {
    init {
        require(timeoutMs in 1..10_000)
        require(workerCount in 1..4)
    }

    private val closed = AtomicBoolean(false)
    private val executor = java.util.concurrent.ThreadPoolExecutor(
        workerCount, workerCount, 0L, java.util.concurrent.TimeUnit.MILLISECONDS,
        java.util.concurrent.ArrayBlockingQueue<Runnable>(64),
        Executors.defaultThreadFactory(),
        java.util.concurrent.ThreadPoolExecutor.AbortPolicy()
    )

    /** Returns false when rejected, closed or overloaded. Never queues non-ALLOW packets. */
    fun submit(request: UdpDatagram.Parsed, policy: PacketPolicy.Result): Boolean {
        if (closed.get() || policy != PacketPolicy.Result.ALLOW) return false
        if (request.sourcePort !in 1..65535 || request.destinationPort !in 1..65535 ||
            request.payload.size > 1472) return false
        // Numeric literal validation, before DNS or socket creation.
        val octets = request.destinationIp.split('.')
        if (octets.size != 4 || octets.any {
            it.isEmpty() || !it.all(Char::isDigit) || it.toIntOrNull() !in 0..255
        }) return false
        return try {
            executor.execute {
                if (closed.get()) return@execute
                val result = UdpExchange(socketFactory).exchange(request, policy, timeoutMs)
                if (!closed.get() && result is UdpExchange.Outcome.Reply) {
                    try { onReply(result.packet) } catch (_: Exception) { /* isolate callback */ }
                }
            }
            true
        } catch (_: java.util.concurrent.RejectedExecutionException) {
            false
        }
    }

    override fun close() {
        if (closed.compareAndSet(false, true)) executor.shutdownNow()
    }
}
