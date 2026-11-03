package com.nonroot.firewall

import java.io.Closeable
import java.net.DatagramPacket
import java.net.DatagramSocket
import java.net.InetAddress
import java.net.InetSocketAddress
import java.net.SocketTimeoutException
import java.util.concurrent.atomic.AtomicBoolean

/**
 * Experimental persistent UDP flow. Exactly one receiver owns this socket.
 * The socket factory must return a VPN-protected, bound socket.
 * Not connected to TUN or VpnService.
 */
class UdpFlowSession(
    private val request: UdpDatagram.Parsed,
    private val socket: DatagramSocket,
    private val onReply: (ByteArray) -> Unit,
    private val idleMs: Long = 30_000
) : Closeable {
    private val closed = AtomicBoolean(false)
    @Volatile private var lastActivity = System.nanoTime()
    private val receiving = AtomicBoolean(false)

    init {
        require(idleMs in 1_000..300_000)
        require(socket.isBound && !socket.isClosed)
        val parts = request.destinationIp.split('.')
        require(parts.size == 4 && parts.all { p ->
            p.isNotEmpty() && p.all { it in '0'..'9' } && (p.toIntOrNull() ?: -1) in 0..255
        })
        val remote = InetAddress.getByAddress(ByteArray(4) { parts[it].toInt().toByte() })
        socket.connect(InetSocketAddress(remote, request.destinationPort))
        socket.soTimeout = 500
    }

    /** Caller must have independently authorized this packet. */
    @Synchronized
    fun send(payload: ByteArray): Boolean {
        if (closed.get() || payload.size > 1472) return false
        return try {
            socket.send(DatagramPacket(payload, payload.size))
            lastActivity = System.nanoTime()
            true
        } catch (_: Exception) {
            close()
            false
        }
    }

    /** Run on a dedicated worker. Never run two receivers for one session. */
    fun receiveLoop() {
        check(receiving.compareAndSet(false, true)) { "Receiver already started" }
        val buffer = ByteArray(2048)
        try {
            while (!closed.get()) {
                if ((System.nanoTime() - lastActivity) / 1_000_000 >= idleMs) break
                val incoming = DatagramPacket(buffer, buffer.size)
                try {
                    socket.receive(incoming)
                    lastActivity = System.nanoTime()
                    val reply = UdpResponsePacket.build(
                        request,
                        incoming.data.copyOfRange(incoming.offset, incoming.offset + incoming.length)
                    )
                    if (reply != null && !closed.get()) onReply(reply)
                } catch (_: SocketTimeoutException) {
                    // Wake periodically for idle expiration.
                }
            }
        } catch (_: Exception) {
            // A failed receiver cannot keep a flow alive.
        } finally {
            close()
        }
    }

    fun isClosed(): Boolean = closed.get() || socket.isClosed

    override fun close() {
        if (closed.compareAndSet(false, true)) socket.close()
    }
}
