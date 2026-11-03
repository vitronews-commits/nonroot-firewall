package com.nonroot.firewall

import java.io.Closeable
import java.net.DatagramSocket
import java.util.concurrent.Executors
import java.util.concurrent.RejectedExecutionException
import java.util.concurrent.atomic.AtomicBoolean

/**
 * Experimental bounded persistent UDP session manager.
 * Socket factory MUST return VPN-protected and bound sockets.
 * No TUN integration; no VPN activation.
 */
class UdpSessionManager(
    private val socketFactory: () -> DatagramSocket,
    private val onReply: (ByteArray) -> Unit,
    private val capacity: Int = 4,
    private val idleMs: Long = 30_000
) : Closeable {
    init {
        require(capacity in 1..16)
        require(idleMs in 1_000..300_000)
    }

    private val closed = AtomicBoolean(false)
    private val executor = Executors.newFixedThreadPool(capacity)
    private val sessions = LinkedHashMap<FlowKey, UdpFlowSession>()
    private val rulesChangedListener: () -> Unit = { onRulesChanged() }

    init { RuleChangeBus.register(rulesChangedListener) }

    /** Only explicitly ALLOWed packets can create or use sessions. */
    @Synchronized
    fun submit(key: FlowKey, request: UdpDatagram.Parsed, policy: PacketPolicy.Result): Boolean {
        if (policy != PacketPolicy.Result.ALLOW) {
            sessions.remove(key)?.close()
            return false
        }
        if (closed.get() ||
            key.protocol != 17 || key.sourceIp != request.sourceIp ||
            key.destinationIp != request.destinationIp ||
            key.sourcePort != request.sourcePort ||
            key.destinationPort != request.destinationPort ||
            request.payload.size > 1472 ||
            request.sourcePort !in 1..65535 ||
            request.destinationPort !in 1..65535) return false

        val existing = sessions[key]
        if (existing != null) {
            if (!existing.isClosed()) return existing.send(request.payload)
            sessions.remove(key)
        }
        if (sessions.size >= capacity) return false

        val socket = try { socketFactory() } catch (_: Exception) { return false }
        val session = try {
            UdpFlowSession(request, socket, onReply, idleMs)
        } catch (_: Exception) {
            socket.close()
            return false
        }
        sessions[key] = session
        return try {
            executor.execute {
                try { session.receiveLoop() }
                finally {
                    synchronized(this) {
                        if (sessions[key] === session) sessions.remove(key)
                    }
                }
            }
            if (!session.send(request.payload)) {
                sessions.remove(key)
                session.close()
                false
            } else true
        } catch (_: RejectedExecutionException) {
            sessions.remove(key)
            session.close()
            false
        }
    }

    /** Revalidate every active flow immediately after firewall rules change. */
    @Synchronized
    fun revokeWhere(shouldRevoke: (FlowKey) -> Boolean): Int {
        var removed = 0
        val iterator = sessions.entries.iterator()
        while (iterator.hasNext()) {
            val entry = iterator.next()
            if (shouldRevoke(entry.key)) {
                entry.value.close()
                iterator.remove()
                removed++
            }
        }
        return removed
    }

    fun onRulesChanged(): Int = revokeWhere { true }

    @Synchronized
    fun activeCount(): Int = sessions.size

    @Synchronized
    override fun close() {
        if (!closed.compareAndSet(false, true)) return
        sessions.values.forEach { it.close() }
        sessions.clear()
        executor.shutdownNow()
        RuleChangeBus.unregister(rulesChangedListener)
    }
}
