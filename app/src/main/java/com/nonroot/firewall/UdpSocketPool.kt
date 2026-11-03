package com.nonroot.firewall

import java.io.Closeable
import java.net.DatagramSocket

/** Per-flow protected UDP socket cache. No VPN or packet I/O is performed here. */
class UdpSocketPool(
    private val openProtectedSocket: () -> DatagramSocket,
    capacity: Int = 32,
    idleMs: Long = 30_000
) : Closeable {
    private val table = FlowResourceTable<DatagramSocket>(capacity, idleMs)

    @Synchronized
    fun socket(key: FlowKey, nowMs: Long): DatagramSocket? {
        if (key.protocol != 17) return null
        table.get(key, nowMs)?.let {
            if (!it.isClosed) return it
            table.remove(key)
        }
        val candidate = try { openProtectedSocket() } catch (_: Exception) { return null }
        if (candidate.isClosed || !candidate.isBound) {
            candidate.close()
            return null
        }
        if (!table.add(key, candidate, nowMs)) {
            candidate.close()
            return table.get(key, nowMs)
        }
        return candidate
    }

    fun remove(key: FlowKey): Boolean = table.remove(key)
    fun expire(nowMs: Long): Int = table.expire(nowMs)
    fun size(): Int = table.size()
    override fun close() = table.close()
}
