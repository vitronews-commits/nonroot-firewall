package com.nonroot.firewall

import java.io.Closeable

/**
 * Bounded lifecycle manager for per-flow resources.
 * Resource creation and actual network I/O remain outside this class.
 */
class FlowResourceTable<T : Closeable>(
    private val capacity: Int = 32,
    private val idleTimeoutMs: Long = 30_000
) : Closeable {
    init {
        require(capacity > 0)
        require(idleTimeoutMs > 0)
    }

    private data class Entry<T>(val resource: T, var touched: Long)
    private val entries = LinkedHashMap<FlowKey, Entry<T>>()
    private var closed = false

    @Synchronized
    fun add(key: FlowKey, resource: T, nowMs: Long): Boolean {
        if (closed || entries.containsKey(key)) return false
        expire(nowMs)
        if (entries.size >= capacity) return false
        entries[key] = Entry(resource, nowMs)
        return true
    }

    @Synchronized
    fun get(key: FlowKey, nowMs: Long): T? {
        if (closed) return null
        expire(nowMs)
        val entry = entries[key] ?: return null
        entry.touched = nowMs
        return entry.resource
    }

    @Synchronized
    fun expire(nowMs: Long): Int {
        var count = 0
        val iterator = entries.entries.iterator()
        while (iterator.hasNext()) {
            val entry = iterator.next().value
            if (nowMs < entry.touched || nowMs - entry.touched >= idleTimeoutMs) {
                iterator.remove()
                entry.resource.close()
                count++
            }
        }
        return count
    }

    @Synchronized
    fun size(): Int = entries.size

    @Synchronized
    override fun close() {
        if (closed) return
        closed = true
        entries.values.forEach { it.resource.close() }
        entries.clear()
    }
}
