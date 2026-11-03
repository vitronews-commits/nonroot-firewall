package com.nonroot.firewall

/**
 * Bounded, deduplicated requests for an eventual packet-processing integration.
 * This is a policy-side model, not a packet buffer or a live VPN queue.
 */
class PendingQueue(private val capacity: Int = 200) {
    init { require(capacity > 0) }
    data class Request(val connection: Connection, val firstSeenMs: Long, val attempts: Int)
    private val entries = LinkedHashMap<Connection, Request>()

    @Synchronized fun record(connection: Connection, nowMs: Long): Boolean {
        val old = entries[connection]
        if (old != null) {
            entries[connection] = old.copy(attempts = old.attempts + 1)
            return false
        }
        if (entries.size >= capacity) entries.remove(entries.keys.first())
        entries[connection] = Request(connection, nowMs, 1)
        return true
    }

    @Synchronized fun resolve(connection: Connection): Request? = entries.remove(connection)
    @Synchronized fun snapshot(): List<Request> = entries.values.toList()
    @Synchronized fun clear() = entries.clear()
    @Synchronized fun size(): Int = entries.size
}
