package com.nonroot.firewall

/**
 * Transport flow identity. A flow is direction-specific and scoped to the network.
 * Pure data: no socket, VPN or network operations.
 */
data class FlowKey(
    val protocol: Int,
    val sourceIp: String,
    val sourcePort: Int,
    val destinationIp: String,
    val destinationPort: Int,
    val network: NetworkKind
) {
    companion object {
        fun fromPacket(packet: PacketParser.Header, network: NetworkKind): FlowKey? {
            if (packet.fragmented || packet.protocol !in listOf(6, 17)) return null
            val sourcePort = packet.sourcePort ?: return null
            val destinationPort = packet.destinationPort ?: return null
            if (sourcePort !in 1..65535 || destinationPort !in 1..65535) return null
            return FlowKey(packet.protocol, packet.source, sourcePort,
                packet.destination, destinationPort, network)
        }
    }
}

/** Bounded flow bookkeeping, without retaining raw packets or personal payload data. */
class FlowTable(private val maxEntries: Int = 1024, private val idleTimeoutMs: Long = 120_000L) {
    init {
        require(maxEntries > 0)
        require(idleTimeoutMs > 0)
    }
    private data class Entry(val packageName: String, var lastSeenMs: Long)
    private val entries = LinkedHashMap<FlowKey, Entry>(16, 0.75f, true)

    @Synchronized
    fun remember(key: FlowKey, packageName: String, nowMs: Long) {
        require(packageName.isNotBlank())
        expire(nowMs)
        entries[key] = Entry(packageName, nowMs)
        while (entries.size > maxEntries) {
            val oldest = entries.keys.iterator()
            oldest.next()
            oldest.remove()
        }
    }

    @Synchronized
    fun owner(key: FlowKey, nowMs: Long): String? {
        expire(nowMs)
        val entry = entries[key] ?: return null
        entry.lastSeenMs = nowMs
        return entry.packageName
    }

    @Synchronized
    fun expire(nowMs: Long) {
        val iterator = entries.entries.iterator()
        while (iterator.hasNext()) {
            val entry = iterator.next().value
            if (nowMs < entry.lastSeenMs || nowMs - entry.lastSeenMs >= idleTimeoutMs) iterator.remove()
        }
    }

    @Synchronized
    fun clear() = entries.clear()

    @Synchronized
    fun size(): Int = entries.size
}
