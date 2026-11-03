package com.nonroot.firewall

/**
 * Process-local bridge between successful rule persistence and a future firewall engine.
 * No VPN or network side effects. An engine may register its own invalidation listener.
 */
object RuleChangeBus {
    private val listeners = LinkedHashSet<() -> Unit>()

    @Synchronized
    fun register(listener: () -> Unit) {
        listeners.add(listener)
    }

    @Synchronized
    fun unregister(listener: () -> Unit) {
        listeners.remove(listener)
    }

    fun notifySaved() {
        val snapshot = synchronized(this) { listeners.toList() }
        snapshot.forEach { listener ->
            try { listener() } catch (_: Exception) { /* isolate listeners */ }
        }
    }
}
