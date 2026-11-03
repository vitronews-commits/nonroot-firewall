package com.nonroot.firewall

/**
 * Boundary between UI/policy and future native packet processing.
 *
 * Implementations MUST call Android VpnService.protect() on upstream sockets
 * before connecting them to avoid VPN routing loops.
 *
 * A packet may be forwarded only when policy returns ALLOW.
 * BLOCK and PENDING are both fail-closed. The pending queue stores metadata
 * only: it does not retain payloads or promise to resume an existing socket.
 */
interface FirewallEngine {
    val isRunning: Boolean
    fun start(): EngineResult
    fun stop()
}

sealed class EngineResult {
    object Started : EngineResult()
    data class Unavailable(val reason: String) : EngineResult()
}

/** Explicitly unavailable until packet forwarding and policy enforcement exist. */
class UnavailableFirewallEngine : FirewallEngine {
    override val isRunning: Boolean = false
    override fun start(): EngineResult =
        EngineResult.Unavailable("Packet processing engine is not integrated")
    override fun stop() = Unit
}

/**
 * Single policy gate to be used by the packet engine once integrated.
 * Unknown connections are recorded for review and NEVER granted access.
 */
class ConnectionGate(
    private val rules: RuleEngine,
    private val pending: PendingQueue
) {
    fun evaluate(connection: Connection, nowMs: Long): Decision {
        val decision = rules.decide(connection)
        if (decision == Decision.PENDING) pending.record(connection, nowMs)
        else pending.resolve(connection)
        return decision
    }
}
