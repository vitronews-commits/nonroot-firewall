package com.nonroot.firewall

/**
 * Pure routing gate. This class never opens sockets or a VPN interface.
 * Every packet requires an explicit policy decision before forwarding.
 */
class ForwardingGate(private val transportReady: () -> Boolean) {
    enum class Action {
        FORWARD,
        DROP_BLOCKED,
        HOLD_PENDING,
        DROP_UNATTRIBUTED,
        DROP_UNSUPPORTED,
        DROP_NO_TRANSPORT
    }

    fun action(result: PacketPolicy.Result): Action = when (result) {
        PacketPolicy.Result.BLOCK -> Action.DROP_BLOCKED
        PacketPolicy.Result.PENDING -> Action.HOLD_PENDING
        PacketPolicy.Result.UNATTRIBUTED -> Action.DROP_UNATTRIBUTED
        PacketPolicy.Result.UNSUPPORTED -> Action.DROP_UNSUPPORTED
        PacketPolicy.Result.ALLOW ->
            if (transportReady()) Action.FORWARD else Action.DROP_NO_TRANSPORT
    }
}
