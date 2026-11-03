package com.nonroot.firewall

/** Policy evaluation is only possible after trustworthy Android UID/package attribution. */
object PacketPolicy {
    enum class Result { ALLOW, BLOCK, PENDING, UNATTRIBUTED, UNSUPPORTED }
    fun evaluateWithOwner(
        packet: PacketParser.Header?,
        ownerPackages: List<String>?,
        network: NetworkKind,
        engine: RuleEngine
    ): Result {
        val unique = ownerPackages?.distinct()?.singleOrNull()
        return evaluate(packet, unique, network, engine)
    }

    fun evaluate(
        packet: PacketParser.Header?,
        packageName: String?,
        network: NetworkKind,
        engine: RuleEngine
    ): Result {
        if (packet == null) return Result.UNSUPPORTED
        if (packageName.isNullOrBlank()) return Result.UNATTRIBUTED
        val port = packet.destinationPort ?: return Result.UNSUPPORTED
        return when (engine.decide(Connection(packageName, packet.destination, port, network))) {
            Decision.ALLOW -> Result.ALLOW
            Decision.BLOCK -> Result.BLOCK
            Decision.PENDING -> Result.PENDING
        }
    }
}
