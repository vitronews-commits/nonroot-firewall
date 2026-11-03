package com.nonroot.firewall

/**
 * Off-tunnel IPv4 UDP pipeline, not attached to the VPN service.
 * The app owner must come from a trusted Android UID lookup, never from packet bytes.
 * No TUN interface is established here.
 */
class UdpPacketPipeline(
    private val engine: RuleEngine,
    private val relay: UdpRelay,
    private val transportReady: () -> Boolean,
    private val sessionManager: UdpSessionManager? = null
) {
    enum class Status {
        QUEUED, BLOCKED, PENDING, UNATTRIBUTED, UNSUPPORTED, NOT_READY, OVERLOADED
    }

    fun accept(
        rawPacket: ByteArray,
        ownerPackages: List<String>?,
        network: NetworkKind
    ): Status {
        val header = PacketParser.parse(rawPacket) ?: return Status.UNSUPPORTED
        if (header.protocol != 17 || header.fragmented) return Status.UNSUPPORTED
        if (!UdpChecksums.verify(rawPacket)) return Status.UNSUPPORTED
        val datagram = UdpDatagram.parseIpv4(rawPacket) ?: return Status.UNSUPPORTED
        val policy = PacketPolicy.evaluateWithOwner(header, ownerPackages, network, engine)
        val gate = ForwardingGate(transportReady)
        return when (gate.action(policy)) {
            ForwardingGate.Action.DROP_BLOCKED -> Status.BLOCKED
            ForwardingGate.Action.HOLD_PENDING -> Status.PENDING
            ForwardingGate.Action.DROP_UNATTRIBUTED -> Status.UNATTRIBUTED
            ForwardingGate.Action.DROP_UNSUPPORTED -> Status.UNSUPPORTED
            ForwardingGate.Action.DROP_NO_TRANSPORT -> Status.NOT_READY
            ForwardingGate.Action.FORWARD ->
                if (relay.submit(datagram, policy)) Status.QUEUED else Status.OVERLOADED
        }
    }
}
