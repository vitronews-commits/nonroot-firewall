package com.nonroot.firewall

import org.junit.Assert.assertEquals
import org.junit.Test

class ForwardingGateTest {
    @Test fun allowCannotForwardWithoutWorkingTransport() {
        assertEquals(ForwardingGate.Action.DROP_NO_TRANSPORT,
            ForwardingGate { false }.action(PacketPolicy.Result.ALLOW))
    }
    @Test fun allowCanForwardOnlyWhenTransportReady() {
        assertEquals(ForwardingGate.Action.FORWARD,
            ForwardingGate { true }.action(PacketPolicy.Result.ALLOW))
    }
    @Test fun unknownAndPendingNeverForwardEvenWhenReady() {
        val gate = ForwardingGate { true }
        assertEquals(ForwardingGate.Action.HOLD_PENDING, gate.action(PacketPolicy.Result.PENDING))
        assertEquals(ForwardingGate.Action.DROP_UNATTRIBUTED, gate.action(PacketPolicy.Result.UNATTRIBUTED))
        assertEquals(ForwardingGate.Action.DROP_UNSUPPORTED, gate.action(PacketPolicy.Result.UNSUPPORTED))
    }
    @Test fun explicitBlockAlwaysWins() {
        assertEquals(ForwardingGate.Action.DROP_BLOCKED,
            ForwardingGate { true }.action(PacketPolicy.Result.BLOCK))
    }
}
