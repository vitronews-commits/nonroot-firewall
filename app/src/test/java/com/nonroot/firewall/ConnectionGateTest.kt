package com.nonroot.firewall

import org.junit.Assert.*
import org.junit.Test

class ConnectionGateTest {
    private val connection = Connection("com.example.test", "198.51.100.3", 443, NetworkKind.WIFI)

    @Test fun unknownConnectionsRemainPendingAndDeduplicated() {
        val pending = PendingQueue()
        val gate = ConnectionGate(RuleEngine(), pending)
        assertEquals(Decision.PENDING, gate.evaluate(connection, 10))
        assertEquals(Decision.PENDING, gate.evaluate(connection, 20))
        assertEquals(1, pending.size())
        assertEquals(2, pending.snapshot().first().attempts)
    }

    @Test fun approvingSpecificIpRemovesPendingRequest() {
        val rules = RuleEngine()
        val pending = PendingQueue()
        val gate = ConnectionGate(rules, pending)
        gate.evaluate(connection, 10)
        rules.ipRules.add(IpRule(connection.packageName, "198.51.100.3/32", null, Decision.ALLOW))
        assertEquals(Decision.ALLOW, gate.evaluate(connection, 20))
        assertEquals(0, pending.size())
    }

    @Test fun unavailableEngineCannotClaimProtection() {
        val engine = UnavailableFirewallEngine()
        assertFalse(engine.isRunning)
        assertTrue(engine.start() is EngineResult.Unavailable)
    }
}
