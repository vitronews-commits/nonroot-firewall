package com.nonroot.firewall

import org.junit.Assert.assertEquals
import org.junit.Test

class RuleChangeBusTest {
    @Test fun notificationIsDeliveredAndCanBeUnregistered() {
        var count = 0
        val listener: () -> Unit = { count++ }
        RuleChangeBus.register(listener)
        try {
            RuleChangeBus.notifySaved()
            assertEquals(1, count)
        } finally {
            RuleChangeBus.unregister(listener)
        }
        RuleChangeBus.notifySaved()
        assertEquals(1, count)
    }

    @Test fun listenerFailureDoesNotPreventOtherListeners() {
        var count = 0
        val broken: () -> Unit = { throw IllegalStateException("test") }
        val healthy: () -> Unit = { count++ }
        RuleChangeBus.register(broken)
        RuleChangeBus.register(healthy)
        try {
            RuleChangeBus.notifySaved()
            assertEquals(1, count)
        } finally {
            RuleChangeBus.unregister(broken)
            RuleChangeBus.unregister(healthy)
        }
    }
}
