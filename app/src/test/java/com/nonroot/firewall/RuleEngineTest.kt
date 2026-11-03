package com.nonroot.firewall

import org.junit.Assert.assertEquals
import org.junit.Test

class RuleEngineTest {
    private val chrome = Connection("com.android.chrome", "192.0.2.15", 443, NetworkKind.WIFI)

    @Test fun unknownConnectionIsPending() {
        assertEquals(Decision.PENDING, RuleEngine().decide(chrome))
    }
    @Test fun exactIpCanBeBlocked() {
        val engine = RuleEngine()
        engine.ipRules.add(IpRule("com.android.chrome", "192.0.2.15/32", null, Decision.BLOCK))
        assertEquals(Decision.BLOCK, engine.decide(chrome))
    }
    @Test fun specificIpOverridesAppAllow() {
        val engine = RuleEngine()
        engine.appRules.add(AppRule("com.android.chrome", null, Decision.ALLOW))
        engine.ipRules.add(IpRule("com.android.chrome", "192.0.2.0/24", null, Decision.BLOCK))
        assertEquals(Decision.BLOCK, engine.decide(chrome))
    }
    @Test fun networkSpecificRuleOnlyMatchesThatNetwork() {
        val engine = RuleEngine()
        engine.ipRules.add(IpRule("com.android.chrome", "192.0.2.15/32", NetworkKind.MOBILE, Decision.BLOCK))
        assertEquals(Decision.PENDING, engine.decide(chrome))
    }
    @Test fun ipv6AddressMatching() {
        val engine = RuleEngine()
        engine.ipRules.add(IpRule(null, "2001:db8::/32", null, Decision.BLOCK))
        assertEquals(Decision.BLOCK, engine.decide(chrome.copy(ip="2001:db8::1")))
    }

    @Test fun networkSpecificAppRuleOverridesGenericRuleRegardlessOfInsertionOrder() {
        val engine = RuleEngine()
        engine.appRules.add(AppRule("com.android.chrome", NetworkKind.WIFI, Decision.BLOCK))
        engine.appRules.add(AppRule("com.android.chrome", null, Decision.ALLOW))
        assertEquals(Decision.BLOCK, engine.decide(chrome))
        assertEquals(Decision.ALLOW, engine.decide(chrome.copy(network = NetworkKind.MOBILE)))
    }

    @Test fun malformedCidrIsRejected() {
        assertEquals(false, RuleEngine.isValidCidr("example.com/32"))
        assertEquals(false, RuleEngine.isValidCidr("256.1.2.3/32"))
        assertEquals(false, RuleEngine.isValidCidr("192.0.2.1/33"))
    }
}
