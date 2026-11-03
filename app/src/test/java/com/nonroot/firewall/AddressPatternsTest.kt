package com.nonroot.firewall

import org.junit.Assert.*
import org.junit.Test

class AddressPatternsTest {
    @Test fun convertsClassicWildcardToCidr() {
        assertEquals("172.217.114.0/24", AddressPatterns.normalize("172.217.114.*"))
        assertEquals("172.217.0.0/16", AddressPatterns.normalize("172.217.*.*"))
        assertEquals("0.0.0.0/0", AddressPatterns.normalize("*"))
    }

    @Test fun rejectsMalformedWildcard() {
        assertNull(AddressPatterns.normalize("172.*.114.*"))
        assertNull(AddressPatterns.normalize("300.1.*.*"))
    }

    @Test fun suggestsBroaderRanges() {
        assertEquals(listOf("172.217.114.4", "172.217.114.*", "172.217.*.*", "172.*.*.*", "*"),
            AddressPatterns.suggestions("172.217.114.4"))
    }

    @Test fun portSpecificRuleOnlyMatchesThatPort() {
        val rules = RuleEngine()
        rules.ipRules.add(IpRule(null, "192.0.2.0/24", null, Decision.BLOCK, 443))
        val connection = Connection("com.example.app", "192.0.2.8", 443, NetworkKind.WIFI)
        assertEquals(Decision.BLOCK, rules.decide(connection))
        assertEquals(Decision.PENDING, rules.decide(connection.copy(port = 80)))
    }

    @Test fun separateNetworkDecisions() {
        val rules = RuleEngine()
        rules.ipRules.add(IpRule(null, "192.0.2.8/32", NetworkKind.WIFI, Decision.ALLOW, 443))
        rules.ipRules.add(IpRule(null, "192.0.2.8/32", NetworkKind.MOBILE, Decision.BLOCK, 443))
        val connection = Connection("com.example.app", "192.0.2.8", 443, NetworkKind.WIFI)
        assertEquals(Decision.ALLOW, rules.decide(connection))
        assertEquals(Decision.BLOCK, rules.decide(connection.copy(network = NetworkKind.MOBILE)))
    }
}
