package com.nonroot.firewall

import org.junit.Assert.*
import org.junit.Test

class JsonEnvelopeTest {
    @Test fun rejectsDeepNestingBeforeRecursiveParser() {
        try { JsonEnvelope.validate("[".repeat(10000)+"]".repeat(10000)); fail() } catch(_: IllegalArgumentException) { }
    }
    @Test fun understandsQuotedBracketsAndEscapes() {
        JsonEnvelope.validate("{\"value\":\"[\\\"}\\\\\",\"list\":[{}]}")
    }
    @Test fun rejectsUnbalancedIncompleteAndControlCharacters() {
        for(s in listOf("[}","{","\"unterminated","{\"x\":\"\n\"}")) {
            try { JsonEnvelope.validate(s); fail("Accepted $s") } catch(_: IllegalArgumentException) { }
        }
    }
}
