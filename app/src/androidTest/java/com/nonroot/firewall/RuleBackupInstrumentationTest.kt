package com.nonroot.firewall

import androidx.test.platform.app.InstrumentationRegistry
import org.junit.Assert.*
import org.junit.Test

class RuleBackupInstrumentationTest {
    private val example=RuleBackup.Data(listOf(IpRule(null,"2001:db8::/32",NetworkKind.WIFI,Decision.BLOCK,443)),
        listOf(AppRule("android",null,Decision.BLOCK),AppRule("com.example.app",NetworkKind.MOBILE,Decision.ALLOW)))
    private fun rejected(bytes: ByteArray) {
        try { RuleBackup.decode(bytes); fail("Unsafe backup accepted") } catch(_: IllegalArgumentException) { } catch(_: org.json.JSONException) { } catch(_: java.nio.charset.CharacterCodingException) { }
    }
    @Test fun roundTripPreservesOrderingFamiliesAndSystemPackage() {
        assertEquals(example,RuleBackup.decode(RuleBackup.encode(example)))
    }
    @Test fun boundedUtf8AndUnknownVersionAreRejected() {
        rejected(ByteArray(RuleBackup.MAX_BYTES+1))
        rejected(byteArrayOf(0xc3.toByte(),0x28))
        rejected(String(RuleBackup.encode(example)).replace("\"version\": 1","\"version\": 2").toByteArray())
    }
    @Test fun invalidCidrPortNetworkAndDecisionRejectWholeArchive() {
        val original=String(RuleBackup.encode(example))
        for((before,after) in listOf("2001:db8::/32" to "example.com/32","443" to "65536","WIFI" to "SATELLITE","BLOCK" to "ALLOW_ALL"))
            rejected(original.replace(before,after).toByteArray())
    }
    @Test fun duplicateApplicationRulesAreRejected() {
        try { RuleBackup.encode(example.copy(apps=example.apps+example.apps.first())); fail() } catch(_: IllegalArgumentException) { }
    }
    @Test fun atomicApplyAndRejectedImportPreserveExistingData() {
        val context=InstrumentationRegistry.getInstrumentation().targetContext.createDeviceProtectedStorageContext()
        val prefs=context.getSharedPreferences("firewall_rules",0)
        val oldIp=prefs.getString("ip_rules",null); val oldApp=prefs.getString("app_rules",null)
        try {
            assertTrue(RuleBackup.apply(context,example))
            assertEquals(example.ips,RuleStore(context).load()); assertEquals(example.apps,AppRuleStore(context).load())
            val before=prefs.all.toMap()
            try { RuleBackup.apply(context,example.copy(ips=listOf(IpRule(null,"invalid",null,Decision.ALLOW)))); fail() } catch(_: IllegalArgumentException) { }
            assertEquals(before,prefs.all)
        } finally {
            val edit=prefs.edit()
            if(oldIp==null) edit.remove("ip_rules") else edit.putString("ip_rules",oldIp)
            if(oldApp==null) edit.remove("app_rules") else edit.putString("app_rules",oldApp)
            assertTrue(edit.commit())
        }
    }
}
