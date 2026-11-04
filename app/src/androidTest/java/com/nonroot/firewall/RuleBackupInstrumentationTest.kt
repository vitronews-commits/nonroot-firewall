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
        val archive=org.json.JSONObject(String(RuleBackup.encode(example))).put("version",2)
        rejected(archive.toString().toByteArray())
    }
    @Test fun invalidCidrPortNetworkAndDecisionRejectWholeArchive() {
        for((key,value) in listOf("cidr" to "example.com/32","port" to 65536,"network" to "SATELLITE","decision" to "ALLOW_ALL")) {
            val archive=org.json.JSONObject(String(RuleBackup.encode(example)))
            archive.getJSONArray("ipRules").getJSONObject(0).put(key,value)
            rejected(archive.toString().toByteArray())
        }
    }
    @Test fun duplicateApplicationRulesAreRejected() {
        try { RuleBackup.encode(example.copy(apps=example.apps+example.apps.first())); fail() } catch(_: IllegalArgumentException) { }
    }
    @Test fun strictEngineLoadRejectsCorruptionWithoutRewritingData() {
        val context=InstrumentationRegistry.getInstrumentation().targetContext.createDeviceProtectedStorageContext()
        val prefs=context.getSharedPreferences("firewall_rules",0)
        val old=prefs.getString("ip_rules",null)
        try {
            val broken="[{\"cidr\":\"broken\",\"decision\":\"BLOCK\"}]"
            assertTrue(prefs.edit().putString("ip_rules",broken).commit())
            try { RuleStore(context).load(strict=true); fail("Corrupt block silently ignored") } catch(_: IllegalStateException) { }
            assertFalse(RuleStore(context).save(emptyList()))
            assertEquals(broken,prefs.getString("ip_rules",null))
        } finally { val edit=prefs.edit(); if(old==null) edit.remove("ip_rules") else edit.putString("ip_rules",old); assertTrue(edit.commit()) }
    }
    @Test fun corruptAppRulesCannotBeSilentlyReplacedByNormalEdit() {
        val context=InstrumentationRegistry.getInstrumentation().targetContext.createDeviceProtectedStorageContext()
        val prefs=context.getSharedPreferences("firewall_rules",0)
        val previous=prefs.getString("app_rules",null)
        val broken="[{\"packageName\":\"\",\"decision\":\"BLOCK\"}]"
        try {
            assertTrue(prefs.edit().putString("app_rules",broken).commit())
            assertFalse(AppRuleStore(context).save(emptyList()))
            assertEquals(broken,prefs.getString("app_rules",null))
        } finally {
            val edit=prefs.edit()
            if(previous==null) edit.remove("app_rules") else edit.putString("app_rules",previous)
            assertTrue(edit.commit())
        }
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
