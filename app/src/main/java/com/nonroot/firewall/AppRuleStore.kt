package com.nonroot.firewall

import android.content.Context
import org.json.JSONArray
import org.json.JSONObject

/** Persist per-app decisions separately from IP/CIDR rules. */
class AppRuleStore(context: Context, private val onRulesSaved: () -> Unit = {}) {
    private val prefs = context.getSharedPreferences("firewall_rules", Context.MODE_PRIVATE)

    fun load(strict: Boolean=false): MutableList<AppRule> {
        val output = mutableListOf<AppRule>()
        val arr = try { JSONArray(prefs.getString("app_rules", "[]")) } catch (e: Exception) { if(strict) throw IllegalStateException("Malformed saved rules",e); JSONArray() }
        for (i in 0 until arr.length()) {
            try {
                val obj = arr.getJSONObject(i)
                if(strict) { for(key in listOf("packageName","decision")) require(obj.get(key) is String); require(!obj.has("network") || obj.get("network") is String) }
                val pkg = obj.getString("packageName")
                if (pkg.isBlank()) { check(!strict) { "Malformed saved package" }; continue }
                val kind = obj.optString("network").takeIf { it.isNotBlank() }?.let(NetworkKind::valueOf)
                val decision = Decision.valueOf(obj.getString("decision"))
                if (decision == Decision.PENDING) { check(!strict) { "Pending is not a saved app decision" }; continue }
                output.add(AppRule(pkg, kind, decision))
            } catch (e: Exception) { if(strict) throw IllegalStateException("Malformed saved app rule",e) }
        }
        return output
    }

    fun save(rules: List<AppRule>): Boolean {
        val array = JSONArray()
        rules.forEach { rule ->
            require(rule.packageName.isNotBlank())
            array.put(JSONObject().apply {
                put("packageName", rule.packageName)
                put("network", rule.network?.name ?: "")
                put("decision", rule.decision.name)
            })
        }
        val saved = prefs.edit().putString("app_rules", array.toString()).commit()
        if (saved) onRulesSaved()
        return saved
    }
}
