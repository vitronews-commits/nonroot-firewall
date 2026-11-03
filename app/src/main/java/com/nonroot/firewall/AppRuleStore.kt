package com.nonroot.firewall

import android.content.Context
import org.json.JSONArray
import org.json.JSONObject

/** Persist per-app decisions separately from IP/CIDR rules. */
class AppRuleStore(context: Context) {
    private val prefs = context.getSharedPreferences("firewall_rules", Context.MODE_PRIVATE)

    fun load(): MutableList<AppRule> {
        val output = mutableListOf<AppRule>()
        val arr = try { JSONArray(prefs.getString("app_rules", "[]")) } catch (_: Exception) { JSONArray() }
        for (i in 0 until arr.length()) {
            try {
                val obj = arr.getJSONObject(i)
                val pkg = obj.getString("packageName")
                if (pkg.isBlank()) continue
                val kind = obj.optString("network").takeIf { it.isNotBlank() }?.let(NetworkKind::valueOf)
                val decision = Decision.valueOf(obj.getString("decision"))
                if (decision == Decision.PENDING) continue
                output.add(AppRule(pkg, kind, decision))
            } catch (_: Exception) { }
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
        return prefs.edit().putString("app_rules", array.toString()).commit()
    }
}
