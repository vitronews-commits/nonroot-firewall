package com.nonroot.firewall

import android.content.Context
import org.json.JSONArray
import org.json.JSONObject

/** Local-only persistence. No networking or VPN side effects. */
class RuleStore(context: Context, private val onRulesSaved: () -> Unit = {}) {
    private val prefs = context.getSharedPreferences("firewall_rules", Context.MODE_PRIVATE)

    fun load(): MutableList<IpRule> {
        val result = mutableListOf<IpRule>()
        val array = try { JSONArray(prefs.getString("ip_rules", "[]")) } catch (_: Exception) { JSONArray() }
        for (i in 0 until array.length()) {
            try {
                val obj = array.getJSONObject(i)
                val cidr = obj.getString("cidr")
                if (!RuleEngine.isValidCidr(cidr)) continue
                result.add(IpRule(
                    obj.optString("packageName").takeIf { it.isNotBlank() },
                    cidr,
                    obj.optString("network").takeIf { it.isNotBlank() }?.let(NetworkKind::valueOf),
                    Decision.valueOf(obj.getString("decision")),
                    obj.optInt("port", -1).takeIf { it in 0..65535 }
                ))
            } catch (_: Exception) { /* Ignore malformed individual records. */ }
        }
        return result
    }

    fun save(rules: List<IpRule>): Boolean {
        val array = JSONArray()
        for (rule in rules) {
            require(RuleEngine.isValidCidr(rule.cidr))
            array.put(JSONObject().apply {
                put("packageName", rule.packageName ?: "")
                put("cidr", rule.cidr)
                put("network", rule.network?.name ?: "")
                put("decision", rule.decision.name)
                put("port", rule.port ?: -1)
            })
        }
        val saved = prefs.edit().putString("ip_rules", array.toString()).commit()
        if (saved) onRulesSaved()
        return saved
    }
}
