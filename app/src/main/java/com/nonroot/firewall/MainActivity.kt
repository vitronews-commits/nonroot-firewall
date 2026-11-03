package com.nonroot.firewall

import android.app.Activity
import android.app.AlertDialog
import android.os.Bundle
import android.graphics.Color
import android.text.InputType
import android.view.Gravity
import android.widget.*

/** Classic minimal shell. Rules are saved locally but NOT enforced until VPN engine integration. */
class MainActivity : Activity() {
    private lateinit var content: LinearLayout
    private lateinit var store: RuleStore
    private lateinit var appStore: AppRuleStore
    private val appRules = mutableListOf<AppRule>()
    private val rules = mutableListOf<IpRule>()
    private var page = "Home"

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        store = RuleStore(this)
        appStore = AppRuleStore(this)
        rules.addAll(store.load())
        appRules.addAll(appStore.load())
        val root = LinearLayout(this).apply { orientation = LinearLayout.VERTICAL; setBackgroundColor(Color.WHITE) }
        root.addView(TextView(this).apply {
            text = "NonRoot Firewall"; textSize = 20f; setTextColor(Color.WHITE)
            setPadding(20, 22, 20, 22); setBackgroundColor(Color.rgb(55, 55, 55))
        })
        val tabs = LinearLayout(this).apply { orientation = LinearLayout.HORIZONTAL }
        content = LinearLayout(this).apply { orientation = LinearLayout.VERTICAL; setPadding(20, 22, 20, 20) }
        for (name in listOf("Home", "Pending", "Apps", "Filters", "Log")) {
            tabs.addView(Button(this).apply {
                text = name; textSize = 10f; isAllCaps = false; setPadding(0, 0, 0, 0)
                setOnClickListener { page = name; render() }
            }, LinearLayout.LayoutParams(0, 54, 1f))
        }
        root.addView(tabs)
        root.addView(ScrollView(this).apply { addView(content) }, LinearLayout.LayoutParams(-1, 0, 1f))
        setContentView(root)
        render()
    }

    private fun message(value: String) {
        content.addView(TextView(this).apply {
            text = value; textSize = 16f; setTextColor(Color.DKGRAY); setPadding(0, 8, 0, 16)
        })
    }

    private fun render() {
        content.removeAllViews()
        when (page) {
            "Home" -> message("Firewall is stopped\n\nRules are saved but NOT enforced. VPN engine not integrated.")
            "Pending" -> message("No live pending connections. Packet capture is not implemented yet.")
            "Apps" -> {
                message("App Rules — saved locally (not yet active)")
                content.addView(Button(this).apply { text = "+ Add app rule"; setOnClickListener { addAppRule() } })
                appRules.forEachIndexed { index, rule ->
                    content.addView(Button(this).apply {
                        text = "${rule.decision}: ${rule.packageName} • ${rule.network ?: "All networks"}"
                        isAllCaps = false
                        setOnClickListener {
                            AlertDialog.Builder(this@MainActivity).setTitle("Remove app rule?")
                                .setMessage(text)
                                .setPositiveButton("Remove") { _, _ ->
                                    val previous = appRules.toList()
                                    appRules.removeAt(index)
                                    if (!appStore.save(appRules)) {
                                        appRules.clear(); appRules.addAll(previous)
                                        Toast.makeText(this@MainActivity, "Unable to save", Toast.LENGTH_LONG).show()
                                    }
                                    render()
                                }
                                .setNegativeButton("Cancel", null).show()
                        }
                    })
                }
            }
            "Log" -> message("Connection history: upcoming.")
            "Filters" -> {
                message("IP Filters — saved locally (not yet active)")
                content.addView(Button(this).apply { text = "+ Add IP rule"; setOnClickListener { addRule() } })
                rules.forEachIndexed { index, rule ->
                    content.addView(Button(this).apply {
                        text = "${rule.decision}: ${rule.cidr}  •  ${rule.packageName ?: "All apps"}  •  ${rule.network ?: "All networks"}"
                        isAllCaps = false
                        setOnClickListener {
                            AlertDialog.Builder(this@MainActivity)
                                .setTitle("Remove this rule?")
                                .setMessage(text)
                                .setPositiveButton("Remove") { _, _ ->
                                    val old = rules.toList()
                                    rules.removeAt(index)
                                    if (!store.save(rules)) {
                                        rules.clear(); rules.addAll(old)
                                        Toast.makeText(this@MainActivity, "Unable to save", Toast.LENGTH_LONG).show()
                                    }
                                    render()
                                }
                                .setNegativeButton("Cancel", null).show()
                        }
                    })
                }
            }
        }
    }

    private fun addRule() {
        val form = LinearLayout(this).apply { orientation = LinearLayout.VERTICAL; setPadding(24, 8, 24, 8) }
        val cidr = EditText(this).apply {
            hint = "IP or CIDR (e.g. 192.0.2.10 or 2001:db8::/32)"
            inputType = InputType.TYPE_CLASS_TEXT
        }
        val pkg = EditText(this).apply { hint = "Package name (optional; blank = all apps)" }
        val network = Spinner(this).apply {
            adapter = ArrayAdapter(this@MainActivity, android.R.layout.simple_spinner_dropdown_item, listOf("All networks", "Wi-Fi", "Mobile"))
        }
        val decision = Spinner(this).apply {
            adapter = ArrayAdapter(this@MainActivity, android.R.layout.simple_spinner_dropdown_item, listOf("BLOCK", "ALLOW"))
        }
        form.addView(cidr); form.addView(pkg); form.addView(network); form.addView(decision)
        val dialog = AlertDialog.Builder(this).setTitle("Add IP rule").setView(form)
            .setNegativeButton("Cancel", null).setPositiveButton("Save", null).create()
        dialog.setOnShowListener {
            dialog.getButton(AlertDialog.BUTTON_POSITIVE).setOnClickListener {
                val raw = cidr.text.toString().trim()
                val normalized = if ('/' in raw) raw else raw + if (':' in raw) "/128" else "/32"
                if (!RuleEngine.isValidCidr(normalized)) {
                    cidr.error = "Enter a valid numeric IPv4/IPv6 address or CIDR"; return@setOnClickListener
                }
                val kind = when (network.selectedItemPosition) {
                    1 -> NetworkKind.WIFI
                    2 -> NetworkKind.MOBILE
                    else -> null
                }
                val value = if (decision.selectedItemPosition == 0) Decision.BLOCK else Decision.ALLOW
                val newRule = IpRule(pkg.text.toString().trim().ifBlank { null }, normalized, kind, value)
                rules.add(newRule)
                if (!store.save(rules)) {
                    rules.removeAt(rules.lastIndex)
                    Toast.makeText(this, "Unable to save rule", Toast.LENGTH_LONG).show()
                    return@setOnClickListener
                }
                dialog.dismiss(); render()
            }
        }
        dialog.show()
    }
    private fun addAppRule() {
        val form = LinearLayout(this).apply { orientation = LinearLayout.VERTICAL; setPadding(24, 8, 24, 8) }
        val pkg = EditText(this).apply { hint = "Package name (e.g. com.android.chrome)" }
        val network = Spinner(this).apply {
            adapter = ArrayAdapter(this@MainActivity, android.R.layout.simple_spinner_dropdown_item, listOf("All networks", "Wi-Fi", "Mobile"))
        }
        val decision = Spinner(this).apply {
            adapter = ArrayAdapter(this@MainActivity, android.R.layout.simple_spinner_dropdown_item, listOf("BLOCK", "ALLOW"))
        }
        form.addView(pkg); form.addView(network); form.addView(decision)
        val dialog = AlertDialog.Builder(this).setTitle("Add app rule").setView(form)
            .setNegativeButton("Cancel", null).setPositiveButton("Save", null).create()
        dialog.setOnShowListener {
            dialog.getButton(AlertDialog.BUTTON_POSITIVE).setOnClickListener {
                val name = pkg.text.toString().trim()
                if (!name.matches(Regex("[A-Za-z_][A-Za-z0-9_]*(\\.[A-Za-z_][A-Za-z0-9_]*)+"))) {
                    pkg.error = "Enter a valid package name"; return@setOnClickListener
                }
                val kind = when (network.selectedItemPosition) {
                    1 -> NetworkKind.WIFI
                    2 -> NetworkKind.MOBILE
                    else -> null
                }
                val value = if (decision.selectedItemPosition == 0) Decision.BLOCK else Decision.ALLOW
                val previous = appRules.toList()
                appRules.removeAll { it.packageName == name && it.network == kind }
                appRules.add(AppRule(name, kind, value))
                if (!appStore.save(appRules)) {
                    appRules.clear(); appRules.addAll(previous)
                    Toast.makeText(this, "Unable to save", Toast.LENGTH_LONG).show()
                    return@setOnClickListener
                }
                dialog.dismiss(); render()
            }
        }
        dialog.show()
    }

}
