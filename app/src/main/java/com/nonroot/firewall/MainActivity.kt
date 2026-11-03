package com.nonroot.firewall

import android.app.Activity
import android.app.AlertDialog
import android.os.Bundle
import android.graphics.Color
import android.text.InputType
import android.view.Gravity
import android.widget.*
import android.content.pm.PackageManager
import android.content.Intent
import android.graphics.drawable.Drawable

/** Classic minimal shell. Rules are saved locally but NOT enforced until VPN engine integration. */
class MainActivity : Activity() {
    private lateinit var content: LinearLayout
    private lateinit var toolbar: TextView
    private val tabIcons = mutableMapOf<String, TextView>()
    private val tabLabels = mutableMapOf<String, TextView>()
    private lateinit var store: RuleStore
    private lateinit var appStore: AppRuleStore
    private val appRules = mutableListOf<AppRule>()
    private val rules = mutableListOf<IpRule>()
    private var page = "Home"
    private var detailPackage: String? = null
    private fun dp(value: Int) = (value * resources.displayMetrics.density + 0.5f).toInt()
    private fun appInfo(pkg: String): Pair<String, Drawable?> = try {
        val info = packageManager.getApplicationInfo(pkg, 0)
        packageManager.getApplicationLabel(info).toString() to packageManager.getApplicationIcon(info)
    } catch (_: PackageManager.NameNotFoundException) {
        pkg to null
    }
    private fun appIcon(pkg: String): android.view.View = ImageView(this).apply {
        val icon = appInfo(pkg).second
        if (icon != null) setImageDrawable(icon)
        else setImageResource(android.R.drawable.sym_def_app_icon)
        scaleType = ImageView.ScaleType.FIT_CENTER
        setPadding(dp(5), dp(5), dp(5), dp(5))
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        store = RuleStore(this)
        appStore = AppRuleStore(this)
        rules.addAll(store.load())
        appRules.addAll(appStore.load())
        val root = LinearLayout(this).apply { orientation = LinearLayout.VERTICAL; setBackgroundColor(Color.rgb(250,250,250)) }
        toolbar = TextView(this).apply {
            text = "☰    NoRoot Firewall"; textSize = 23f; setTextColor(Color.BLACK)
            setPadding(20, 28, 20, 28); setBackgroundColor(Color.rgb(144,202,249))
        }
        root.addView(toolbar)
        content = LinearLayout(this).apply { orientation = LinearLayout.VERTICAL }
        val scroll = ScrollView(this).apply { addView(content) }
        root.addView(scroll, LinearLayout.LayoutParams(-1, 0, 1f))
        val tabs = LinearLayout(this).apply {
            orientation = LinearLayout.HORIZONTAL
            setBackgroundColor(Color.rgb(66,165,245))
        }
        for ((name, icon) in listOf("Home" to "⌂", "Pending" to "➜", "Apps" to "▦", "Global" to "◉", "Logs" to "◷")) {
            val tab = LinearLayout(this).apply {
                orientation = LinearLayout.VERTICAL
                gravity = Gravity.CENTER
                setOnClickListener { page = name; detailPackage = null; render() }
            }
            val iconView = TextView(this).apply {
                text = icon
                textSize = 27f
                gravity = Gravity.CENTER
                setTextColor(if (page == name) Color.WHITE else Color.rgb(185,220,246))
            }
            val labelView = TextView(this).apply {
                text = name
                textSize = 13f
                gravity = Gravity.CENTER
                setTextColor(Color.WHITE)
            }
            tab.addView(iconView)
            tab.addView(labelView)
            tabIcons[name] = iconView
            tabLabels[name] = labelView
            tabs.addView(tab, LinearLayout.LayoutParams(0, dp(72), 1f))
        }
        root.addView(tabs)
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
        toolbar.text = if (detailPackage == null) "☰    NoRoot Firewall" else "‹    App Detail"
        toolbar.setOnClickListener(if (detailPackage != null) android.view.View.OnClickListener {
            detailPackage = null; render()
        } else null)
        for ((name, view) in tabIcons) view.setTextColor(if (name == page) Color.WHITE else Color.rgb(185,220,246))
        for ((name, view) in tabLabels) view.setTextColor(if (name == page) Color.WHITE else Color.rgb(185,220,246))
        if (detailPackage != null) {
            appDetail(detailPackage!!)
            return
        }
        when (page) {
            "Home" -> homeScreen()
            "Pending" -> message("No live pending accesses — VPN engine not connected.")
            "Apps" -> appsScreen()
            "Logs" -> message("No connection logs — VPN engine not connected.")
            "Global" -> globalScreen()
        }
    }

    private fun visibleLaunchablePackages(): List<String> {
        val intent = Intent(Intent.ACTION_MAIN).addCategory(Intent.CATEGORY_LAUNCHER)
        return packageManager.queryIntentActivities(intent, 0)
            .map { it.activityInfo.packageName }
            .distinct()
    }

    private fun appsScreen() {
        section("◆   ▥                  Applications")
        // Include saved targets even if the app was uninstalled.
        val packages = (visibleLaunchablePackages() +
            appRules.map { it.packageName } +
            rules.mapNotNull { it.packageName })
            .distinct()
            .sortedWith(compareBy(String.CASE_INSENSITIVE_ORDER) { appInfo(it).first })
        if (packages.isEmpty()) message("No visible applications found")
        for (pkg in packages) {
            val row = LinearLayout(this).apply {
                orientation = LinearLayout.HORIZONTAL
                gravity = Gravity.CENTER_VERTICAL
                setPadding(12, 6, 12, 6)
            }
            val wifi = appRules.lastOrNull { it.packageName == pkg && (it.network == NetworkKind.WIFI || it.network == null) }
            val mobile = appRules.lastOrNull { it.packageName == pkg && (it.network == NetworkKind.MOBILE || it.network == null) }
            row.addView(appIcon(pkg), LinearLayout.LayoutParams(dp(48), dp(54)))
            row.addView(TextView(this).apply { text = marker(wifi?.decision); textSize = 25f }, LinearLayout.LayoutParams(dp(46), dp(54)))
            row.addView(TextView(this).apply { text = marker(mobile?.decision); textSize = 25f }, LinearLayout.LayoutParams(dp(46), dp(54)))
            row.addView(TextView(this).apply { text = appInfo(pkg).first; textSize = 16f; gravity = Gravity.CENTER_VERTICAL }, LinearLayout.LayoutParams(0, dp(54), 1f))
            row.addView(TextView(this).apply { text = "›"; textSize = 30f })
            row.setOnClickListener { detailPackage = pkg; render() }
            content.addView(row)
            content.addView(View(this).apply { setBackgroundColor(Color.LTGRAY) }, LinearLayout.LayoutParams(-1, 1))
        }
        content.addView(Button(this).apply { text = "+ Add app rule"; setOnClickListener { addAppRule() } })
    }

    private fun marker(decision: Decision?): String = when (decision) {
        Decision.ALLOW -> "☑"
        Decision.BLOCK -> "☒"
        else -> "□"
    }

    private fun appDetail(pkg: String) {
        detailPackage = pkg
        content.removeAllViews()
        val identity = LinearLayout(this).apply { orientation = LinearLayout.HORIZONTAL; gravity = Gravity.CENTER_VERTICAL; setPadding(dp(16), dp(16), dp(16), dp(16)) }
        identity.addView(appIcon(pkg), LinearLayout.LayoutParams(dp(64), dp(64)))
        identity.addView(TextView(this).apply { text = appInfo(pkg).first; textSize = 19f; setTextColor(Color.DKGRAY); setPadding(dp(12), 0, 0, 0) })
        content.addView(identity)
        message("◆   Wi-Fi       Custom filters")
        message("▥   Mobile     Custom filters")
        section("◆   ▥                  Custom Filters")
        message("The first matching custom rule 'wins'")
        for (rule in rules.filter { it.packageName == pkg }) filterRow(rule)
        content.addView(Button(this).apply { text = "＋ New Custom Filter"; setOnClickListener { addRule(pkg) } })
        content.addView(Button(this).apply { text = "Edit App Access"; setOnClickListener { addAppRule(pkg) } })
        content.addView(Button(this).apply {
            text = "‹ Back to Apps"; setOnClickListener { detailPackage = null; render() }
        })
    }

    private fun globalScreen() {
        header("🌐     Global Filters")
        section("◆   ▥                  Pre-Filters")
        for (rule in rules.filter { it.packageName == null }) filterRow(rule)
        content.addView(Button(this).apply { text = "＋ New Pre-Filter"; setOnClickListener { addRule(null) } })
        section("◆   ▥                  Post-Filters")
        message("No post-filters configured")
    }

    private fun filterRow(rule: IpRule) {
        val row = LinearLayout(this).apply {
            orientation = LinearLayout.HORIZONTAL
            gravity = Gravity.CENTER_VERTICAL
            setPadding(12, 4, 12, 4)
        }
        val color = if (rule.decision == Decision.ALLOW) Color.rgb(76,175,80) else Color.rgb(211,47,47)
        val wifi = if (rule.network == NetworkKind.MOBILE) "□" else marker(rule.decision)
        val mobile = if (rule.network == NetworkKind.WIFI) "□" else marker(rule.decision)
        row.addView(TextView(this).apply { text = wifi; textSize = 23f; setTextColor(color) }, LinearLayout.LayoutParams(48, 62))
        row.addView(TextView(this).apply { text = mobile; textSize = 23f; setTextColor(color) }, LinearLayout.LayoutParams(48, 62))
        row.addView(TextView(this).apply {
            text = rule.cidr + ":" + (rule.port?.toString() ?: "*"); textSize = 16f; gravity = Gravity.CENTER_VERTICAL
        }, LinearLayout.LayoutParams(0, 62, 1f))
        row.addView(Button(this).apply {
            text = "DELETE"
            setOnClickListener {
                AlertDialog.Builder(this@MainActivity).setTitle("Delete filter?")
                    .setMessage(rule.cidr).setNegativeButton("CANCEL", null)
                    .setPositiveButton("DELETE") { _, _ ->
                        val old = rules.toList()
                        rules.remove(rule)
                        if (!store.save(rules)) {
                            rules.clear(); rules.addAll(old)
                            Toast.makeText(this@MainActivity, "Unable to save", Toast.LENGTH_LONG).show()
                        }
                        render()
                    }.show()
            }
        })
        content.addView(row)
        content.addView(View(this).apply { setBackgroundColor(Color.LTGRAY) }, LinearLayout.LayoutParams(-1, 1))
    }

    private fun header(value: String) {
        content.addView(TextView(this).apply {
            text = value; textSize = 21f; setTextColor(Color.DKGRAY)
            setPadding(20, 26, 12, 26)
        })
    }

    private fun section(value: String) {
        content.addView(TextView(this).apply {
            text = value; textSize = 19f; setTextColor(Color.WHITE)
            setBackgroundColor(Color.rgb(66,66,66)); setPadding(16, 12, 16, 12)
        })
    }

    private fun homeScreen() {
        val box = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            gravity = Gravity.CENTER_HORIZONTAL
            setPadding(20, 40, 20, 20)
        }
        box.addView(Button(this).apply {
            text = "START"; textSize = 28f; isEnabled = false
        }, LinearLayout.LayoutParams(240, 160))
        box.addView(TextView(this).apply {
            text = "Click OK when it tries to create VPN connection"
            textSize = 16f; gravity = Gravity.CENTER; setPadding(0, 14, 0, 10)
        })
        box.addView(CheckBox(this).apply { text = "Auto start on boot"; isEnabled = false })
        box.addView(Button(this).apply {
            text = "STOP"; textSize = 28f; isEnabled = false
            setBackgroundColor(Color.rgb(211,47,47)); setTextColor(Color.WHITE)
        }, LinearLayout.LayoutParams(240, 110).apply { topMargin = 65 })
        box.addView(TextView(this).apply {
            text = "Firewall engine not integrated — protection OFF"
            setTextColor(Color.RED); gravity = Gravity.CENTER; setPadding(0, 24, 0, 0)
        })
        content.addView(box)
    }

    private fun addRule(prefillPackage: String? = null) {
        val form = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            setPadding(24, 12, 24, 12)
        }
        val address = EditText(this).apply {
            hint = "Address (e.g. 172.217.114.*)"
            inputType = InputType.TYPE_CLASS_TEXT
            isSingleLine = true
        }
        val addressMenu = Button(this).apply {
            text = "▼"
            setOnClickListener {
                val choices = AddressPatterns.suggestions(address.text.toString())
                AlertDialog.Builder(this@MainActivity).setItems(choices.toTypedArray()) { _, index ->
                    address.setText(choices[index])
                }.show()
            }
        }
        val port = EditText(this).apply {
            hint = "Port (* or 443)"
            setText("*")
            inputType = InputType.TYPE_CLASS_TEXT
            isSingleLine = true
        }
        val portMenu = Button(this).apply {
            text = "▼"
            setOnClickListener {
                val choices = arrayOf("443", "80", "*")
                AlertDialog.Builder(this@MainActivity).setItems(choices) { _, index ->
                    port.setText(choices[index])
                }.show()
            }
        }
        val pkg = EditText(this).apply {
            hint = "Package (blank = global)"
            setText(prefillPackage ?: "")
            isEnabled = prefillPackage == null
        }
        // Compact three-state buttons: Pending → Allow → Block → Pending.
        var wifiChoice = 0
        var mobileChoice = 0
        fun symbol(value: Int): String = when (value) {
            1 -> "☑"
            2 -> "☒"
            else -> "□"
        }
        fun tint(value: Int): Int = when (value) {
            1 -> Color.rgb(76, 175, 80)
            2 -> Color.rgb(211, 47, 47)
            else -> Color.GRAY
        }
        fun stateButton(onAdvance: () -> Int): TextView = TextView(this).apply {
            textSize = 28f
            gravity = Gravity.CENTER
            text = symbol(0)
            setTextColor(Color.GRAY)
            setOnClickListener {
                val state = onAdvance()
                text = symbol(state)
                setTextColor(tint(state))
            }
        }
        val wifi = stateButton { wifiChoice = (wifiChoice + 1) % 3; wifiChoice }
        val mobile = stateButton { mobileChoice = (mobileChoice + 1) % 3; mobileChoice }
        val addressRow = LinearLayout(this).apply { orientation = LinearLayout.HORIZONTAL; gravity = Gravity.CENTER_VERTICAL }
        addressRow.addView(TextView(this).apply { text = "Address"; textSize = 14f }, LinearLayout.LayoutParams(80, -2))
        addressRow.addView(address, LinearLayout.LayoutParams(0, -2, 1f))
        addressRow.addView(addressMenu, LinearLayout.LayoutParams(56, -2))
        val portRow = LinearLayout(this).apply { orientation = LinearLayout.HORIZONTAL; gravity = Gravity.CENTER_VERTICAL }
        portRow.addView(TextView(this).apply { text = "Port"; textSize = 14f }, LinearLayout.LayoutParams(80, -2))
        portRow.addView(port, LinearLayout.LayoutParams(0, -2, 1f))
        portRow.addView(portMenu, LinearLayout.LayoutParams(56, -2))
        form.addView(addressRow); form.addView(portRow)
        if (prefillPackage == null) form.addView(pkg)
        val modes = LinearLayout(this).apply {
            orientation = LinearLayout.HORIZONTAL
            gravity = Gravity.CENTER_VERTICAL
            setPadding(0, 12, 0, 16)
        }
        modes.addView(TextView(this).apply { text = "◆"; textSize = 25f; setTextColor(Color.rgb(33,150,243)) })
        modes.addView(wifi, LinearLayout.LayoutParams(56, 48))
        modes.addView(TextView(this).apply { text = "▥"; textSize = 27f; setTextColor(Color.rgb(33,150,243)) })
        modes.addView(mobile, LinearLayout.LayoutParams(56, 48))
        form.addView(modes)
        val dialog = AlertDialog.Builder(this).setTitle("New Custom Filter")
            .setView(form).setNegativeButton("CANCEL", null)
            .setPositiveButton("SAVE", null).create()
        dialog.setOnShowListener {
            dialog.getButton(AlertDialog.BUTTON_POSITIVE).setOnClickListener {
                val cidr = AddressPatterns.normalize(address.text.toString())
                if (cidr == null) { address.error = "Invalid IP, wildcard or CIDR"; return@setOnClickListener }
                val rawPort = port.text.toString().trim()
                val parsedPort = if (rawPort == "*") null else rawPort.toIntOrNull()
                if (rawPort != "*" && (parsedPort == null || parsedPort !in 0..65535)) {
                    port.error = "Enter 0–65535 or *"; return@setOnClickListener
                }
                if (wifiChoice == 0 && mobileChoice == 0) {
                    Toast.makeText(this, "Choose Allow or Block for at least one network", Toast.LENGTH_LONG).show()
                    return@setOnClickListener
                }
                val name = pkg.text.toString().trim().ifBlank { null }
                val additions = mutableListOf<IpRule>()
                fun choice(index: Int): Decision = if (index == 1) Decision.ALLOW else Decision.BLOCK
                if (wifiChoice != 0)
                    additions.add(IpRule(name, cidr, NetworkKind.WIFI, choice(wifiChoice), parsedPort))
                if (mobileChoice != 0)
                    additions.add(IpRule(name, cidr, NetworkKind.MOBILE, choice(mobileChoice), parsedPort))
                val old = rules.toList()
                rules.addAll(additions)
                if (!store.save(rules)) {
                    rules.clear(); rules.addAll(old)
                    Toast.makeText(this, "Unable to save rule", Toast.LENGTH_LONG).show()
                    return@setOnClickListener
                }
                dialog.dismiss(); render()
            }
        }
        dialog.show()
    }
    private fun addAppRule(prefillPackage: String? = null) {
        val form = LinearLayout(this).apply { orientation = LinearLayout.VERTICAL; setPadding(24, 8, 24, 8) }
        val pkg = EditText(this).apply { hint = "Package name (e.g. com.android.chrome)"; setText(prefillPackage ?: "") }
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
