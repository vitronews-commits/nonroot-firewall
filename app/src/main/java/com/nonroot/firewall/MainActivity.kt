package com.nonroot.firewall

import android.app.Activity
import android.app.AlertDialog
import android.os.Bundle
import android.graphics.Color
import android.text.InputType
import android.view.Gravity
import android.view.View
import android.widget.*
import android.content.pm.PackageManager
import android.content.Intent
import android.graphics.drawable.Drawable
import android.content.pm.ApplicationInfo
import android.os.Handler
import android.os.Looper
import java.util.concurrent.Executors
import androidx.recyclerview.widget.RecyclerView
import androidx.recyclerview.widget.LinearLayoutManager

/** Classic minimal shell. Rules are saved locally but NOT enforced until VPN engine integration. */
class MainActivity : Activity() {
    private lateinit var content: LinearLayout
    private lateinit var screenHost: FrameLayout
    private var appsScrollPosition = 0
    private lateinit var toolbar: TextView
    private val tabIcons = mutableMapOf<String, TextView>()
    private val tabLabels = mutableMapOf<String, TextView>()
    private lateinit var store: RuleStore
    private lateinit var appStore: AppRuleStore
    private val appRules = mutableListOf<AppRule>()
    private val rules = mutableListOf<IpRule>()
    private var page = "Home"
    private val appExecutor = Executors.newSingleThreadExecutor()
    private val mainHandler = Handler(Looper.getMainLooper())
    private var installedApps: List<AppEntry> = emptyList()
    private var appsLoaded = false
    private var appsLoading = false
    private var catalogRevision = 0L
    private var showSystemApps = true
    private var appSearch = ""
    private var pendingSearch: Runnable? = null
    private var appListAdapter: AppListAdapter? = null
    private var appGeneration = 0
    private data class AppEntry(val pkg: String, val label: String, val system: Boolean)
    private var detailPackage: String? = null
    private fun dp(value: Int) = (value * resources.displayMetrics.density + 0.5f).toInt()
    private fun appInfo(pkg: String): Pair<String, Drawable?> = try {
        val info = packageManager.getApplicationInfo(pkg, 0)
        packageManager.getApplicationLabel(info).toString() to packageManager.getApplicationIcon(info)
    } catch (_: PackageManager.NameNotFoundException) {
        pkg to null
    } catch (_: SecurityException) {
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
        screenHost = FrameLayout(this)
        screenHost.addView(ScrollView(this).apply { addView(content) })
        root.addView(screenHost, LinearLayout.LayoutParams(-1, 0, 1f))
        val tabs = LinearLayout(this).apply {
            orientation = LinearLayout.HORIZONTAL
            setBackgroundColor(Color.rgb(66,165,245))
        }
        for ((name, icon) in listOf("Home" to "⌂", "Pending" to "➜", "Apps" to "▦", "Global" to "◉", "Logs" to "◷")) {
            val tab = LinearLayout(this).apply {
                orientation = LinearLayout.VERTICAL
                gravity = Gravity.CENTER
                setOnClickListener { if (page == "Apps") appsScrollPosition = (screenHost.findViewWithTag<RecyclerView>("app-list")?.layoutManager as? LinearLayoutManager)?.findFirstVisibleItemPosition() ?: 0; page = name; detailPackage = null; render() }
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
        val cached = AppCatalog.read(this)
        if (cached.isNotEmpty()) {
            installedApps = cached.map { AppEntry(it.pkg, it.label, it.system) }
            appsLoaded = true
            catalogRevision = AppCatalog.revision(this)
        }
        render()
        if (!appsLoaded || AppCatalog.needsReconciliation(this)) loadAppsAsync()
    }

    override fun onResume() {
        super.onResume()
        if (!::content.isInitialized) return
        val revision = AppCatalog.revision(this)
        if (revision != catalogRevision && revision != 0L) {
            installedApps = AppCatalog.read(this).map { AppEntry(it.pkg, it.label, it.system) }
            appsLoaded = true
            catalogRevision = revision
            if (page == "Apps" && detailPackage == null) render()
        }
        if (!appsLoading && AppCatalog.needsReconciliation(this)) loadAppsAsync()
    }

    override fun onDestroy() {
        appGeneration++
        pendingSearch?.let { mainHandler.removeCallbacks(it) }
        appExecutor.shutdownNow()
        super.onDestroy()
    }

    private fun loadAppsAsync() {
        if (appsLoading) return
        appsLoading = true
        val generation = ++appGeneration
        appExecutor.execute {
            val entries = try { AppCatalog.scan(applicationContext) } catch (_: Exception) { emptyList() }
            mainHandler.post {
                if (generation != appGeneration || isFinishing || isDestroyed) return@post
                if (entries.isNotEmpty()) {
                    installedApps = entries.map { AppEntry(it.pkg, it.label, it.system) }
                    catalogRevision = AppCatalog.revision(this)
                    appsLoaded = true
                }
                appsLoading = false
                if (page == "Apps" && detailPackage == null) render()
            }
        }
    }

    private fun message(value: String) {
        content.addView(TextView(this).apply {
            text = value; textSize = 16f; setTextColor(Color.DKGRAY); setPadding(0, 8, 0, 16)
        })
    }

    private fun render() {
        appListGeneration++
        appListAdapter = null
        screenHost.removeAllViews()
        content = LinearLayout(this).apply { orientation = LinearLayout.VERTICAL }
        screenHost.addView(ScrollView(this).apply { addView(content) })
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
        return try {
            packageManager.queryIntentActivities(intent, 0)
                .map { it.activityInfo.packageName }
                .distinct()
        } catch (_: SecurityException) {
            emptyList()
        }
    }

    private fun effectiveAppDecision(pkg: String, network: NetworkKind): Decision? =
        appRules.lastOrNull { it.packageName == pkg && it.network == network }?.decision
            ?: appRules.lastOrNull { it.packageName == pkg && it.network == null }?.decision

    private fun cycleAppAccess(pkg: String, network: NetworkKind) {
        val next = when (effectiveAppDecision(pkg, network)) {
            null, Decision.PENDING -> Decision.ALLOW
            Decision.ALLOW -> Decision.BLOCK
            Decision.BLOCK -> null
        }
        val old = appRules.toList()
        // Preserve other-network behavior if a generic rule was previously configured.
        val other = if (network == NetworkKind.WIFI) NetworkKind.MOBILE else NetworkKind.WIFI
        val otherDecision = effectiveAppDecision(pkg, other)
        appRules.removeAll { it.packageName == pkg && (it.network == network || it.network == null) }
        if (otherDecision != null && appRules.none { it.packageName == pkg && it.network == other }) {
            appRules.add(AppRule(pkg, other, otherDecision))
        }
        if (next != null) appRules.add(AppRule(pkg, network, next))
        if (!appStore.save(appRules)) {
            appRules.clear(); appRules.addAll(old)
            Toast.makeText(this, "Unable to save app rule", Toast.LENGTH_LONG).show()
        }
        if (page == "Apps" && detailPackage == null) appListAdapter?.refreshRule(pkg) else render()
    }

    private fun appsScreen() {
        section("Applications")
        if (!appsLoaded) {
            message("Loading installed applications in background…")
            if (!appsLoading) loadAppsAsync()
            return
        }
        val search = EditText(this).apply {
            hint = "Search applications or package name"
            setSingleLine(true)
            setText(appSearch)
            setSelection(text.length)
            addTextChangedListener(object : android.text.TextWatcher {
                override fun beforeTextChanged(s: CharSequence?, start: Int, count: Int, after: Int) {}
                override fun onTextChanged(s: CharSequence?, start: Int, before: Int, count: Int) {
                    appSearch = s?.toString().orEmpty()
                    appsScrollPosition = 0
                    pendingSearch?.let { mainHandler.removeCallbacks(it) }
                    pendingSearch = Runnable { if (page == "Apps" && detailPackage == null) updateAppRows() }
                    mainHandler.postDelayed(pendingSearch!!, 180)
                }
                override fun afterTextChanged(s: android.text.Editable?) {}
            })
        }
        content.addView(search)
        val actions = LinearLayout(this).apply { orientation = LinearLayout.HORIZONTAL; gravity = Gravity.CENTER_VERTICAL }
        actions.addView(Button(this).apply {
            text = "Refresh"
            setOnClickListener {
                if (!appsLoading) loadAppsAsync()
                Toast.makeText(this@MainActivity, "Checking installed apps…", Toast.LENGTH_SHORT).show()
            }
        })
        actions.addView(TextView(this).apply {
            text = if (appsLoading) "Scanning…" else "Cached catalog"
            textSize = 12f
            setPadding(dp(12), 0, 0, 0)
            setTextColor(Color.DKGRAY)
        })
        content.addView(actions)
        content.addView(CheckBox(this).apply {
            text = "Show system applications"
            isChecked = showSystemApps
            setOnCheckedChangeListener { _, checked ->
                showSystemApps = checked
                updateAppRows()
            }
        })
        val counter = TextView(this).apply { tag = "app-count"; textSize = 12f; setPadding(dp(12),dp(8),dp(12),dp(8)); setTextColor(Color.DKGRAY) }
        content.addView(counter)
        val adapter = AppListAdapter(this,
            { pkg, network -> effectiveAppDecision(pkg, network) },
            { pkg, network -> cycleAppAccess(pkg, network) },
            { pkg -> detailPackage = pkg; render() })
        appListAdapter = adapter
        val list = RecyclerView(this).apply {
            tag = "app-list"
            layoutManager = LinearLayoutManager(this@MainActivity)
            this.adapter = adapter
            setHasFixedSize(true)
            isNestedScrollingEnabled = true
        }
        val appsLayout = LinearLayout(this).apply { orientation = LinearLayout.VERTICAL }
        while (content.childCount > 0) {
            val child = content.getChildAt(0)
            content.removeViewAt(0)
            appsLayout.addView(child)
        }
        appsLayout.addView(list, LinearLayout.LayoutParams(-1, 0, 1f))
        screenHost.removeAllViews()
        screenHost.addView(appsLayout, FrameLayout.LayoutParams(-1, -1))
        updateAppRows()
        list.post { (list.layoutManager as? LinearLayoutManager)?.scrollToPosition(appsScrollPosition) }
    }

    private fun updateAppRows() {
        val adapter = appListAdapter ?: return
        val known = installedApps.associateBy { it.pkg }
        val saved = (appRules.map { it.packageName } + rules.mapNotNull { it.packageName })
            .filterNot { known.containsKey(it) }.distinct()
            .map { AppEntry(it, it, false) }
        val visible = (installedApps + saved).filter {
            (showSystemApps || !it.system) &&
            (appSearch.isBlank() || it.label.contains(appSearch, true) || it.pkg.contains(appSearch, true))
        }
        screenHost.findViewWithTag<TextView>("app-count")?.text =
            "${visible.size} applications • ${installedApps.count { it.system }} system apps found"
        adapter.submit(visible.map { AppListAdapter.Item(it.pkg, it.label, it.system) })
    }

    private var appListGeneration = 0

    private fun decisionColor(decision: Decision?): Int = when (decision) {
        Decision.ALLOW -> Color.rgb(46, 125, 50)
        Decision.BLOCK -> Color.rgb(198, 40, 40)
        else -> Color.GRAY
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
        val accessRow = LinearLayout(this).apply {
            orientation = LinearLayout.HORIZONTAL
            gravity = Gravity.CENTER_VERTICAL
            setPadding(dp(12), dp(6), dp(12), dp(6))
        }
        fun accessButton(network: NetworkKind, symbol: String): TextView =
            TextView(this).apply {
                val current = effectiveAppDecision(pkg, network)
                text = "$symbol  ${marker(current)}"
                textSize = 22f
                gravity = Gravity.CENTER
                setTextColor(when (current) {
                    Decision.ALLOW -> Color.rgb(46, 125, 50)
                    Decision.BLOCK -> Color.rgb(198, 40, 40)
                    else -> Color.GRAY
                })
                setOnClickListener { cycleAppAccess(pkg, network) }
            }
        accessRow.addView(accessButton(NetworkKind.WIFI, "◆"), LinearLayout.LayoutParams(0, dp(56), 1f))
        accessRow.addView(accessButton(NetworkKind.MOBILE, "▥"), LinearLayout.LayoutParams(0, dp(56), 1f))
        content.addView(accessRow)
        message("Tap Wi-Fi or Mobile to cycle Pending / Allow / Block")
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
