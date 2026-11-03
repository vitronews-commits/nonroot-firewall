package com.nonroot.firewall

import android.content.Context
import android.content.pm.ApplicationInfo
import android.content.pm.PackageManager
import org.json.JSONArray
import org.json.JSONObject

/** Persist lightweight package metadata; never cache Drawable objects. */
object AppCatalog {
    data class Entry(val pkg: String, val label: String, val system: Boolean)
    private const val PREFS = "app_catalog"
    private const val KEY = "entries"
    private const val VERSION = "revision"
    private const val LAST_SCAN = "last_scan"
    private val lock = Any()

    fun read(context: Context): List<Entry> = synchronized(lock) {
        val raw = context.getSharedPreferences(PREFS, Context.MODE_PRIVATE).getString(KEY, null) ?: return@synchronized emptyList()
        try {
            val arr = JSONArray(raw)
            (0 until arr.length()).map { i ->
                val o = arr.getJSONObject(i)
                Entry(o.getString("pkg"), o.getString("label"), o.getBoolean("system"))
            }
        } catch (_: Exception) { emptyList() }
    }

    fun needsReconciliation(context: Context): Boolean {
        val last = context.getSharedPreferences(PREFS, Context.MODE_PRIVATE).getLong(LAST_SCAN, 0L)
        return last == 0L || System.currentTimeMillis() - last > 24L * 60 * 60 * 1000 || last > System.currentTimeMillis()
    }

    fun revision(context: Context): Long =
        context.getSharedPreferences(PREFS, Context.MODE_PRIVATE).getLong(VERSION, 0L)

    private fun save(context: Context, entries: List<Entry>) = synchronized(lock) {
        val arr = JSONArray()
        entries.forEach { entry ->
            arr.put(JSONObject().put("pkg", entry.pkg).put("label", entry.label).put("system", entry.system))
        }
        val prefs = context.getSharedPreferences(PREFS, Context.MODE_PRIVATE)
        val nextRevision = prefs.getLong(VERSION, 0L) + 1L
        prefs.edit().putString(KEY, arr.toString()).putLong(VERSION, nextRevision).commit()
    }

    fun scan(context: Context): List<Entry> = synchronized(lock) {
        val pm = context.packageManager
        val entries = pm.getInstalledApplications(0).map { info ->
            Entry(info.packageName, pm.getApplicationLabel(info).toString(),
                (info.flags and (ApplicationInfo.FLAG_SYSTEM or ApplicationInfo.FLAG_UPDATED_SYSTEM_APP)) != 0)
        }.distinctBy { it.pkg }.sortedWith(compareBy(String.CASE_INSENSITIVE_ORDER) { it.label })
        save(context, entries)
        context.getSharedPreferences(PREFS, Context.MODE_PRIVATE).edit().putLong(LAST_SCAN, System.currentTimeMillis()).apply()
        entries
    }

    fun updatePackage(context: Context, pkg: String, removed: Boolean) {
        synchronized(lock) {
            val entries = read(context).filterNot { it.pkg == pkg }.toMutableList()
            if (!removed) {
                val pm = context.packageManager
                try {
                    val info = pm.getApplicationInfo(pkg, 0)
                    entries.add(Entry(pkg, pm.getApplicationLabel(info).toString(),
                        (info.flags and (ApplicationInfo.FLAG_SYSTEM or ApplicationInfo.FLAG_UPDATED_SYSTEM_APP)) != 0))
                } catch (_: PackageManager.NameNotFoundException) { }
            }
            save(context, entries.sortedWith(compareBy(String.CASE_INSENSITIVE_ORDER) { it.label }))
        }
    }
}
