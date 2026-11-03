package com.nonroot.firewall

import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent

/** Manifest receiver: updates package cache without keeping the UI process alive. */
class PackageChangeReceiver : BroadcastReceiver() {
    override fun onReceive(context: Context, intent: Intent) {
        val pkg = intent.data?.schemeSpecificPart ?: return
        val action = intent.action ?: return
        if (action == Intent.ACTION_PACKAGE_REMOVED && intent.getBooleanExtra(Intent.EXTRA_REPLACING, false)) return
        val removed = action == Intent.ACTION_PACKAGE_REMOVED || action == Intent.ACTION_PACKAGE_FULLY_REMOVED
        val pending = goAsync()
        val appContext = context.applicationContext
        Thread {
            try { AppCatalog.updatePackage(appContext, pkg, removed) }
            finally { pending.finish() }
        }.start()
    }
}
