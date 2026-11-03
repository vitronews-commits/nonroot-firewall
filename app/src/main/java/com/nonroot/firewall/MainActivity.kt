package com.nonroot.firewall

import android.app.Activity
import android.os.Bundle
import android.graphics.Color
import android.view.Gravity
import android.widget.*

/** Initial classic five-tab shell. Buttons are deliberately not connected to VPN yet. */
class MainActivity : Activity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        val root = LinearLayout(this).apply { orientation = LinearLayout.VERTICAL; setBackgroundColor(Color.WHITE) }
        val header = TextView(this).apply {
            text = "NonRoot Firewall"; textSize = 20f; setTextColor(Color.WHITE)
            setPadding(20, 22, 20, 22); setBackgroundColor(Color.rgb(55, 55, 55))
        }
        root.addView(header)
        val tabs = LinearLayout(this).apply { orientation = LinearLayout.HORIZONTAL }
        val content = LinearLayout(this).apply { orientation = LinearLayout.VERTICAL; setPadding(24, 30, 24, 20) }
        val pages = mapOf(
            "Home" to "Firewall is stopped\n\nVPN engine not integrated yet",
            "Pending" to "Pending connections will appear here",
            "Apps" to "Per-app Wi-Fi / Mobile rules",
            "Filters" to "IP / CIDR allow and block rules",
            "Log" to "Connection history"
        )
        for ((name, message) in pages) {
            val button = Button(this).apply {
                text = name; textSize = 10f; isAllCaps = false; setPadding(0, 0, 0, 0)
                setOnClickListener {
                    content.removeAllViews()
                    content.addView(TextView(this@MainActivity).apply {
                        text = message; textSize = 17f; setTextColor(Color.DKGRAY)
                    })
                }
            }
            tabs.addView(button, LinearLayout.LayoutParams(0, 54, 1f))
        }
        root.addView(tabs)
        root.addView(content, LinearLayout.LayoutParams(-1, 0, 1f))
        setContentView(root)
        content.addView(TextView(this).apply { text = pages.getValue("Home"); textSize = 17f; gravity = Gravity.START })
    }
}
