package com.nonroot.firewall

import androidx.test.platform.app.InstrumentationRegistry
import androidx.test.ext.junit.runners.AndroidJUnit4
import org.junit.Test
import org.junit.Assert.*
import org.junit.runner.RunWith
import java.net.Socket
import java.net.DatagramSocket

/** Does not request VPN permission or establish TUN. Safe on shared test devices. */
@RunWith(AndroidJUnit4::class)
class EngineInstrumentationTest {
    private val instrumentation get()=InstrumentationRegistry.getInstrumentation()
    @Test fun testBidirectionalAndroidSocketPacketPipeline() {
        EngineSelfTest.verify({ Socket() },{ DatagramSocket(null) })
    }
    @Test fun testActivityKeepsFiveTabsAndPreservesStoredRules() {
        val context=instrumentation.targetContext
        val before=context.getSharedPreferences("firewall_rules",0).all.toMap()
        val activity=instrumentation.startActivitySync(android.content.Intent(context,MainActivity::class.java)
            .addFlags(android.content.Intent.FLAG_ACTIVITY_NEW_TASK))
        try {
            instrumentation.runOnMainSync {
                val labels=mutableListOf<String>()
                fun visit(view: android.view.View) {
                    if(view is android.widget.TextView) labels.add(view.text.toString())
                    if(view is android.view.ViewGroup) for(i in 0 until view.childCount) visit(view.getChildAt(i))
                }
                visit(activity.window.decorView)
                for(tab in listOf("Home","Pending","Apps","Logs","Global")) assertTrue("Missing $tab",labels.contains(tab))
            }
            assertEquals(before,context.getSharedPreferences("firewall_rules",0).all)
        } finally { instrumentation.runOnMainSync { activity.finish() } }
    }
    @Test fun testMalformedTrafficCannotOpenSockets() {
        var opened=false
        PacketForwarder({ opened=true; Socket() },{ opened=true; DatagramSocket(null) },{ true },{}).use {
            assertFalse(it.accept(byteArrayOf(0x45)))
            assertFalse(opened)
        }
    }
}
