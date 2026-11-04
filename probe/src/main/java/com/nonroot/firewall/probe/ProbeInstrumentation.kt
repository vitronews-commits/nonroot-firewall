package com.nonroot.firewall.probe

import android.app.Activity
import android.app.Instrumentation
import android.os.Bundle
import java.net.DatagramPacket
import java.net.DatagramSocket
import java.net.InetSocketAddress
import java.net.Socket
import java.net.SocketTimeoutException

/** Separate UID is essential: a VPN's own UID does not prove packet interception. */
class ProbeInstrumentation : Instrumentation() {
    private var mode="allow"
    override fun onCreate(arguments: Bundle?) { mode=arguments?.getString("mode") ?: "allow"; start() }
    override fun onStart() {
        val result=Bundle()
        try {
            val payload="separate-UID-through-TUN".toByteArray()
            if(mode=="allow" || mode=="tcp_hold") {
                Socket().use { tcp ->
                    tcp.soTimeout=4000; tcp.connect(InetSocketAddress("10.0.2.2",28080),5000)
                    tcp.getOutputStream().write(payload)
                    val bytes=ByteArray(payload.size)
                    java.io.DataInputStream(tcp.getInputStream()).readFully(bytes)
                    check(bytes.contentEquals(payload)) { "TCP payload mismatch" }
                    if(mode=="tcp_hold") {
                        sendStatus(0,Bundle().apply { putString("phase","READY") })
                        Thread.sleep(1500)
                        try {
                            tcp.getOutputStream().write(payload)
                            result.putString("status",if(tcp.getInputStream().read()<0) "BLOCKED" else "ESCAPED")
                        } catch(_: SocketTimeoutException) { result.putString("status","BLOCKED") }
                        catch(_: java.net.SocketException) { result.putString("status","BLOCKED") }
                    }
                }
            }
            if(mode=="allow" || mode=="udp_block") {
                DatagramSocket().use { udp ->
                    udp.soTimeout=3000; udp.connect(InetSocketAddress("10.0.2.2",28081))
                    udp.send(DatagramPacket(payload,payload.size))
                    val reply=DatagramPacket(ByteArray(128),128)
                    try {
                        udp.receive(reply)
                        check(reply.data.copyOf(reply.length).contentEquals(payload)) { "UDP payload mismatch" }
                        result.putString("status",if(mode=="udp_block") "ESCAPED" else "OK")
                    } catch(e: SocketTimeoutException) {
                        if(mode=="udp_block") result.putString("status","BLOCKED") else throw e
                    }
                }
            }
        } catch(e: Exception) { result.putString("status","ERROR: ${e.javaClass.simpleName}: ${e.message}") }
        finish(Activity.RESULT_OK,result)
    }
}
