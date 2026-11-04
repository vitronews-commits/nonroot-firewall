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
    private fun permissionDenied(error: Throwable): Boolean {
        var cause: Throwable?=error
        while(cause!=null) {
            if(cause is android.system.ErrnoException &&
                cause.errno in listOf(android.system.OsConstants.EPERM,android.system.OsConstants.EACCES)) return true
            cause=cause.cause
        }
        return false
    }
    override fun onStart() {
        val result=Bundle()
        var stage="initial"
        try {
            val payload="separate-UID-through-TUN".toByteArray()
            val tcpPayload=if(mode=="allow") ByteArray(65536) { (it*37).toByte() } else payload
            if(mode=="allow" || mode=="tcp_hold") {
                Socket().use { tcp ->
                    stage="tcp-connect"
                    tcp.soTimeout=15000; tcp.connect(InetSocketAddress("10.0.2.2",28080),5000)
                    stage="tcp-first-echo"
                    tcp.getOutputStream().write(tcpPayload)
                    val bytes=ByteArray(tcpPayload.size)
                    java.io.DataInputStream(tcp.getInputStream()).readFully(bytes)
                    check(bytes.contentEquals(tcpPayload)) { "TCP payload mismatch" }
                    if(mode=="tcp_hold") {
                        sendStatus(0,Bundle().apply { putString("phase","READY") })
                        Thread.sleep(1500)
                        stage="tcp-after-revoke"
                        try {
                            tcp.getOutputStream().write(tcpPayload)
                            result.putString("status",if(tcp.getInputStream().read()<0) "BLOCKED" else "ESCAPED")
                        } catch(_: SocketTimeoutException) { result.putString("status","BLOCKED") }
                        catch(_: java.net.SocketException) { result.putString("status","BLOCKED") }
                        catch(e: java.io.IOException) { if(permissionDenied(e)) result.putString("status","BLOCKED") else throw e }
                    }
                }
            }
            if(mode=="allow" || mode=="udp_block") {
                DatagramSocket().use { udp ->
                    udp.soTimeout=3000; udp.connect(InetSocketAddress("10.0.2.2",28081))
                    stage="udp-send"
                    udp.send(DatagramPacket(payload,payload.size))
                    val reply=DatagramPacket(ByteArray(128),128)
                    try {
                        stage="udp-receive"
                        udp.receive(reply)
                        check(reply.data.copyOf(reply.length).contentEquals(payload)) { "UDP payload mismatch" }
                        result.putString("status",if(mode=="udp_block") "ESCAPED" else "OK")
                    } catch(e: SocketTimeoutException) {
                        if(mode=="udp_block") result.putString("status","BLOCKED") else throw e
                    }
                }
            }
        } catch(e: Exception) {
            if(mode=="udp_block" && permissionDenied(e)) result.putString("status","BLOCKED")
            else result.putString("status","ERROR mode=$mode stage=$stage: ${e.javaClass.simpleName}: ${e.message}")
        }
        finish(Activity.RESULT_OK,result)
    }
}
