package com.nonroot.firewall

import java.net.DatagramSocket
import java.net.Socket

/** Protection must succeed before any bind/connect. Injection makes failure testable. */
object SocketProtection {
    fun tcp(protect: (Socket)->Boolean): Socket {
        val s=Socket()
        try { check(protect(s)) { "TCP socket protection rejected" }; return s }
        catch(e: Exception) { s.close(); throw e }
    }
    fun udp(protect: (DatagramSocket)->Boolean): DatagramSocket {
        val s=DatagramSocket(null)
        try { check(protect(s)) { "UDP socket protection rejected" }; return s }
        catch(e: Exception) { s.close(); throw e }
    }
}
