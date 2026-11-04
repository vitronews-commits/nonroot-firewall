package com.nonroot.firewall

import java.net.DatagramSocket
import java.net.Socket
import java.net.InetSocketAddress

/** Protection must succeed before connect/send. A local TCP bind creates Android's lazy native descriptor without transmitting traffic. */
object SocketProtection {
    fun tcp(protect: (Socket)->Boolean): Socket {
        val s=Socket()
        try {
            // Android Socket() does not allocate a native FD until bind/connect.
            // Protecting an uncreated FD fails; local bind must precede protect.
            s.bind(InetSocketAddress(0))
            check(protect(s)) { "TCP socket protection rejected" }
            return s
        }
        catch(e: Exception) { s.close(); throw e }
    }
    fun udp(protect: (DatagramSocket)->Boolean): DatagramSocket {
        val s=DatagramSocket(null)
        try { check(protect(s)) { "UDP socket protection rejected" }; return s }
        catch(e: Exception) { s.close(); throw e }
    }
}
