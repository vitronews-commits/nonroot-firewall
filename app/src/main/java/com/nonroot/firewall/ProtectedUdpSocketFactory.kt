package com.nonroot.firewall

import android.net.VpnService
import java.net.DatagramSocket
import java.net.InetSocketAddress

/**
 * Creates a UDP socket outside the VPN tunnel.
 * The caller owns the socket and must close it. No VPN interface is established.
 */
class ProtectedUdpSocketFactory(private val vpn: VpnService) {
    fun open(): DatagramSocket {
        val socket = DatagramSocket(null)
        try {
            check(vpn.protect(socket)) { "VPN socket protection failed" }
            socket.bind(InetSocketAddress(0))
            return socket
        } catch (failure: Exception) {
            socket.close()
            throw failure
        }
    }
}
