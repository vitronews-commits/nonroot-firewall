package com.nonroot.firewall

import org.junit.Assert.*
import org.junit.Test
import java.net.Inet6Address
import java.net.InetAddress
import java.net.NetworkInterface

class NetworkDestinationTest {
    private fun header(ip: String)=PacketParser.Header("fd23::2",ip,17,1234,53,false)
    @Test fun linkLocalGetsUnderlyingInterfaceScope() {
        val loop=checkNotNull(NetworkInterface.getByInetAddress(InetAddress.getByName("::1")))
        val result=NetworkDestination.resolve(header("fe80::1"),loop.name)
        assertEquals(loop.index,(result.address as Inet6Address).scopeId)
        assertEquals(53,result.port)
    }
    @Test fun globalV6AndV4DoNotRequireScope() {
        assertEquals(0,(NetworkDestination.resolve(header("2001:db8::1"),null).address as Inet6Address).scopeId)
        assertEquals("192.0.2.4",NetworkDestination.resolve(header("192.0.2.4"),null).address.hostAddress)
    }
    @Test fun missingScopeAndHostnamesFailClosed() {
        try { NetworkDestination.resolve(header("fe80::1"),null); fail() } catch(_: IllegalStateException) { }
        try { NetworkDestination.resolve(header("example.com"),null); fail() } catch(_: IllegalArgumentException) { }
    }
}
