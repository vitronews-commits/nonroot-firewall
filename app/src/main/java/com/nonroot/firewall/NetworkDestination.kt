package com.nonroot.firewall

import java.net.Inet6Address
import java.net.InetAddress
import java.net.InetSocketAddress
import java.net.NetworkInterface

/** Policy keeps unscoped numeric addresses; link-local socket destinations need physical scope. */
object NetworkDestination {
    fun resolve(header: PacketParser.Header,interfaceName: String?): InetSocketAddress {
        require(header.destination.matches(Regex("[0-9a-fA-F:.]+"))) { "Numeric destination required" }
        var address=InetAddress.getByName(header.destination)
        if(address is Inet6Address && address.isLinkLocalAddress) {
            val networkInterface=interfaceName?.let { NetworkInterface.getByName(it) }
                ?: error("No underlying interface for link-local destination")
            require(networkInterface.index>0)
            address=Inet6Address.getByAddress(null,address.address,networkInterface.index)
        }
        return InetSocketAddress(address,checkNotNull(header.destinationPort))
    }
}
