package com.nonroot.firewall

import android.content.Context
import android.net.ConnectivityManager
import android.os.Build
import android.os.Process
import java.net.InetSocketAddress

/**
 * Android 10+ connection owner lookup for an active VPN.
 * The caller must supply the original packet's source/destination tuple.
 * No ownership is inferred from IP address alone.
 */
class ConnectionOwnerResolver(context: Context) {
    private val connectivity = context.getSystemService(ConnectivityManager::class.java)
    private val packages = context.packageManager

    data class Owner(val uid: Int, val packageNames: List<String>) {
        /** Shared UIDs are ambiguous; do not silently select an arbitrary package. */
        val unambiguousPackage: String? get() = packageNames.singleOrNull()
    }

    fun resolve(packet: PacketParser.Header): Owner? {
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.Q) return null
        if (packet.fragmented || packet.sourcePort == null || packet.destinationPort == null) return null
        val protocol = when (packet.protocol) {
            6 -> android.system.OsConstants.IPPROTO_TCP
            17 -> android.system.OsConstants.IPPROTO_UDP
            else -> return null
        }
        return try {
            val local = InetSocketAddress(java.net.InetAddress.getByName(packet.source), packet.sourcePort)
            val remote = InetSocketAddress(java.net.InetAddress.getByName(packet.destination), packet.destinationPort)
            val uid = connectivity.getConnectionOwnerUid(protocol, local, remote)
            if (uid == Process.INVALID_UID || uid < 0) return null
            val names = packages.getPackagesForUid(uid)?.distinct()?.sorted().orEmpty()
            if (names.isEmpty()) null else Owner(uid, names)
        } catch (_: SecurityException) {
            null
        } catch (_: IllegalArgumentException) {
            null
        } catch (_: RuntimeException) {
            null
        }
    }
}
