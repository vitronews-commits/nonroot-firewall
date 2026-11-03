package com.nonroot.firewall

import java.net.InetAddress

enum class Decision { ALLOW, BLOCK, PENDING }
enum class NetworkKind { WIFI, MOBILE, OTHER }
data class Connection(val packageName: String, val ip: String, val port: Int, val network: NetworkKind)
data class IpRule(val packageName: String?, val cidr: String, val network: NetworkKind?, val decision: Decision)
data class AppRule(val packageName: String, val network: NetworkKind?, val decision: Decision)

/** Pure policy engine. No network forwarding is implemented in this milestone. */
class RuleEngine(
    val ipRules: MutableList<IpRule> = mutableListOf(),
    val appRules: MutableList<AppRule> = mutableListOf()
) {
    fun decide(connection: Connection): Decision {
        require(connection.port in 0..65535)
        val applicable = ipRules.filter {
            (it.packageName == null || it.packageName == connection.packageName) &&
            (it.network == null || it.network == connection.network) &&
            matchesCidr(connection.ip, it.cidr)
        }
        // Specific app+IP outranks global IP; longest prefix outranks broader prefix.
        applicable.maxWithOrNull(compareBy<IpRule> {
            if (it.packageName == connection.packageName) 1 else 0
        }.thenBy { prefix(it.cidr) }.thenBy { if (it.network == connection.network) 1 else 0 })
            ?.let { return it.decision }
        appRules.lastOrNull { it.packageName == connection.packageName && (it.network == null || it.network == connection.network) }
            ?.let { return it.decision }
        return Decision.PENDING // Ask by default: unknown connections must never pass.
    }

    private fun prefix(cidr: String): Int = cidr.substringAfter('/', "").toIntOrNull() ?: -1

    private fun matchesCidr(address: String, cidr: String): Boolean {
        return try {
            val parts = cidr.split('/')
            if (parts.size != 2 || parts[0].any { it.isLetter() && it !in "abcdefABCDEF" }) return false
            val ip = InetAddress.getByName(address).address
            val network = InetAddress.getByName(parts[0]).address
            if (ip.size != network.size) return false
            val bits = parts[1].toInt()
            if (bits !in 0..ip.size * 8) return false
            for (i in 0 until bits / 8) if (ip[i] != network[i]) return false
            val rem = bits % 8
            rem == 0 || ((ip[bits / 8].toInt() xor network[bits / 8].toInt()) and (0xff shl (8 - rem))) == 0
        } catch (_: Exception) { false }
    }
}
