package com.nonroot.firewall

import java.net.InetAddress

enum class Decision { ALLOW, BLOCK, PENDING }
enum class NetworkKind { WIFI, MOBILE, OTHER }
data class Connection(val packageName: String, val ip: String, val port: Int, val network: NetworkKind)
data class IpRule(val packageName: String?, val cidr: String, val network: NetworkKind?, val decision: Decision, val port: Int? = null)
data class AppRule(val packageName: String, val network: NetworkKind?, val decision: Decision)

/** Pure policy engine. No network forwarding is implemented in this milestone. */
class RuleEngine(
    val ipRules: MutableList<IpRule> = mutableListOf(),
    val appRules: MutableList<AppRule> = mutableListOf()
) {
    fun decide(connection: Connection): Decision {
        require(connection.port in 0..65535)
        // Precedence: first matching app-specific filter, then app access, then global filters, then pending.
        val specific = ipRules.filter {
            it.packageName == connection.packageName &&
            (it.network == null || it.network == connection.network) &&
            (it.port == null || it.port == connection.port) &&
            matchesCidr(connection.ip, it.cidr)
        }
        specific.firstOrNull()?.let { return it.decision }
        appRules.lastOrNull { it.packageName == connection.packageName && it.network == connection.network }
            ?.let { return it.decision }
        appRules.lastOrNull { it.packageName == connection.packageName && it.network == null }
            ?.let { return it.decision }
        val global = ipRules.filter {
            it.packageName == null &&
            (it.network == null || it.network == connection.network) &&
            (it.port == null || it.port == connection.port) &&
            matchesCidr(connection.ip, it.cidr)
        }
        global.firstOrNull()?.let { return it.decision }
        return Decision.PENDING // Ask by default: unknown connections must never pass.
    }

    companion object {
        /** Only numeric literals are accepted: no hostname resolution or network lookup. */
        fun isValidCidr(cidr: String): Boolean {
            val parts = cidr.split('/')
            if (parts.size != 2) return false
            val bits = parts[1].toIntOrNull() ?: return false
            val ip = parts[0]
            if (':' in ip) {
                if (!ip.matches(Regex("[0-9a-fA-F:.]+"))) return false
                return try {
                    val bytes = InetAddress.getByName(ip).address
                    bytes.size == 16 && bits in 0..128
                } catch (_: Exception) { false }
            }
            val octets = ip.split('.')
            if (octets.size != 4 || octets.any { it.isEmpty() || !it.all(Char::isDigit) || it.toIntOrNull() !in 0..255 }) return false
            return bits in 0..32
        }
    }

    private fun matchesCidr(address: String, cidr: String): Boolean {
        if (!isValidCidr(cidr)) return false
        return try {
            val parts = cidr.split('/')
            if (parts.size != 2 || parts[0].any { it.isLetter() && it !in "abcdefABCDEF" }) return false
            // Reject hostnames before InetAddress: policy evaluation must not trigger DNS.
            val numeric = if (':' in address) {
                address.matches(Regex("[0-9a-fA-F:.]+"))
            } else {
                val octets = address.split('.')
                octets.size == 4 && octets.all {
                    it.isNotEmpty() && it.all(Char::isDigit) && it.toIntOrNull() in 0..255
                }
            }
            if (!numeric) return false
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
