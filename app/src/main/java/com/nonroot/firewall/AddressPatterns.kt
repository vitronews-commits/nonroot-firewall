package com.nonroot.firewall

/** Classic NoRoot IPv4 wildcard syntax mapped to numeric CIDR. */
object AddressPatterns {
    fun normalize(input: String): String? {
        val raw = input.trim()
        if (raw == "*") return "0.0.0.0/0"
        if ('*' in raw) {
            val chunks = raw.split('.')
            if (chunks.size != 4) return null
            val firstWildcard = chunks.indexOfFirst { it == "*" }
            if (firstWildcard < 0 || chunks.drop(firstWildcard).any { it != "*" }) return null
            val octets = chunks.take(firstWildcard)
            if (octets.any { it.isEmpty() || !it.all(Char::isDigit) || it.toIntOrNull() !in 0..255 }) return null
            return (octets + List(4 - firstWildcard) { "0" }).joinToString(".") + "/" + (firstWildcard * 8)
        }
        val cidr = if ('/' in raw) raw else raw + if (':' in raw) "/128" else "/32"
        return cidr.takeIf { RuleEngine.isValidCidr(it) }
    }

    fun suggestions(address: String): List<String> {
        val raw = address.trim().substringBefore('/')
        val parts = raw.split('.')
        if (parts.size != 4 || parts.any { it.toIntOrNull() !in 0..255 }) return listOf(raw, "*").distinct()
        return listOf(raw, parts.take(3).joinToString(".") + ".*",
            parts.take(2).joinToString(".") + ".*.*",
            parts.take(1).joinToString(".") + ".*.*.*", "*")
    }
}
