package com.nonroot.firewall

/** Reject excessive nesting before invoking Android's recursive JSON parser on an untrusted file. */
object JsonEnvelope {
    fun validate(text: String,maxDepth: Int=8) {
        val stack=ArrayDeque<Char>(); var quoted=false; var escaped=false
        for(c in text) {
            if(quoted) {
                require(c.code>=32) { "Control character in JSON string" }
                if(escaped) escaped=false else if(c=='\\') escaped=true else if(c=='"') quoted=false
            } else when(c) {
                '"' -> quoted=true
                '{','[' -> { require(stack.size<maxDepth) { "JSON nesting limit exceeded" }; stack.addLast(c) }
                '}',']' -> { require(stack.isNotEmpty() && stack.removeLast()==if(c=='}') '{' else '[') { "Unbalanced JSON" } }
            }
        }
        require(!quoted && !escaped && stack.isEmpty()) { "Incomplete JSON" }
    }
}
