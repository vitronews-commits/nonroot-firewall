package com.nonroot.firewall

/** Whole-packet TUN writes. false from attempt means EAGAIN, never a partially written packet. */
class TunWriter(
    private val attempt: (ByteArray)->Boolean,
    private val waitWritable: (Int)->Unit,
    private val permitted: (ByteArray)->Boolean,
    private val clock: ()->Long={ System.nanoTime()/1000000 },
    private val timeoutMs: Long=1000
) {
    init { require(timeoutMs>0) }
    @Synchronized fun write(packet: ByteArray): Boolean {
        val deadline=clock()+timeoutMs
        while(permitted(packet)) {
            if(attempt(packet)) return true
            val remaining=deadline-clock()
            if(remaining<=0) throw java.net.SocketTimeoutException("TUN write backpressure timeout")
            waitWritable(minOf(50L,remaining).toInt())
        }
        return false
    }
}
