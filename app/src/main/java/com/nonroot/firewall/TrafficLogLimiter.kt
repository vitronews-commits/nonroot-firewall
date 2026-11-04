package com.nonroot.firewall

/** Counters track every packet; the UI log samples repetitive per-flow events once per second. */
class TrafficLogLimiter(private val intervalMs: Long=1000,private val capacity: Int=256) {
    private val last=LinkedHashMap<Pair<PacketParser.Header?,Int>,Long>()
    init { require(intervalMs>0 && capacity>0) }
    @Synchronized fun allow(header: PacketParser.Header?,kind: Int,now: Long=System.nanoTime()/1000000): Boolean {
        val key=header to kind
        val before=last[key]
        if(before!=null && now>=before && now-before<intervalMs) return false
        if(!last.containsKey(key) && last.size>=capacity) last.remove(last.keys.first())
        last[key]=now
        return true
    }
    @Synchronized fun clear()=last.clear()
}
