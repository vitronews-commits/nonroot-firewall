package com.nonroot.firewall

/** Bounded metadata only. No payloads or DNS content are retained. */
object EngineEvents {
    data class Event(val time: Long, val connection: Connection?, val result: String,val protocol: Int?=null)
    data class LiveConnection(val connection: Connection,val protocol: Int,val sourcePort: Int?,val status: String,val tunInputBytes: Long,val tunOutputBytes: Long)
    @Volatile var liveConnections: ()->List<LiveConnection> = { emptyList() }
    val pending=PendingQueue()
    @Volatile var status="OFF — validation required"
    private val events=ArrayDeque<Event>()
    @Synchronized fun record(connection: Connection?, result: String,protocol: Int?=null) {
        if(events.size==500) events.removeFirst()
        events.addLast(Event(System.currentTimeMillis(),connection,result,protocol))
    }
    @Synchronized fun snapshot()=events.toList().asReversed()
}
