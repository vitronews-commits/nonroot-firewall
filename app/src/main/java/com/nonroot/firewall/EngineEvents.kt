package com.nonroot.firewall

/** Bounded metadata only. No payloads or DNS content are retained. */
object EngineEvents {
    data class Event(val time: Long, val connection: Connection?, val result: String)
    val pending=PendingQueue()
    @Volatile var status="OFF — validation required"
    private val events=ArrayDeque<Event>()
    @Synchronized fun record(connection: Connection?, result: String) {
        if(events.size==500) events.removeFirst()
        events.addLast(Event(System.currentTimeMillis(),connection,result))
    }
    @Synchronized fun snapshot()=events.toList().asReversed()
}
