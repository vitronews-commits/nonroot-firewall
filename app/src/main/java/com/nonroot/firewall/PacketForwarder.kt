package com.nonroot.firewall

import java.io.Closeable
import java.net.DatagramPacket
import java.net.DatagramSocket
import java.net.InetSocketAddress
import java.net.Socket
import java.net.SocketTimeoutException
import java.util.concurrent.ThreadPoolExecutor
import java.util.concurrent.SynchronousQueue
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicBoolean

/** Transport orchestration shared by off-device integration tests and VpnService. */
class PacketForwarder(
    private val tcpSocket: ()->Socket,
    private val udpSocket: ()->DatagramSocket,
    private val policy: (PacketParser.Header)->Boolean,
    private val output: (ByteArray)->Unit,
    private val capacity: Int=64,
    private val onError: (Exception)->Unit={}
): Closeable {
    private data class Entry(val closeable: Closeable, val accept: (TransportPacket.Packet)->Boolean, var lastActivity: Long=System.nanoTime())
    private val flows=HashMap<PacketParser.Header,Entry>()
    private val workers=ThreadPoolExecutor(0,capacity,30,TimeUnit.SECONDS,SynchronousQueue())
    @Volatile private var generation=0L
    private val closed=AtomicBoolean(false)
    private val sweeper=java.util.concurrent.Executors.newSingleThreadScheduledExecutor().apply {
        scheduleWithFixedDelay({ expireIdle() },1,1,TimeUnit.SECONDS)
    }
    init { require(capacity in 1..128) }
    @Synchronized fun accept(raw: ByteArray): Boolean {
        if(closed.get()) return false
        val p=TransportPacket.parse(raw) ?: return false
        val h=p.header
        if(!policy(h)) { flows.remove(h)?.closeable?.close(); return false }
        flows[h]?.let { it.lastActivity=System.nanoTime(); return it.accept(p) }
        if(flows.size>=capacity) return false
        val epoch=generation
        val resource: Closeable
        val accept: (TransportPacket.Packet)->Boolean
        val run: ()->Unit
        if(h.protocol==6) {
            if(p.flags and 0x3f!=TcpProxySession.SYN || p.payload.isNotEmpty()) return false
            val session=TcpProxySession(p,tcpSocket,{ deliver(h,it,epoch) },{ allowed(h,epoch) },onError=onError)
            resource=session; accept={ session.offer(it) }; run={ session.run() }
        } else {
            val session=UdpSession(h,epoch)
            if(!session.offer(p)) { session.close(); return false }
            resource=session; accept={ session.offer(it) }; run={ session.run() }
        }
        val entry=Entry(resource,accept)
        flows[h]=entry
        try {
            workers.execute {
                try { run() } finally {
                    resource.close()
                    synchronized(this) { if(flows[h]===entry) flows.remove(h) }
                }
            }
        } catch(_: Exception) { flows.remove(h); resource.close(); return false }
        return true
    }
    private fun allowed(h: PacketParser.Header, epoch: Long)=!closed.get() && generation==epoch && policy(h)
    @Synchronized private fun deliver(h: PacketParser.Header, b: ByteArray, epoch: Long) { if(allowed(h,epoch)) { flows[h]?.lastActivity=System.nanoTime(); output(b) } }
    @Synchronized private fun expireIdle() {
        val now=System.nanoTime()
        val iterator=flows.iterator()
        while(iterator.hasNext()) {
            val e=iterator.next()
            val limit=if(e.key.protocol==6) 120_000 else 30_000
            if((now-e.value.lastActivity)/1_000_000>=limit) { e.value.closeable.close(); iterator.remove() }
        }
    }
    @Synchronized fun invalidate() { generation++; flows.values.forEach { it.closeable.close() }; flows.clear() }
    @Synchronized fun activeCount()=flows.size
    @Synchronized fun activeHeaders(): Set<PacketParser.Header> = flows.keys.toSet()
    @Synchronized override fun close() {
        if(closed.compareAndSet(false,true)) { invalidate(); workers.shutdownNow(); sweeper.shutdownNow() }
    }
    private inner class UdpSession(private val h: PacketParser.Header, private val epoch: Long): Closeable {
        private val queue=java.util.concurrent.ArrayBlockingQueue<ByteArray>(32)
        private val stopped=AtomicBoolean(false)
        @Volatile private var socket: DatagramSocket?=null
        fun offer(p: TransportPacket.Packet)=!stopped.get() && queue.offer(p.payload)
        fun run() {
            try {
                if(stopped.get() || !allowed(h,epoch)) return
                val s=udpSocket(); socket=s
                if(stopped.get() || !allowed(h,epoch)) { s.close(); return }
                s.bind(InetSocketAddress(0))
                s.connect(InetSocketAddress(h.destination,h.destinationPort!!)); s.soTimeout=50
                var last=System.nanoTime()
                // One extra byte detects oversize responses; never deliver truncated DNS/QUIC.
                val maxPayload=1500-(if(':' in h.source) 40 else 20)-8
                val buffer=ByteArray(maxPayload+1)
                while(!stopped.get() && allowed(h,epoch) && (System.nanoTime()-last)/1_000_000<30_000) {
                    repeat(32) {
                        queue.poll()?.let { b ->
                            if(!allowed(h,epoch) || stopped.get()) return@let
                            s.send(DatagramPacket(b,b.size)); last=System.nanoTime()
                        }
                    }
                    val packet=DatagramPacket(buffer,buffer.size)
                    try {
                        s.receive(packet); last=System.nanoTime()
                        if(packet.length<=maxPayload && !stopped.get())
                            deliver(h,TransportPacket.build(TransportPacket.reverse(h),buffer.copyOf(packet.length)),epoch)
                    } catch(_: SocketTimeoutException) { }
                }
            } catch(e: Exception) { if(!stopped.get() && !closed.get()) onError(e) } finally { close() }
        }
        override fun close() { if(stopped.compareAndSet(false,true)) { socket?.close(); queue.clear() } }
    }
}
