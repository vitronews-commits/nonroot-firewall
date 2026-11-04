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
    private val onError: (Exception)->Unit={},
    private val pathMtu: ()->Int={ 1500 },
    private val authorizeIo: (PacketParser.Header)->Boolean=policy,
    private val destination: (PacketParser.Header)->InetSocketAddress={ InetSocketAddress(it.destination,it.destinationPort!!) },
    private val onFlowError: (PacketParser.Header,Exception)->Unit={ _,e -> onError(e) },
    private val nanoTime: ()->Long={ System.nanoTime() }
): Closeable {
    init { require(capacity in 1..128) }
    private class Lease { val open=AtomicBoolean(true) }
    private data class Entry(val lease: Lease, val initialSequence: Long, val closeable: Closeable, val accept: (TransportPacket.Packet)->Boolean, var lastActivity: Long, val startedAt: Long=System.currentTimeMillis(), var inputBytes: Long=0,var outputBytes: Long=0,val state: ()->String={ "ACTIVE" })
    private val flows=HashMap<PacketParser.Header,Entry>()
    private val workers=ThreadPoolExecutor(0,capacity,30,TimeUnit.SECONDS,SynchronousQueue())
    @Volatile private var generation=0L
    private val closed=AtomicBoolean(false)
    private val sweeper=java.util.concurrent.Executors.newSingleThreadScheduledExecutor().apply {
        scheduleWithFixedDelay({ expireIdle() },5,5,TimeUnit.SECONDS)
    }
    @Synchronized fun accept(raw: ByteArray): Boolean {
        if(closed.get()) return false
        val p=TransportPacket.parse(raw) ?: return false
        val h=p.header
        if(!policy(h)) { flows.remove(h)?.let { retire(it) }; return false }
        if(h.protocol==17) {
            val mtu=pathMtu().coerceIn(if(':' in h.source) 1280 else 68,1500)
            if(raw.size>mtu) PathMtu.response(raw,mtu)?.let { error -> if(policy(h) && authorizeIo(h)) output(error); return false }
        }
        flows[h]?.let {
            // A new SYN may reuse a tuple before the previous worker has exited.
            if(!it.lease.open.get() || (h.protocol==6 && p.flags and 0x3f==TcpProxySession.SYN && p.sequence!=it.initialSequence)) {
                flows.remove(h); retire(it)
            }
        }
        flows[h]?.let {
            val accepted=it.accept(p)
            if(accepted) { it.lastActivity=nanoTime(); it.inputBytes+=raw.size }
            return accepted
        }
        if(flows.size>=capacity) return false
        val epoch=generation
        val lease=Lease()
        val resource: Closeable
        val accept: (TransportPacket.Packet)->Boolean
        val run: ()->Unit
        val state: ()->String
        if(h.protocol==6) {
            if(p.flags and 0x3f!=TcpProxySession.SYN || p.payload.isNotEmpty()) return false
            val session=TcpProxySession(p,tcpSocket,{ deliver(h,it,epoch,lease) },{ valid(h,epoch,lease) },onError={ onFlowError(h,it) },authorizeUpload={ allowed(h,epoch,lease) },destination={ destination(h) },nanoTime=nanoTime)
            resource=session; accept={ session.offer(it) }; run={ session.run() }; state={ session.state() }
        } else {
            val session=UdpSession(h,epoch,lease)
            if(!session.offer(p)) { session.close(); return false }
            resource=session; accept={ session.offer(it) }; run={ session.run() }; state={ "ACTIVE" }
        }
        val entry=Entry(lease,p.sequence,resource,accept,lastActivity=nanoTime(),inputBytes=raw.size.toLong(),state=state)
        flows[h]=entry
        try {
            workers.execute {
                try { run() } finally {
                    lease.open.set(false)
                    try { resource.close() } finally {
                        synchronized(this) { if(flows[h]===entry) flows.remove(h) }
                    }
                }
            }
        } catch(_: Exception) { flows.remove(h); retire(entry); return false }
        return true
    }
    private fun valid(h: PacketParser.Header, epoch: Long, lease: Lease)=lease.open.get() && !closed.get() && generation==epoch && policy(h)
    private fun allowed(h: PacketParser.Header, epoch: Long, lease: Lease)=valid(h,epoch,lease) && authorizeIo(h)
    @Synchronized private fun deliver(h: PacketParser.Header, b: ByteArray, epoch: Long, lease: Lease) { if(flows[h]?.lease===lease && allowed(h,epoch,lease)) { output(b); flows[h]?.let { it.lastActivity=nanoTime(); it.outputBytes+=b.size } } }
    @Synchronized private fun expireIdle() {
        val now=nanoTime()
        val iterator=flows.iterator()
        while(iterator.hasNext()) {
            val e=iterator.next()
            val limit=if(e.key.protocol==6) 120_000 else 30_000
            if((now-e.value.lastActivity)/1_000_000>=limit) { retire(e.value); iterator.remove() }
        }
    }
    private fun retire(entry: Entry) {
        entry.lease.open.set(false)
        try { entry.closeable.close() } catch(e: Exception) { try { onError(e) } catch(_: Exception) { } }
    }
    @Synchronized fun invalidate() { generation++; flows.values.forEach { retire(it) }; flows.clear() }
    data class Snapshot(val header: PacketParser.Header,val startedAt: Long,val tunInputBytes: Long,val tunOutputBytes: Long,val status: String)
    @Synchronized fun snapshot()=flows.map { (h,e) -> Snapshot(h,e.startedAt,e.inputBytes,e.outputBytes,e.state()) }
    @Synchronized fun activeCount()=flows.size
    @Synchronized fun activeHeaders(): Set<PacketParser.Header> = flows.keys.toSet()
    @Synchronized override fun close() {
        if(closed.compareAndSet(false,true)) { invalidate(); workers.shutdownNow(); sweeper.shutdownNow() }
    }
    private inner class UdpSession(private val h: PacketParser.Header, private val epoch: Long, private val lease: Lease): Closeable {
        private val queue=java.util.concurrent.ArrayBlockingQueue<ByteArray>(32)
        private val stopped=AtomicBoolean(false)
        @Volatile private var socket: DatagramSocket?=null
        @Volatile private var selector: java.nio.channels.Selector?=null
        fun offer(p: TransportPacket.Packet): Boolean {
            if(stopped.get() || !queue.offer(p.payload)) return false
            selector?.wakeup(); return true
        }
        fun run() {
            try {
                if(stopped.get() || !allowed(h,epoch,lease)) return
                val s=udpSocket(); socket=s
                if(stopped.get() || !allowed(h,epoch,lease)) { s.close(); return }
                s.bind(InetSocketAddress(0))
                val remote=destination(h); s.soTimeout=50
                val channel=s.channel
                var key=if(channel!=null) {
                    val selected=java.nio.channels.Selector.open(); selector=selected
                    channel.configureBlocking(false); channel.register(selected,java.nio.channels.SelectionKey.OP_READ)
                } else null
                var last=nanoTime()
                val maxPayload=1500-(if(':' in h.source) 40 else 20)-8
                val buffer=ByteArray(maxPayload+1)
                val nio=java.nio.ByteBuffer.wrap(buffer)
                while(!stopped.get() && valid(h,epoch,lease) && (nanoTime()-last)/1_000_000<30_000) {
                    var sendBlocked=false
                    repeat(32) {
                        queue.poll()?.let { b ->
                            if(!allowed(h,epoch,lease) || stopped.get()) return@let
                            if(channel!=null) {
                                val count=channel.send(java.nio.ByteBuffer.wrap(b),remote)
                                if(count==0 && b.isNotEmpty()) { queue.offer(b); sendBlocked=true }
                                else last=nanoTime()
                            } else { s.send(DatagramPacket(b,b.size,remote)); last=nanoTime() }
                        }
                    }
                    if(channel!=null) {
                        var receiveBudget=32
                        while(receiveBudget-->0 && !stopped.get()) {
                            nio.clear()
                            val sender=channel.receive(nio) ?: break
                            if(sender!=remote) continue
                            last=nanoTime()
                            if(nio.position()<=maxPayload) deliver(h,TransportPacket.build(TransportPacket.reverse(h),buffer.copyOf(nio.position())),epoch,lease)
                        }
                        if(queue.isNotEmpty() && !sendBlocked) continue
                        key!!.interestOps(java.nio.channels.SelectionKey.OP_READ or if(sendBlocked) java.nio.channels.SelectionKey.OP_WRITE else 0)
                        selector!!.select(1000); selector!!.selectedKeys().clear()
                    } else {
                        val packet=DatagramPacket(buffer,buffer.size)
                        try {
                            s.receive(packet); last=nanoTime()
                            if(packet.socketAddress==remote && packet.length<=maxPayload && !stopped.get()) deliver(h,TransportPacket.build(TransportPacket.reverse(h),buffer.copyOf(packet.length)),epoch,lease)
                        } catch(_: SocketTimeoutException) { }
                    }
                }
            } catch(e: Exception) { if(!stopped.get() && !closed.get()) onFlowError(h,e) }
            finally { close(); try { selector?.close() } catch(_: Exception) { } }
        }
        override fun close() {
            if(stopped.compareAndSet(false,true)) {
                selector?.wakeup()
                try { socket?.close() } finally { try { selector?.close() } finally { queue.clear() } }
            }
        }
    }
}
