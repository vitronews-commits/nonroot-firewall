package com.nonroot.firewall

import java.io.Closeable
import java.net.InetSocketAddress
import java.net.Socket
import java.nio.ByteBuffer
import java.nio.channels.SelectionKey
import java.nio.channels.Selector
import java.security.SecureRandom
import java.util.concurrent.ArrayBlockingQueue
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicBoolean

/** Bounded TCP endpoint. No window scaling/SACK negotiation; reordering is recovered by retransmission.
 * One state owner, 32 KiB upload buffer, at most 64 KiB unacknowledged response, selector wakeups.
 * Production socket factory supplies a protected SocketChannel; plain sockets support the baseline harness.
 */
class TcpProxySession(
    private val initial: TransportPacket.Packet,
    private val socketFactory: ()->Socket,
    private val reply: (ByteArray)->Unit,
    private val permitted: ()->Boolean,
    private val idleMs: Long=120_000,
    private val initialSequence: Long=SecureRandom().nextInt().toLong() and MASK,
    private val onError: (Exception)->Unit={},
    private val authorizeUpload: ()->Boolean=permitted,
    private val destination: ()->InetSocketAddress={ InetSocketAddress(initial.header.destination,initial.header.destinationPort!!) },
    private val nanoTime: ()->Long={ System.nanoTime() }
): Closeable {
    companion object {
        const val FIN=1; const val SYN=2; const val RST=4; const val PSH=8; const val ACK=16
        const val MASK=0xffffffffL
        private const val RECEIVE_WINDOW=32768
        fun add(sequence: Long, amount: Int)=(sequence+amount) and MASK
        private fun distance(from: Long,to: Long)=(to-from) and MASK
    }
    private data class Sent(val sequence: Long,val end: Long,val bytes: ByteArray,var at: Long,var retries: Int=0)
    @Volatile private var state="CONNECTING"
    fun state()=state
    private val closed=AtomicBoolean(false)
    private val incoming=ArrayBlockingQueue<TransportPacket.Packet>(256)
    @Volatile private var socket: Socket?=null
    @Volatile private var selector: Selector?=null
    private var clientNext=add(initial.sequence,1)
    private var serverNext=initialSequence
    private var serverAcknowledged=initialSequence
    private var established=false
    private var clientFin=false
    private var outputShutdown=false
    private var remoteFin=false
    private var peerWindow=initial.window
    private var lastActivity=nanoTime()
    private val sent=ArrayDeque<Sent>()
    private val upload=ByteBuffer.allocate(RECEIVE_WINDOW)
    private var windowSequence=initial.sequence
    private var windowAck=initialSequence
    private var duplicateAcks=0
    private var lastProbe=0L
    private var operation="initial"
    private var lastDataByte: Byte?=null
    private val reverse=TransportPacket.reverse(initial.header)
    private val receiveMss=if(':' in initial.header.source) 1440 else 1460
    private val sendMss=minOf(initial.maximumSegmentSize ?: if(':' in initial.header.source) 1220 else 536,receiveMss)
    init {
        require(initial.flags and 0x3f==SYN && initial.payload.isEmpty())
        require(idleMs>=1000)
        require(initial.maximumSegmentSize==null || initial.maximumSegmentSize in 1..65535)
    }
    fun offer(packet: TransportPacket.Packet): Boolean {
        if(closed.get() || !incoming.offer(packet)) return false
        selector?.wakeup()
        return true
    }
    fun isClosed()=closed.get()
    private fun now()=nanoTime()/1_000_000
    private fun emit(payload: ByteArray=byteArrayOf(),flags: Int=ACK,tracked: Boolean=false) {
        if(closed.get() || !permitted()) return
        val sequence=serverNext
        val bytes=TransportPacket.build(reverse,payload,sequence,clientNext,flags,upload.remaining(),
            maximumSegmentSize=if(flags and SYN!=0) receiveMss else null)
        if(tracked) {
            serverNext=add(serverNext,payload.size+if(flags and (SYN or FIN)!=0) 1 else 0)
            sent.addLast(Sent(sequence,serverNext,bytes,now()))
            if(payload.isNotEmpty()) lastDataByte=payload.last()
        }
        reply(bytes)
    }
    fun run() {
        try {
            if(closed.get() || !permitted() || !authorizeUpload()) return
            val upstream=socketFactory(); socket=upstream
            if(closed.get() || !permitted() || !authorizeUpload()) { upstream.close(); return }
            upstream.tcpNoDelay=true
            operation="connect"
            upstream.connect(destination(),5000)
            val channel=upstream.channel
            val key=if(channel!=null) {
                val selected=Selector.open(); selector=selected
                channel.configureBlocking(false); channel.register(selected,0)
            } else null
            state="SYN_RECEIVED"
            emit(flags=SYN or ACK,tracked=true)
            val buffer=ByteArray(sendMss)
            while(!closed.get() && permitted()) {
                if((nanoTime()-lastActivity)/1_000_000>=idleMs) break
                repeat(32) { incoming.poll()?.let { process(it,upstream) } }
                if(closed.get()) break
                if(upload.position()>0) {
                    if(!authorizeUpload()) break
                    val previousFree=upload.remaining()
                    operation="upload-write"
                    upload.flip()
                    if(channel!=null) channel.write(upload)
                    else { val b=ByteArray(upload.remaining()); upload.get(b); upstream.getOutputStream().write(b) }
                    upload.compact()
                    // Reopen a closed/small receive window without waiting for another upload.
                    if(upload.remaining()>previousFree && (previousFree<receiveMss || upload.remaining()-previousFree>=receiveMss)) emit()
                }
                if(clientFin && !outputShutdown && upload.position()==0) { shutdownOutput(upstream); outputShutdown=true }
                var progressed=false
                if(established && !remoteFin) {
                    var budget=64
                    while(budget-->0) {
                        val available=(peerWindow-distance(serverAcknowledged,serverNext)).coerceAtMost(65535).toInt()
                        if(remoteFin || available<=0 || sent.size>=128 || !permitted() || closed.get()) break
                        operation="response-read"
                        val count=if(channel!=null) channel.read(ByteBuffer.wrap(buffer,0,minOf(buffer.size,available)))
                            else if(upstream.getInputStream().available()>0) upstream.getInputStream().read(buffer,0,minOf(buffer.size,available)) else 0
                        if(count<0) { remoteFin=true; state="REMOTE_HALF_CLOSED"; emit(flags=FIN or ACK,tracked=true); break }
                        if(count>0) { lastActivity=nanoTime(); emit(buffer.copyOf(count),ACK or PSH,true); progressed=true }
                        else break
                    }
                    // Plain-socket harness needs EOF detection; production uses selector/channel EOF.
                    if(channel==null && !progressed && sent.isEmpty() && peerWindow>0) {
                        upstream.soTimeout=10
                        try {
                            val count=upstream.getInputStream().read(buffer,0,minOf(buffer.size,peerWindow))
                            if(count<0) { remoteFin=true; state="REMOTE_HALF_CLOSED"; emit(flags=FIN or ACK,tracked=true) }
                            else if(count>0) { lastActivity=nanoTime(); emit(buffer.copyOf(count),ACK or PSH,true); progressed=true }
                        } catch(_: java.net.SocketTimeoutException) { }
                    }
                }
                val oldest=sent.firstOrNull()
                if(oldest!=null && now()-oldest.at >= (1000L shl oldest.retries.coerceAtMost(3))) {
                    if(++oldest.retries>5) break
                    if(permitted() && !closed.get()) reply(oldest.bytes)
                    oldest.at=now()
                }
                if(established && peerWindow==0 && now()-lastProbe>=1000) {
                    lastProbe=now()
                    if(permitted()) reply(TransportPacket.build(reverse,lastDataByte?.let { byteArrayOf(it) } ?: byteArrayOf(),
                        add(serverNext,-1),clientNext,ACK,upload.remaining()))
                }
                if(clientFin && remoteFin && sent.isEmpty()) break
                if(incoming.isNotEmpty() || progressed) continue
                if(key!=null) {
                    var ops=0
                    if(established && !remoteFin && peerWindow>distance(serverAcknowledged,serverNext) && sent.size<128) ops=ops or SelectionKey.OP_READ
                    if(upload.position()>0) ops=ops or SelectionKey.OP_WRITE
                    key.interestOps(ops)
                    selector!!.select(if(peerWindow==0 || sent.isNotEmpty()) 100 else 1000)
                    selector!!.selectedKeys().clear()
                } else incoming.poll(20,TimeUnit.MILLISECONDS)?.let { process(it,upstream) }
            }
        } catch(e: Exception) {
            if(!closed.get()) onError(java.io.IOException("TCP $operation: ${e.message}; clientFin=$clientFin remoteFin=$remoteFin uploadPending=${upload.position()} inFlight=${distance(serverAcknowledged,serverNext)}",e))
            try { emit(flags=RST or ACK) } catch(_: Exception) { }
        } finally { close(); try { selector?.close() } catch(_: Exception) { } }
    }
    private fun shutdownOutput(upstream: Socket) {
        operation="half-close"
        val channel=upstream.channel
        if(channel!=null) channel.shutdownOutput() else upstream.shutdownOutput()
    }
    private fun process(p: TransportPacket.Packet,upstream: Socket) {
        if(!permitted() || closed.get()) return
        if(p.flags and RST!=0) {
            if(p.sequence==clientNext) close()
            else if(distance(clientNext,p.sequence)<RECEIVE_WINDOW) emit()
            return
        }
        if(p.flags and SYN!=0) {
            if(p.sequence==initial.sequence && !established) sent.firstOrNull()?.let { reply(it.bytes) }
            return
        }
        if(p.flags and ACK==0) return
        // ACK processing and ordered upload consumption are independent.
        val seqDistance=distance(clientNext,p.sequence)
        if(seqDistance>=RECEIVE_WINDOW) { emit(); return }
        val beyondSent=distance(serverNext,p.acknowledgement)
        if(beyondSent in 1L..0x7fffffffL) { emit(); return }
        if(!established && (p.sequence!=clientNext || p.acknowledgement!=serverNext)) { emit(); return }
        val acknowledged=distance(serverAcknowledged,p.acknowledgement)
        if(acknowledged<=distance(serverAcknowledged,serverNext)) {
            val advanced=acknowledged>0
            serverAcknowledged=p.acknowledgement
            while(sent.isNotEmpty() && distance(sent.first().end,p.acknowledgement)<0x80000000L) sent.removeFirst()
            // RFC window update ordering: stale ACKs cannot shrink/reopen a newer window.
            if(distance(windowSequence,p.sequence)<0x80000000L &&
                (p.sequence!=windowSequence || distance(windowAck,p.acknowledgement)<0x80000000L)) {
                peerWindow=p.window; windowSequence=p.sequence; windowAck=p.acknowledgement
            }
            if(advanced) duplicateAcks=0
            else if(p.payload.isEmpty() && sent.isNotEmpty() && ++duplicateAcks==3) {
                val first=sent.first(); if(permitted()) reply(first.bytes); first.at=now()
            }
        }
        established=true; if(!clientFin && !remoteFin) state="ESTABLISHED"; lastActivity=nanoTime()
        if(p.sequence!=clientNext) { emit(); return }
        if(p.payload.isNotEmpty()) {
            if(clientFin || p.payload.size>upload.remaining()) { emit(); return }
            upload.put(p.payload); clientNext=add(clientNext,p.payload.size)
            // Legacy sockets write immediately to preserve the synchronous harness contract.
            if(upstream.channel==null) { if(!authorizeUpload()) { close(); return }; upload.flip(); val b=ByteArray(upload.remaining()); upload.get(b); upstream.getOutputStream().write(b); upload.clear() }
            emit()
        }
        if(p.flags and FIN!=0 && !clientFin) {
            clientFin=true; state="CLIENT_HALF_CLOSED"; clientNext=add(clientNext,1)
            if(upload.position()==0) { shutdownOutput(upstream); outputShutdown=true }
            emit()
        }
    }
    override fun close() {
        if(closed.compareAndSet(false,true)) {
            state="CLOSED"
            selector?.wakeup()
            try { socket?.close() } finally { try { selector?.close() } finally { incoming.clear() } }
        }
    }
}
