package com.nonroot.firewall

import java.io.Closeable
import java.net.InetSocketAddress
import java.net.Socket
import java.net.SocketTimeoutException
import java.security.SecureRandom
import java.util.concurrent.ArrayBlockingQueue
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicBoolean

/**
 * Bounded stop-and-wait TCP endpoint. No window scaling/SACK negotiation.
 * Out-of-order segments are ACKed and discarded for peer retransmission.
 * One worker owns all TCP state and upstream I/O; queue never blocks TUN.
 * Experimental until Android end-to-end validation passes.
 */
class TcpProxySession(
    private val initial: TransportPacket.Packet,
    private val socketFactory: ()->Socket,
    private val reply: (ByteArray)->Unit,
    private val permitted: ()->Boolean,
    private val idleMs: Long=120_000,
    private val initialSequence: Long=SecureRandom().nextInt().toLong() and MASK,
    private val onError: (Exception)->Unit={}
): Closeable {
    companion object {
        const val FIN=1; const val SYN=2; const val RST=4; const val PSH=8; const val ACK=16
        const val MASK=0xffffffffL
        fun add(sequence: Long, amount: Int)=(sequence+amount) and MASK
    }
    private val closed=AtomicBoolean(false)
    private val incoming=ArrayBlockingQueue<TransportPacket.Packet>(32)
    @Volatile private var socket: Socket?=null
    private var clientNext=add(initial.sequence,1)
    private var serverNext=initialSequence
    private var established=false
    private var clientFin=false
    private var remoteFin=false
    private var peerWindow=initial.window
    private var lastActivity=System.nanoTime()
    private var outstanding: ByteArray?=null
    private var outstandingEnd=0L
    private var sentAt=0L
    private var retries=0
    private val reverse=TransportPacket.reverse(initial.header)

    init { require(initial.flags and 0x3f==SYN && initial.payload.isEmpty()); require(idleMs>=1000) }
    fun offer(packet: TransportPacket.Packet): Boolean = !closed.get() && incoming.offer(packet)
    fun isClosed()=closed.get()
    private fun now()=System.nanoTime()/1_000_000
    private fun emit(payload: ByteArray=byteArrayOf(), flags: Int=ACK, tracked: Boolean=false) {
        if(closed.get() || !permitted()) return
        val bytes=TransportPacket.build(reverse,payload,serverNext,clientNext,flags)
        if(tracked) {
            serverNext=add(serverNext,payload.size+if(flags and (SYN or FIN)!=0) 1 else 0)
            outstanding=bytes; outstandingEnd=serverNext; sentAt=now(); retries=0
        }
        reply(bytes)
    }
    fun run() {
        try {
            if(closed.get() || !permitted()) return
            val upstream=socketFactory()
            socket=upstream
            if(closed.get() || !permitted()) { upstream.close(); return }
            upstream.tcpNoDelay=true
            upstream.sendBufferSize=16384
            upstream.connect(InetSocketAddress(initial.header.destination,initial.header.destinationPort!!),5000)
            upstream.soTimeout=50
            emit(flags=SYN or ACK,tracked=true)
            val buffer=ByteArray(536)
            while(!closed.get() && permitted()) {
                if((System.nanoTime()-lastActivity)/1_000_000>=idleMs) break
                repeat(32) { incoming.poll()?.let { process(it,upstream) } }
                if(closed.get()) break
                if(outstanding!=null) {
                    if(now()-sentAt>=1000L shl retries.coerceAtMost(3)) {
                        if(++retries>5) break
                        if(permitted()) reply(outstanding!!)
                        sentAt=now()
                    }
                    // Wake immediately for an ACK, otherwise sleep until the next timer check.
                    // A busy loop here burns CPU and floods Android UID lookups.
                    incoming.poll(50,TimeUnit.MILLISECONDS)?.let { process(it,upstream) }
                } else if(established && !remoteFin && peerWindow>0) {
                    val count=try { upstream.getInputStream().read(buffer,0,minOf(buffer.size,peerWindow)) }
                        catch(_: SocketTimeoutException) { 0 }
                    if(count<0) { remoteFin=true; emit(flags=FIN or ACK,tracked=true) }
                    else if(count>0) { lastActivity=System.nanoTime(); emit(buffer.copyOf(count),ACK or PSH,true) }
                } else Thread.sleep(10)
                if(clientFin && remoteFin && outstanding==null) break
            }
        } catch(e: Exception) {
            if(!closed.get()) onError(e)
            try { emit(flags=RST or ACK) } catch(_: Exception) { }
        } finally { close() }
    }
    private fun process(p: TransportPacket.Packet, upstream: Socket) {
        if(!permitted() || closed.get()) return
        if(p.flags and RST!=0) { close(); return }
        if(p.flags and SYN!=0) {
            if(p.sequence==initial.sequence && outstanding!=null && !established) reply(outstanding!!)
            return
        }
        if(p.flags and ACK==0) return
        // Only a valid next sequence can update the peer window/ack state.
        if(p.sequence!=clientNext) { emit(); return }
        if(p.acknowledgement!=serverNext) { emit(); return }
        peerWindow=p.window
        if(outstanding!=null && p.acknowledgement==outstandingEnd) outstanding=null
        established=true
        lastActivity=System.nanoTime()
        if(p.payload.isNotEmpty()) {
            if(clientFin) { emit(); return }
            upstream.getOutputStream().write(p.payload)
            clientNext=add(clientNext,p.payload.size)
            emit()
        }
        if(p.flags and FIN!=0 && !clientFin) {
            clientFin=true; clientNext=add(clientNext,1)
            upstream.shutdownOutput(); emit()
        }
    }
    override fun close() {
        if(closed.compareAndSet(false,true)) { socket?.close(); incoming.clear() }
    }
}
