package com.nonroot.firewall

import org.junit.Assert.*
import org.junit.Test
import java.net.InetAddress
import java.net.ServerSocket
import java.nio.channels.SocketChannel
import java.util.concurrent.LinkedBlockingQueue
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicReference

class TcpLoadTest {
    private fun transfer(size: Int) {
        val begin=System.nanoTime()
        val bean=Class.forName("java.lang.management.ManagementFactory").getMethod("getOperatingSystemMXBean").invoke(null)
        val cpuMethod=Class.forName("com.sun.management.OperatingSystemMXBean").getMethod("getProcessCpuTime")
        fun cpu()=cpuMethod.invoke(bean) as Long
        val cpuBefore=cpu()
        val runtime=Runtime.getRuntime(); val heapBefore=runtime.totalMemory()-runtime.freeMemory()
        val failure=AtomicReference<Throwable?>()
        ServerSocket(0,4,InetAddress.getByName("127.0.0.1")).use { server ->
            server.soTimeout=10000
            val echo=Thread {
                try { server.accept().use { peer ->
                    peer.soTimeout=30000
                    val b=ByteArray(16384)
                    while(true) { val n=peer.getInputStream().read(b); if(n<0) break; peer.getOutputStream().write(b,0,n) }
                    peer.shutdownOutput()
                } } catch(t: Throwable) { failure.set(t) }
            }.apply { start() }
            val h=PacketParser.Header("10.23.0.2","127.0.0.1",6,48000,server.localPort,false)
            val q=LinkedBlockingQueue<ByteArray>(1024)
            val s=TcpProxySession(TransportPacket.Packet(h,byteArrayOf(),100,0,2,65535,1460),
                { SocketChannel.open().socket() },{ check(q.offer(it)) },{ true },30000,500,{ failure.set(it) })
            val worker=Thread { s.run() }.apply { start() }
            try {
                val syn=TransportPacket.parse(checkNotNull(q.poll(10,TimeUnit.SECONDS)))!!
                var downSeq=syn.sequence+1; var upload=0; var received=0; var acknowledged=101L; var window=syn.window; var uploadFin=false; var remoteFin=false
                val deadline=System.nanoTime()+TimeUnit.SECONDS.toNanos(120)
                fun send(p: TransportPacket.Packet) { while(!s.offer(p)) { check(!s.isClosed()); Thread.yield() } }
                send(TransportPacket.Packet(h,byteArrayOf(),101,downSeq,16,65535))
                while(!remoteFin) {
                    check(System.nanoTime()<deadline) { "Transfer timed out upload=$upload received=$received ack=$acknowledged window=$window failure=${failure.get()}" }
                    var budget=16
                    while(upload<size && budget-->0 && 101L+upload-acknowledged<window) {
                        val n=minOf(1460,size-upload,(window-(101L+upload-acknowledged)).toInt())
                        if(n<=0) break
                        val b=ByteArray(n) { ((upload+it)*37).toByte() }
                        send(TransportPacket.Packet(h,b,101L+upload,downSeq,24,65535)); upload+=n
                    }
                    if(upload==size && !uploadFin) { send(TransportPacket.Packet(h,byteArrayOf(),101L+upload,downSeq,17,65535)); uploadFin=true }
                    val raw=q.poll(1,TimeUnit.SECONDS) ?: continue
                    val p=checkNotNull(TransportPacket.parse(raw))
                    if(p.acknowledgement>=acknowledged) { acknowledged=p.acknowledgement; window=p.window }
                    if(p.payload.isNotEmpty()) {
                        assertEquals(downSeq,p.sequence)
                        for(i in p.payload.indices) assertEquals(((received+i)*37).toByte(),p.payload[i])
                        received+=p.payload.size; downSeq=TcpProxySession.add(downSeq,p.payload.size)
                        send(TransportPacket.Packet(h,byteArrayOf(),101L+upload+if(uploadFin) 1 else 0,downSeq,16,65535))
                    }
                    if(p.flags and 1!=0) { downSeq=TcpProxySession.add(downSeq,1); send(TransportPacket.Packet(h,byteArrayOf(),101L+upload+1,downSeq,16,65535)); remoteFin=true }
                }
                assertEquals(size,received)
                echo.join(3000); assertFalse(echo.isAlive); assertNull(failure.get())
                println("JVM_TCP bytes=$size elapsedMs=${(System.nanoTime()-begin)/1000000} processCpuMs=${(cpu()-cpuBefore)/1000000} heapBeforeBytes=$heapBefore heapAfterBytes=${runtime.totalMemory()-runtime.freeMemory()}")
            } finally { s.close(); worker.join(3000); echo.join(3000); assertFalse(worker.isAlive) }
        }
    }
    @Test fun oneMiB()=transfer(1024*1024)
    @Test fun tenMiB()=transfer(10*1024*1024)
    @Test fun hundredMiB()=transfer(100*1024*1024)
    @Test fun fourConcurrentMiB() {
        val failure=AtomicReference<Throwable?>()
        val workers=(1..4).map { Thread { try { transfer(1024*1024) } catch(t: Throwable) { failure.set(t) } }.apply { start() } }
        workers.forEach { it.join(130000); assertFalse(it.isAlive) }; failure.get()?.let { throw AssertionError(it) }
    }
}
