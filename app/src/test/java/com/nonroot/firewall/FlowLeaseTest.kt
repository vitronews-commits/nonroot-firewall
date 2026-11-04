package com.nonroot.firewall

import org.junit.Assert.*
import org.junit.Test
import java.net.ServerSocket
import java.net.InetAddress
import java.net.DatagramSocket
import java.util.concurrent.LinkedBlockingQueue
import java.util.concurrent.TimeUnit

class FlowLeaseTest {
    @Test fun newSynOnSameTupleRetiresOldWorkerAndItsResponse() {
        ServerSocket(0,2,InetAddress.getByName("127.0.0.1")).use { server ->
            server.soTimeout=3000
            val h=PacketParser.Header("10.23.0.2","127.0.0.1",6,47000,server.localPort,false)
            val replies=LinkedBlockingQueue<ByteArray>()
            val workerThreads=LinkedBlockingQueue<Thread>()
            PacketForwarder({ workerThreads.offer(Thread.currentThread()); SocketProtection.tcp { true } },
                { DatagramSocket(null) },{ true },{ replies.offer(it) }).use { forwarder ->
                assertTrue(forwarder.accept(TransportPacket.build(h,byteArrayOf(),100,0,2)))
                server.accept().use { old ->
                    val oldThread=workerThreads.poll(3,TimeUnit.SECONDS)!!
                    val syn=TransportPacket.parse(replies.poll(3,TimeUnit.SECONDS)!!)!!
                    assertTrue(forwarder.accept(TransportPacket.build(h,byteArrayOf(),101,syn.sequence+1,16)))
                    synchronized(forwarder) {
                        old.getOutputStream().write(byteArrayOf(99))
                        val deadline=System.nanoTime()+TimeUnit.SECONDS.toNanos(3)
                        while(oldThread.state!=Thread.State.BLOCKED && System.nanoTime()<deadline) Thread.sleep(5)
                        assertEquals("Old reply must be blocked at delivery monitor",Thread.State.BLOCKED,oldThread.state)
                        assertTrue(forwarder.accept(TransportPacket.build(h,byteArrayOf(),200,0,2)))
                    }
                    server.accept().use {
                        val fresh=TransportPacket.parse(replies.poll(3,TimeUnit.SECONDS)!!)!!
                        assertEquals(201L,fresh.acknowledgement)
                        assertTrue(fresh.flags and 2!=0)
                        assertTrue(fresh.payload.isEmpty())
                        assertEquals(1,forwarder.activeCount())
                    }
                }
            }
        }
    }
}
