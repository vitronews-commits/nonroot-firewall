package com.nonroot.firewall

import org.junit.Assert.*
import org.junit.Test
import java.io.Closeable
import java.net.InetAddress
import java.net.ServerSocket
import java.net.Socket
import java.net.SocketTimeoutException
import java.util.concurrent.LinkedBlockingQueue
import java.util.concurrent.TimeUnit

class TcpProxySessionTest {
    private class Fixture : Closeable {
        val server=ServerSocket(0,1,InetAddress.getByName("127.0.0.1")).apply { soTimeout=3000 }
        val header=PacketParser.Header("10.23.0.2","127.0.0.1",6,40000,server.localPort,false)
        val replies=LinkedBlockingQueue<ByteArray>()
        val initial=TransportPacket.Packet(header,byteArrayOf(),100,0,2,16384)
        val session=TcpProxySession(initial,{ Socket() },{ replies.offer(it) },{ true },3000,500)
        val thread=Thread { session.run() }.apply { start() }
        val peer=server.accept().apply { soTimeout=1000 }
        val syn=next()
        fun next(): TransportPacket.Packet=TransportPacket.parse(checkNotNull(replies.poll(3,TimeUnit.SECONDS)))!!
        fun send(seq: Long, ack: Long, flags: Int=16, payload: ByteArray=byteArrayOf(),window: Int=16384) {
            check(session.offer(TransportPacket.Packet(header,payload,seq,ack,flags,window)))
        }
        fun handshake() { send(101,501) }
        override fun close() { session.close(); peer.close(); server.close(); thread.join(2000); assertFalse(thread.isAlive) }
    }
    @Test fun duplicateClientDataIsNotWrittenTwice() {
        Fixture().use { f ->
            f.handshake(); f.send(101,501,24,byteArrayOf(7,8,9))
            assertEquals(7,f.peer.getInputStream().read()); assertEquals(8,f.peer.getInputStream().read()); assertEquals(9,f.peer.getInputStream().read())
            assertEquals(104L,f.next().acknowledgement)
            f.send(101,501,24,byteArrayOf(7,8,9))
            assertEquals(104L,f.next().acknowledgement)
            try { f.peer.getInputStream().read(); fail("duplicate bytes reached upstream") } catch(_: SocketTimeoutException) {}
        }
    }
    @Test fun outOfOrderClientDataIsDroppedUntilRetransmitted() {
        Fixture().use { f ->
            f.handshake(); f.send(110,501,24,byteArrayOf(9))
            assertEquals(101L,f.next().acknowledgement)
            f.send(101,501,24,byteArrayOf(8))
            assertEquals(8,f.peer.getInputStream().read())
        }
    }
    @Test fun unacknowledgedServerPayloadIsRetransmittedExactly() {
        Fixture().use { f ->
            f.handshake(); f.peer.getOutputStream().write(byteArrayOf(1,2))
            val first=f.next(); val retry=f.next()
            assertEquals(first.sequence,retry.sequence)
            assertArrayEquals(first.payload,retry.payload)
            assertEquals(501L,first.sequence)
            f.send(101,503)
        }
    }
    @Test fun clientHalfCloseAllowsRemoteResponseAndFin() {
        Fixture().use { f ->
            f.handshake(); f.send(101,501,17)
            assertEquals(-1,f.peer.getInputStream().read())
            assertEquals(102L,f.next().acknowledgement)
            f.peer.getOutputStream().write(byteArrayOf(42))
            val reply=f.next(); assertArrayEquals(byteArrayOf(42),reply.payload)
            f.send(102,502)
            f.peer.shutdownOutput()
            val fin=f.next(); assertEquals(17,fin.flags)
            f.send(102,503)
            f.thread.join(2000); assertTrue(f.session.isClosed())
        }
    }
    @Test fun resetClosesUpstreamAndWorker() {
        Fixture().use { f ->
            f.send(101,501,4)
            f.thread.join(2000)
            assertTrue(f.session.isClosed()); assertEquals(-1,f.peer.getInputStream().read())
        }
    }
    @Test fun waitingForAcknowledgementDoesNotBusySpin() {
        val checks=java.util.concurrent.atomic.AtomicInteger()
        val replies=LinkedBlockingQueue<ByteArray>()
        ServerSocket(0,1,InetAddress.getByName("127.0.0.1")).use { server ->
            server.soTimeout=3000
            val h=PacketParser.Header("10.23.0.2","127.0.0.1",6,41000,server.localPort,false)
            val first=TransportPacket.Packet(h,byteArrayOf(),100,0,2,16384)
            val session=TcpProxySession(first,{ Socket() },{ replies.offer(it) },{ checks.incrementAndGet(); true })
            val worker=Thread { session.run() }.apply { start() }
            try {
                server.accept().use {
                    assertNotNull(replies.poll(3,TimeUnit.SECONDS))
                    Thread.sleep(250)
                    assertTrue("ACK wait busy-spun: ${checks.get()} policy lookups",checks.get()<100)
                }
            } finally { session.close(); worker.join(2000); assertFalse(worker.isAlive) }
        }
    }
    @Test fun sequenceWrapIsHandledDuringHandshake() {
        assertEquals(1L,TcpProxySession.add(0xffffffffL,2))
    }
}
