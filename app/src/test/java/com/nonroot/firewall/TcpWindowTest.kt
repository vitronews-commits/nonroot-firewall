package com.nonroot.firewall

import org.junit.Assert.*
import org.junit.Test
import java.net.InetAddress
import java.net.ServerSocket
import java.nio.channels.SocketChannel
import java.util.concurrent.LinkedBlockingQueue
import java.util.concurrent.TimeUnit

class TcpWindowTest {
    private fun windowTest(block: (TcpProxySession,java.net.Socket,LinkedBlockingQueue<ByteArray>,PacketParser.Header,Long)->Unit) {
        ServerSocket(0,1,InetAddress.getByName("127.0.0.1")).use { server ->
            server.soTimeout=3000
            val h=PacketParser.Header("10.23.0.2","127.0.0.1",6,49000,server.localPort,false)
            val q=LinkedBlockingQueue<ByteArray>()
            val session=TcpProxySession(TransportPacket.Packet(h,byteArrayOf(),100,0,2,16384,1460),
                { SocketChannel.open().socket() },{ q.offer(it) },{ true },10000,500)
            val worker=Thread { session.run() }.apply { start() }
            try { server.accept().use { peer ->
                peer.soTimeout=3000
                val syn=TransportPacket.parse(q.poll(3,TimeUnit.SECONDS)!!)!!
                assertTrue(session.offer(TransportPacket.Packet(h,byteArrayOf(),101,501,16,16384)))
                block(session,peer,q,h,syn.sequence+1)
            } } finally { session.close(); worker.join(2000); assertFalse(worker.isAlive) }
        }
    }
    private fun next(q: LinkedBlockingQueue<ByteArray>)=TransportPacket.parse(checkNotNull(q.poll(3,TimeUnit.SECONDS)))!!
    @Test fun multipleSegmentsAreSentBeforeAcknowledgement()=windowTest { s,peer,q,h,start ->
        peer.getOutputStream().write(ByteArray(4096) { it.toByte() })
        var bytes=0; var seq=start
        while(bytes<4096) { val p=next(q); assertEquals(seq,p.sequence); assertTrue(p.payload.isNotEmpty()); bytes+=p.payload.size; seq=TcpProxySession.add(seq,p.payload.size) }
        assertTrue(s.offer(TransportPacket.Packet(h,byteArrayOf(),101,seq,16,16384)))
        assertNull("Cumulative ACK did not retire all retransmission records",q.poll(1300,TimeUnit.MILLISECONDS))
    }
    @Test fun invalidResetCannotTerminateEstablishedFlow()=windowTest { s,peer,q,h,start ->
        assertTrue(s.offer(TransportPacket.Packet(h,byteArrayOf(),102,start,4,16384)))
        assertEquals(101L,next(q).acknowledgement)
        assertFalse(s.isClosed())
        peer.getOutputStream().write(byteArrayOf(9))
        assertArrayEquals(byteArrayOf(9),next(q).payload)
        s.offer(TransportPacket.Packet(h,byteArrayOf(),101,start,4,16384))
        val end=System.nanoTime()+TimeUnit.SECONDS.toNanos(2)
        while(!s.isClosed() && System.nanoTime()<end) Thread.sleep(5)
        assertTrue(s.isClosed())
    }
    @Test fun zeroWindowIsProbedAndCanReopen()=windowTest { s,peer,q,h,start ->
        s.offer(TransportPacket.Packet(h,byteArrayOf(),101,start,16,0))
        peer.getOutputStream().write(byteArrayOf(7,8))
        val probe=next(q)
        assertEquals(TcpProxySession.add(start,-1),probe.sequence)
        assertTrue(probe.payload.isEmpty())
        s.offer(TransportPacket.Packet(h,byteArrayOf(),101,start,16,16384))
        assertArrayEquals(byteArrayOf(7,8),next(q).payload)
    }
    @Test fun partialAckRetainsUnacknowledgedSuffix()=windowTest { s,peer,q,h,start ->
        peer.getOutputStream().write(byteArrayOf(1,2,3,4))
        val first=next(q)
        s.offer(TransportPacket.Packet(h,byteArrayOf(),101,start+2,16,16384))
        val retry=next(q)
        assertEquals(first.sequence,retry.sequence)
        assertArrayEquals(first.payload,retry.payload)
        s.offer(TransportPacket.Packet(h,byteArrayOf(),101,start+4,16,16384))
        peer.getOutputStream().write(byteArrayOf(5))
        assertEquals(start+4,next(q).sequence)
    }
}
