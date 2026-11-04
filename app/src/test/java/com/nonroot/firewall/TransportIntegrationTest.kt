package com.nonroot.firewall

import org.junit.Assert.*
import org.junit.Test
import java.net.DatagramSocket
import java.net.Socket
import java.net.DatagramPacket
import java.net.InetAddress
import java.util.concurrent.LinkedBlockingQueue
import java.util.concurrent.TimeUnit

class TransportIntegrationTest {
    private fun header(protocol: Int=17, ipv6: Boolean=false)=PacketParser.Header(
        if(ipv6) "fd23:23:0:0:0:0:0:2" else "10.23.0.2",
        if(ipv6) "0:0:0:0:0:0:0:1" else "127.0.0.1",protocol,43210,53,false)

    @Test fun realTcpAndUdpRoundTripsBeforeTun() {
        EngineSelfTest.verify({ Socket() },{ DatagramSocket(null) })
    }
    @Test fun codecBothFamiliesAndProtocolsWithOddPayloads() {
        for(v6 in listOf(false,true)) for(protocol in listOf(6,17)) {
            val h=header(protocol,v6)
            val payload=byteArrayOf(1,2,3,4,5)
            val raw=TransportPacket.build(h,payload,0xfffffff0,42,24)
            val parsed=TransportPacket.parse(raw)!!
            assertEquals(h,parsed.header); assertArrayEquals(payload,parsed.payload)
            if(protocol==6) { assertEquals(0xfffffff0,parsed.sequence); assertEquals(42L,parsed.acknowledgement) }
            raw[raw.lastIndex]=(raw.last().toInt() xor 1).toByte()
            assertNull(TransportPacket.parse(raw))
        }
    }
    @Test fun rejectsMalformedLengthsExtensionsFragmentsAndZeroV6Checksum() {
        val b=TransportPacket.build(header(),byteArrayOf(1))
        assertNull(TransportPacket.parse(b.copyOf(b.size-1)))
        assertNull(TransportPacket.parse(b+byteArrayOf(0)))
        val fragment=b.copyOf(); fragment[6]=0x20
        assertNull(TransportPacket.parse(fragment))
        val v6=TransportPacket.build(header(ipv6=true),byteArrayOf(1))
        v6[46]=0; v6[47]=0
        assertNull(TransportPacket.parse(v6))
        v6[6]=0
        assertNull(TransportPacket.parse(v6))
    }
    @Test fun malformedAndDeniedConnectionsNeverAllocateSockets() {
        var opens=0
        PacketForwarder({ opens++; Socket() },{ opens++; DatagramSocket(null) },{ false },{}).use { engine ->
            assertFalse(engine.accept(TransportPacket.build(header(),byteArrayOf(1))))
            assertFalse(engine.accept(byteArrayOf(1)))
            assertEquals(0,engine.activeCount()); assertEquals(0,opens)
        }
    }
    @Test fun protectionFailureClosesSocketsBeforeBindOrConnect() {
        var tcp: Socket?=null
        try { SocketProtection.tcp { tcp=it; assertTrue(it.isBound); assertFalse(it.isConnected); false }; fail() } catch(_: IllegalStateException) {}
        assertTrue(tcp!!.isClosed)
        var udp: DatagramSocket?=null
        try { SocketProtection.udp { udp=it; assertFalse(it.isBound); false }; fail() } catch(_: IllegalStateException) {}
        assertTrue(udp!!.isClosed)
        try { SocketProtection.tcp { tcp=it; error("protection error") }; fail() } catch(_: IllegalStateException) {}
        assertTrue(tcp!!.isClosed)
    }
    @Test fun ruleInvalidationPreventsLateUdpReplies() {
        val replies=LinkedBlockingQueue<ByteArray>()
        DatagramSocket(0,InetAddress.getByName("127.0.0.1")).use { server ->
            server.soTimeout=3000
            PacketForwarder({ Socket() },{ DatagramSocket(null) },{ true },{ replies.offer(it) }).use { engine ->
                val h=header().copy(destinationPort=server.localPort)
                assertTrue(engine.accept(TransportPacket.build(h,byteArrayOf(7))))
                val request=DatagramPacket(ByteArray(16),16); server.receive(request)
                engine.invalidate()
                server.send(DatagramPacket(byteArrayOf(8),1,request.socketAddress))
                assertNull(replies.poll(250,TimeUnit.MILLISECONDS))
                assertEquals(0,engine.activeCount())
            }
        }
    }
    @Test fun ipv6UdpActualLoopbackRoundTrip() {
        val queue=LinkedBlockingQueue<ByteArray>()
        DatagramSocket(0,InetAddress.getByName("::1")).use { server ->
            server.soTimeout=3000
            PacketForwarder({ Socket() },{ DatagramSocket(null) },{ true },{ queue.offer(it) }).use { engine ->
                val h=header(ipv6=true).copy(destinationPort=server.localPort)
                assertTrue(engine.accept(TransportPacket.build(h,byteArrayOf(3,1,4))))
                val request=DatagramPacket(ByteArray(16),16); server.receive(request)
                server.send(DatagramPacket(request.data,request.length,request.socketAddress))
                val reply=TransportPacket.parse(queue.poll(3,TimeUnit.SECONDS)!!)!!
                assertEquals(TransportPacket.reverse(h),reply.header)
                assertArrayEquals(byteArrayOf(3,1,4),reply.payload)
            }
        }
    }
    @Test fun permissionRevocationDropsReplyWithoutAnInvalidationEvent() {
        val permitted=java.util.concurrent.atomic.AtomicBoolean(true)
        val replies=LinkedBlockingQueue<ByteArray>()
        DatagramSocket(0,InetAddress.getByName("127.0.0.1")).use { server ->
            server.soTimeout=3000
            PacketForwarder({ Socket() },{ DatagramSocket(null) },{ permitted.get() },{ replies.offer(it) }).use { engine ->
                val h=header().copy(destinationPort=server.localPort)
                assertTrue(engine.accept(TransportPacket.build(h,byteArrayOf(1))))
                val request=DatagramPacket(ByteArray(16),16); server.receive(request)
                permitted.set(false)
                server.send(DatagramPacket(byteArrayOf(2),1,request.socketAddress))
                assertNull(replies.poll(250,TimeUnit.MILLISECONDS))
                val deadline=System.nanoTime()+TimeUnit.SECONDS.toNanos(1)
                while(engine.activeCount()>0 && System.nanoTime()<deadline) Thread.sleep(10)
                assertEquals(0,engine.activeCount())
            }
        }
    }
    @Test fun ipv6TcpPreservesMultiSegmentResponseBytes() {
        val queue=LinkedBlockingQueue<ByteArray>()
        java.net.ServerSocket(0,1,InetAddress.getByName("::1")).use { server ->
            server.soTimeout=3000
            PacketForwarder({ Socket() },{ DatagramSocket(null) },{ true },{ queue.offer(it) }).use { engine ->
                val h=header(6,true).copy(destinationPort=server.localPort)
                assertTrue(engine.accept(TransportPacket.build(h,byteArrayOf(),100,0,2)))
                server.accept().use { peer ->
                    val syn=TransportPacket.parse(queue.poll(3,TimeUnit.SECONDS)!!)!!
                    var expected=TcpProxySession.add(syn.sequence,1)
                    assertTrue(engine.accept(TransportPacket.build(h,byteArrayOf(),101,expected,16)))
                    val data=ByteArray(4096) { (it*37).toByte() }
                    peer.getOutputStream().write(data)
                    val received=java.io.ByteArrayOutputStream()
                    while(received.size()<data.size) {
                        val reply=TransportPacket.parse(queue.poll(3,TimeUnit.SECONDS)!!)!!
                        assertEquals(TransportPacket.reverse(h),reply.header)
                        assertEquals(expected,reply.sequence)
                        assertTrue(reply.payload.isNotEmpty())
                        received.write(reply.payload)
                        expected=TcpProxySession.add(expected,reply.payload.size)
                        assertTrue(engine.accept(TransportPacket.build(h,byteArrayOf(),101,expected,16)))
                    }
                    assertArrayEquals(data,received.toByteArray())
                }
            }
        }
    }
    @Test fun sequenceArithmeticWraps() { assertEquals(0L,TcpProxySession.add(0xffffffffL,1)) }
}
