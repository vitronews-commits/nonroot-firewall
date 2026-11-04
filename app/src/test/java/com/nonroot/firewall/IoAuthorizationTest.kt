package com.nonroot.firewall

import org.junit.Assert.*
import org.junit.Test
import java.net.DatagramPacket
import java.net.DatagramSocket
import java.net.InetAddress
import java.util.concurrent.LinkedBlockingQueue
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicInteger

class IoAuthorizationTest {
    @Test fun cheapAdmissionCannotBypassFreshIoAuthorization() {
        val opens=AtomicInteger()
        PacketForwarder({ opens.incrementAndGet(); java.net.Socket() },{ opens.incrementAndGet(); DatagramSocket(null) },{ true },{},authorizeIo={ false }).use { engine ->
            for(protocol in listOf(6,17)) {
                val h=PacketParser.Header("10.23.0.2","192.0.2.4",protocol,43210,443,false)
                assertTrue(engine.accept(TransportPacket.build(h,byteArrayOf(),100,0,if(protocol==6) 2 else 0)))
            }
            val deadline=System.nanoTime()+TimeUnit.SECONDS.toNanos(2)
            while(engine.activeCount()>0 && System.nanoTime()<deadline) Thread.sleep(5)
            assertEquals(0,opens.get()); assertEquals(0,engine.activeCount())
        }
    }
    @Test fun nioUdpPreservesEmptyAndQuicSizedDatagramsAndCounters() { for(v6 in listOf(false,true)) checkUdp(v6) }
    private fun checkUdp(v6: Boolean) {
        val replies=LinkedBlockingQueue<ByteArray>()
        val errors=java.util.concurrent.ConcurrentLinkedQueue<Exception>()
        DatagramSocket(0,InetAddress.getByName(if(v6) "::1" else "127.0.0.1")).use { server ->
            server.soTimeout=3000
            PacketForwarder({ SocketProtection.tcp { true } },{ SocketProtection.udp { true } },{ true },{ replies.offer(it) },onError={ errors.add(it) }).use { f ->
                val h=PacketParser.Header(if(v6) "fd23::2" else "10.23.0.2",if(v6) "::1" else "127.0.0.1",17,43210,server.localPort,false)
                for(size in listOf(0,1200,if(v6) 1452 else 1472)) {
                    val b=ByteArray(size) { it.toByte() }; val raw=TransportPacket.build(h,b)
                    assertTrue(f.accept(raw))
                    val request=DatagramPacket(ByteArray(1500),1500); try { server.receive(request) } catch(e: Exception) { throw AssertionError("size=$size active=${f.activeCount()} errors=$errors",e) }
                    assertArrayEquals(b,request.data.copyOf(request.length))
                    DatagramSocket().use { attacker ->
                        attacker.send(DatagramPacket(byteArrayOf(9),1,request.socketAddress))
                        assertNull("Unrelated UDP sender bypassed destination filter",replies.poll(100,TimeUnit.MILLISECONDS))
                    }
                    server.send(DatagramPacket(b,b.size,request.socketAddress))
                    val reply=checkNotNull(replies.poll(3,TimeUnit.SECONDS))
                    assertArrayEquals(b,TransportPacket.parse(reply)!!.payload)
                }
                val snapshot=f.snapshot().single()
                assertEquals(((if(v6) 48 else 28)*3+1200+(if(v6) 1452 else 1472)).toLong(),snapshot.tunInputBytes)
                assertEquals(snapshot.tunInputBytes,snapshot.tunOutputBytes)
            }
        }
    }
    @Test fun transportFailureRetainsItsProtocolAndDestination() {
        val errors=LinkedBlockingQueue<PacketParser.Header>()
        val h=PacketParser.Header("10.23.0.2","192.0.2.4",6,43210,443,false)
        PacketForwarder({ throw java.io.IOException("test connect failure") },{ DatagramSocket(null) },{ true },{},
            onFlowError={ header,_ -> errors.offer(header) }).use { engine ->
            assertTrue(engine.accept(TransportPacket.build(h,byteArrayOf(),100,0,2)))
            assertEquals(h,errors.poll(3,TimeUnit.SECONDS))
        }
    }

}
