package com.nonroot.firewall

import java.net.DatagramPacket
import java.net.DatagramSocket
import java.net.InetAddress
import java.net.ServerSocket
import java.net.Socket
import java.util.concurrent.LinkedBlockingQueue
import java.util.concurrent.TimeUnit

/** Runs real loopback exchanges through the packet forwarder BEFORE TUN establishment. */
object EngineSelfTest {
    fun verify(tcp: ()->Socket, udp: ()->DatagramSocket) {
        val loop=InetAddress.getByName("127.0.0.1")
        val payload="firewall-preflight".toByteArray()
        val replies=LinkedBlockingQueue<ByteArray>()
        val errors=java.util.concurrent.ConcurrentLinkedQueue<Exception>()
        PacketForwarder(tcp,udp,{ true },{ replies.offer(it) },4,{ errors.offer(it) }).use { engine ->
            DatagramSocket(0,loop).use { server ->
                server.soTimeout=3000
                val h=PacketParser.Header("10.23.0.2","127.0.0.1",17,43001,server.localPort,false)
                check(engine.accept(TransportPacket.build(h,payload)))
                val request=DatagramPacket(ByteArray(256),256)
                try { server.receive(request) } catch(e: Exception) {
                    val failure=errors.peek()
                    throw IllegalStateException("UDP preflight receive: " + (failure?.let { it.javaClass.simpleName+": "+it.message } ?: e.message),failure ?: e)
                }
                check(request.data.copyOf(request.length).contentEquals(payload))
                server.send(DatagramPacket(payload,payload.size,request.socketAddress))
                val reply=TransportPacket.parse(checkNotNull(replies.poll(3,TimeUnit.SECONDS)))!!
                check(reply.header==TransportPacket.reverse(h) && reply.payload.contentEquals(payload))
            }
            ServerSocket(0,1,loop).use { server ->
                server.soTimeout=3000
                val h=PacketParser.Header("10.23.0.2","127.0.0.1",6,43002,server.localPort,false)
                check(engine.accept(TransportPacket.build(h,byteArrayOf(),100,0,TcpProxySession.SYN,maximumSegmentSize=1460)))
                val peer=try { server.accept() } catch(e: Exception) {
                    val failure=errors.peek()
                    throw IllegalStateException("TCP preflight accept: " + (failure?.let { it.javaClass.simpleName+": "+it.message } ?: e.message),failure ?: e)
                }
                peer.use { accepted ->
                    accepted.soTimeout=3000
                    val syn=TransportPacket.parse(checkNotNull(replies.poll(3,TimeUnit.SECONDS)))!!
                    check(syn.flags==18 && syn.acknowledgement==101L && syn.header==TransportPacket.reverse(h) && syn.maximumSegmentSize==1460)
                    val serverSeq=TcpProxySession.add(syn.sequence,1)
                    check(engine.accept(TransportPacket.build(h,payload,101,serverSeq,24)))
                    val bytes=ByteArray(payload.size)
                    java.io.DataInputStream(accepted.getInputStream()).readFully(bytes)
                    check(bytes.contentEquals(payload))
                    accepted.getOutputStream().write(bytes)
                    var reply: TransportPacket.Packet?=null
                    val deadline=System.nanoTime()+TimeUnit.SECONDS.toNanos(4)
                    while(System.nanoTime()<deadline) {
                        val b=replies.poll(200,TimeUnit.MILLISECONDS) ?: continue
                        val p=TransportPacket.parse(b) ?: error("Invalid reply checksum")
                        if(p.payload.isNotEmpty()) { reply=p; break }
                    }
                    check(reply?.payload?.contentEquals(payload)==true)
                    check(reply!!.acknowledgement==101L+payload.size)
                    check(engine.accept(TransportPacket.build(h,byteArrayOf(),101L+payload.size,
                        TcpProxySession.add(reply.sequence,payload.size),16)))
                }
            }
        }
    }
}
