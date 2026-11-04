package com.nonroot.firewall

import org.junit.Assert.*
import org.junit.Test
import java.net.InetAddress
import java.net.ServerSocket
import java.util.concurrent.LinkedBlockingQueue
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicLong

class SuspendClockTest {
    @Test fun elapsedSleepExpiresTcpWithoutWaitingAnotherIdlePeriodAfterWake() {
        val clock=AtomicLong(0)
        ServerSocket(0,1,InetAddress.getByName("127.0.0.1")).use { server ->
            server.soTimeout=3000
            val h=PacketParser.Header("10.23.0.2","127.0.0.1",6,43000,server.localPort,false)
            val replies=LinkedBlockingQueue<ByteArray>()
            val s=TcpProxySession(TransportPacket.Packet(h,byteArrayOf(),100,0,2,16384,1460),
                { SocketProtection.tcp { true } },{ replies.offer(it) },{ true },1000,500,nanoTime={ clock.get() })
            val worker=Thread { s.run() }.apply { start() }
            try {
                server.accept().use { peer ->
                    peer.soTimeout=3000
                    assertNotNull(replies.poll(3,TimeUnit.SECONDS))
                    clock.set(TimeUnit.SECONDS.toNanos(2))
                    s.offer(TransportPacket.Packet(h,byteArrayOf(),101,501,16,16384))
                    worker.join(2000)
                    assertFalse(worker.isAlive); assertTrue(s.isClosed())
                    assertEquals(-1,peer.getInputStream().read())
                }
            } finally { s.close(); worker.join(2000) }
        }
    }
}
