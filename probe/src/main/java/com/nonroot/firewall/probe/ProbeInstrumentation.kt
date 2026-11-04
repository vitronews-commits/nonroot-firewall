package com.nonroot.firewall.probe

import android.app.Activity
import android.app.Instrumentation
import android.os.Bundle
import java.net.DatagramPacket
import java.net.DatagramSocket
import java.net.InetSocketAddress
import java.net.Socket
import java.net.SocketTimeoutException

/** Separate UID is essential: a VPN's own UID does not prove packet interception. */
class ProbeInstrumentation : Instrumentation() {
    private var mode="allow"
    private var durationSeconds=0
    private var completed=0L
    @Volatile private var progress=""
    private fun transfer(size: Int) {
        Socket().use { socket ->
            socket.soTimeout=30000; socket.connect(InetSocketAddress("10.0.2.2",28080),5000)
            val error=java.util.concurrent.atomic.AtomicReference<Throwable?>()
            val writer=Thread {
                try {
                    val chunk=ByteArray(16384); var offset=0
                    while(offset<size) { val count=minOf(chunk.size,size-offset); for(i in 0 until count) chunk[i]=((offset+i)*37).toByte(); socket.getOutputStream().write(chunk,0,count); offset+=count; progress="uploaded=$offset/$size" }
                    socket.shutdownOutput()
                } catch(t: Throwable) { error.set(t) }
            }.apply { start() }
            try {
                val chunk=ByteArray(16384); var offset=0
                while(offset<size) { val count=socket.getInputStream().read(chunk,0,minOf(chunk.size,size-offset)); check(count>0) { "Early EOF $offset/$size" }; for(i in 0 until count) check(chunk[i]==((offset+i)*37).toByte()) { "Corruption at ${offset+i}" }; offset+=count; progress="received=$offset/$size" }
                check(socket.getInputStream().read()==-1) { "Missing half-close EOF" }
                writer.join(30000); check(!writer.isAlive); error.get()?.let { throw IllegalStateException("Upload failed",it) }
            } finally { socket.close(); writer.join(2000) }
        }
    }
    private fun dnsTransports() {
        val bytes=java.io.ByteArrayOutputStream()
        val data=java.io.DataOutputStream(bytes)
        data.writeShort(0x4e52); data.writeShort(0x0100); data.writeShort(1)
        repeat(3) { data.writeShort(0) }
        for(label in listOf("firewall-test","invalid")) { data.writeByte(label.length); data.write(label.toByteArray()) }
        data.writeByte(0); data.writeShort(1); data.writeShort(1)
        val query=bytes.toByteArray()
        fun verify(reply: ByteArray) {
            check(reply.size==query.size+16 && reply[0]==query[0] && reply[1]==query[1])
            check(reply[2]==0x81.toByte() && reply[3]==0x80.toByte())
            check(reply.takeLast(4).toByteArray().contentEquals(byteArrayOf(192.toByte(),0,2,123)))
        }
        DatagramSocket().use { socket ->
            socket.soTimeout=5000; socket.connect(InetSocketAddress("10.0.2.2",28082))
            socket.send(DatagramPacket(query,query.size)); val reply=DatagramPacket(ByteArray(512),512)
            socket.receive(reply); verify(reply.data.copyOf(reply.length))
        }
        Socket().use { socket ->
            socket.soTimeout=5000; socket.connect(InetSocketAddress("10.0.2.2",28083),5000)
            val output=java.io.DataOutputStream(socket.getOutputStream()); output.writeShort(query.size); output.write(query)
            val input=java.io.DataInputStream(socket.getInputStream()); val length=input.readUnsignedShort(); check(length<=512)
            val reply=ByteArray(length); input.readFully(reply); verify(reply)
        }
    }
    override fun onCreate(arguments: Bundle?) { mode=arguments?.getString("mode") ?: "allow"; durationSeconds=arguments?.getString("durationSeconds")?.toIntOrNull()?.coerceIn(0,3660) ?: 0; start() }
    private fun permissionDenied(error: Throwable): Boolean {
        var cause: Throwable?=error
        while(cause!=null) {
            if(cause is android.system.ErrnoException &&
                cause.errno in listOf(android.system.OsConstants.EPERM,android.system.OsConstants.EACCES)) return true
            cause=cause.cause
        }
        return false
    }
    override fun onStart() {
        val result=Bundle()
        var stage="initial"
        var received=0
        try {
            val payload=ByteArray(1200) { (it*17).toByte() }
            if(mode=="stress" || mode=="soak") {
                val started=System.nanoTime()
                val cpu=android.os.Process.getElapsedCpuTime()
                val pssBefore=android.os.Debug.getPss()
                if(mode=="stress") {
                    for(size in listOf(1,10,100)) {
                        stage="${size}MiB"; val begin=System.nanoTime(); transfer(size*1024*1024); completed+=size.toLong()*1024*1024
                        sendStatus(0,Bundle().apply { putString("measurement","$stage bytes=${size*1024*1024} elapsedMs=${(System.nanoTime()-begin)/1000000}") })
                    }
                    stage="concurrent"; val errors=java.util.concurrent.ConcurrentLinkedQueue<Throwable>()
                    val threads=(1..4).map { Thread { try { transfer(1024*1024) } catch(t: Throwable) { errors.add(t) } }.apply { start() } }
                    threads.forEach { it.join(120000); check(!it.isAlive) }; check(errors.isEmpty()) { errors.toString() }; completed+=4*1024*1024
                } else {
                    check(durationSeconds>=3600) { "Soak requires at least 60 minutes" }
                    val deadline=System.nanoTime()+java.util.concurrent.TimeUnit.SECONDS.toNanos(durationSeconds.toLong())
                    while(System.nanoTime()<deadline) {
                        stage="soak-transfer"; transfer(65536); completed+=65536
                        DatagramSocket().use { udp -> udp.soTimeout=5000; udp.connect(InetSocketAddress("10.0.2.2",28081)); udp.send(DatagramPacket(payload,payload.size)); val answer=DatagramPacket(ByteArray(1500),1500); udp.receive(answer); check(answer.data.copyOf(answer.length).contentEquals(payload)) }
                        Thread.sleep(5000)
                    }
                }
                result.putString("status","OK")
                result.putString("metrics","mode=$mode bytes=$completed concurrentConnections=${if(mode=="stress") 4 else 1} elapsedMs=${(System.nanoTime()-started)/1000000} cpuMs=${android.os.Process.getElapsedCpuTime()-cpu} pssBeforeKiB=$pssBefore pssAfterKiB=${android.os.Debug.getPss()}")
                finish(Activity.RESULT_OK,result); return
            }
            val tcpPayload=if(mode=="allow") ByteArray(65536) { (it*37).toByte() } else payload
            if(mode=="allow" || mode=="tcp_hold") {
                Socket().use { tcp ->
                    stage="tcp-connect"
                    tcp.soTimeout=15000; tcp.connect(InetSocketAddress("10.0.2.2",28080),5000)
                    stage="tcp-first-echo"
                    tcp.getOutputStream().write(tcpPayload)
                    val bytes=ByteArray(tcpPayload.size)
                    while(received<bytes.size) {
                        val count=tcp.getInputStream().read(bytes,received,bytes.size-received)
                        check(count>=0) { "TCP closed before all echo bytes arrived" }
                        received+=count
                    }
                    check(bytes.contentEquals(tcpPayload)) { "TCP payload mismatch" }
                    if(mode=="tcp_hold") {
                        sendStatus(0,Bundle().apply { putString("phase","READY") })
                        Thread.sleep(1500)
                        stage="tcp-after-revoke"
                        try {
                            tcp.getOutputStream().write(tcpPayload)
                            result.putString("status",if(tcp.getInputStream().read()<0) "BLOCKED" else "ESCAPED")
                        } catch(_: SocketTimeoutException) { result.putString("status","BLOCKED") }
                        catch(_: java.net.SocketException) { result.putString("status","BLOCKED") }
                        catch(e: java.io.IOException) { if(permissionDenied(e)) result.putString("status","BLOCKED") else throw e }
                    }
                }
            }
            if(mode=="allow") { stage="dns-transports"; dnsTransports() }
            if(mode=="allow" || mode=="udp_block") {
                DatagramSocket().use { udp ->
                    udp.soTimeout=3000; udp.connect(InetSocketAddress("10.0.2.2",28081))
                    stage="udp-send"
                    udp.send(DatagramPacket(payload,payload.size))
                    val reply=DatagramPacket(ByteArray(1500),1500)
                    try {
                        stage="udp-receive"
                        udp.receive(reply)
                        check(reply.data.copyOf(reply.length).contentEquals(payload)) { "UDP payload mismatch" }
                        result.putString("status",if(mode=="udp_block") "ESCAPED" else "OK")
                    } catch(e: SocketTimeoutException) {
                        if(mode=="udp_block") result.putString("status","BLOCKED") else throw e
                    }
                }
            }
        } catch(e: Exception) {
            if(mode=="udp_block" && permissionDenied(e)) result.putString("status","BLOCKED")
            else result.putString("status","ERROR mode=$mode stage=$stage received=$received $progress: ${e.javaClass.simpleName}: ${e.message} at ${e.stackTrace.take(4).joinToString()}")
        }
        finish(Activity.RESULT_OK,result)
    }
}
