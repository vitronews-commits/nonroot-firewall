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
    private fun allowedMode()=mode in listOf("allow","allow_mobile")
    private var durationSeconds=0
    private var token=""
    private var completed=0L
    @Volatile private var progress=""
    private fun transfer(size: Int) {
        if(mode=="direct_channel") { directChannelTransfer(size); return }
        val connection=Socket()
        connection.use { socket ->
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
                if(mode!="stress_payload") check(socket.getInputStream().read()==-1) { "Missing half-close EOF" }
                writer.join(30000); check(!writer.isAlive); error.get()?.let { throw IllegalStateException("Upload failed",it) }
            } finally { socket.close(); writer.join(2000) }
        }
    }
    private fun directChannelTransfer(size: Int) {
        java.nio.channels.SocketChannel.open().use { channel ->
            channel.socket().bind(InetSocketAddress(0))
            targetContext.getSystemService(android.net.ConnectivityManager::class.java).activeNetwork?.bindSocket(channel.socket())
            channel.socket().connect(InetSocketAddress("10.0.2.2",28080),5000)
            channel.configureBlocking(false)
            java.nio.channels.Selector.open().use { selected ->
                val key=channel.register(selected,java.nio.channels.SelectionKey.OP_READ or java.nio.channels.SelectionKey.OP_WRITE)
                val up=java.nio.ByteBuffer.allocate(16384).apply { limit(0) }
                val down=java.nio.ByteBuffer.allocate(16384)
                var written=0; var read=0; var fin=false
                val deadline=android.os.SystemClock.elapsedRealtimeNanos()+java.util.concurrent.TimeUnit.SECONDS.toNanos(60)
                while(true) {
                    check(android.os.SystemClock.elapsedRealtimeNanos()<deadline) { "NIO direct deadline written=$written read=$read" }
                    var progress=false
                    if(written<size) {
                        if(!up.hasRemaining()) {
                            up.clear(); val count=minOf(up.capacity(),size-written)
                            for(i in 0 until count) up.put(((written+i)*37).toByte())
                            up.flip()
                        }
                        val n=channel.write(up); written+=n; progress=n>0
                    }
                    if(written==size && !fin) { channel.shutdownOutput(); fin=true }
                    down.clear()
                    val n=channel.read(down)
                    if(n<0) { check(read==size) { "NIO direct early EOF $read/$size" }; break }
                    if(n>0) {
                        down.flip()
                        repeat(n) { check(down.get()==((read+it)*37).toByte()) }
                        read+=n; progress=true; this.progress="received="+read.toString()+"/"+size.toString()
                    }
                    if(!progress) {
                        key.interestOps(java.nio.channels.SelectionKey.OP_READ or if(written<size) java.nio.channels.SelectionKey.OP_WRITE else 0)
                        selected.select(1000); selected.selectedKeys().clear()
                    }
                }
            }
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
    override fun onCreate(arguments: Bundle?) { token=arguments?.getString("token").orEmpty(); mode=arguments?.getString("mode") ?: "allow"; durationSeconds=arguments?.getString("durationSeconds")?.toIntOrNull()?.coerceIn(0,3660) ?: 0; start() }
    private fun permissionDenied(error: Throwable): Boolean {
        var cause: Throwable?=error
        while(cause!=null) {
            if(cause is android.system.ErrnoException &&
                cause.errno in listOf(android.system.OsConstants.EPERM,android.system.OsConstants.EACCES)) return true
            cause=cause.cause
        }
        return false
    }
    /** Instrumentation force-stops/restarts this UID. Wait for Android's blocked-UID
     * callback before DNS; otherwise netd rejects the lookup before any TUN packet exists.
     * This never changes firewall rules or bypasses VPN routing.
     */
    private fun awaitNetworkAccess(requireAccess: Boolean=true): Boolean {
        val cm=targetContext.getSystemService(android.net.ConnectivityManager::class.java)
        val ready=java.util.concurrent.CountDownLatch(1)
        val callback=object: android.net.ConnectivityManager.NetworkCallback() {
            override fun onBlockedStatusChanged(network: android.net.Network, blocked: Boolean) {
                if(!blocked) ready.countDown()
            }
        }
        cm.registerDefaultNetworkCallback(callback)
        try {
            val admitted=ready.await(if(requireAccess) 10L else 1L,java.util.concurrent.TimeUnit.SECONDS)
            if(requireAccess) check(admitted) { "Android kept probe UID network-blocked before DNS" }
            return admitted
        }
        finally { cm.unregisterNetworkCallback(callback) }
    }
    override fun onStart() {
        val result=Bundle()
        var stage="initial"
        var received=0
        try {
            if(mode.startsWith("lockdown_") || mode=="vpn_status") {
                check(android.os.Build.HARDWARE in listOf("ranchu","goldfish")) { "Device policy tests require disposable emulator" }
                val dpm=targetContext.getSystemService(android.app.admin.DevicePolicyManager::class.java)
                val admin=android.content.ComponentName(targetContext,ProbeAdmin::class.java)
                when(mode) {
                    "lockdown_on" -> {
                        dpm.setAlwaysOnVpnPackage(admin,"com.nonroot.firewall",true)
                        check(dpm.getAlwaysOnVpnPackage(admin)=="com.nonroot.firewall")
                        check(dpm.isAlwaysOnVpnLockdownEnabled(admin))
                        result.putString("status","OK")
                    }
                    "lockdown_off" -> { dpm.setAlwaysOnVpnPackage(admin,null,false); result.putString("status","OK") }
                    "vpn_status" -> {
                        result.putBoolean("networkAdmitted",awaitNetworkAccess(requireAccess=false))
                        val cm=targetContext.getSystemService(android.net.ConnectivityManager::class.java)
                        result.putString("status",if(cm.getNetworkCapabilities(cm.activeNetwork)?.hasTransport(android.net.NetworkCapabilities.TRANSPORT_VPN)==true) "VPN" else "NO_VPN")
                        result.putBoolean("lockdown",dpm.isAlwaysOnVpnLockdownEnabled(admin))
                    }
                    "lockdown_control", "lockdown_probe" -> {
                        check(token.length in 16..64 && token.all { it.isLetterOrDigit() })
                        val packet=("lockdown-"+token).toByteArray()
                        var attempts=0; var denied=0; var escaped=false
                        sendStatus(0,Bundle().apply { putString("phase","READY") })
                        val deadline=android.os.SystemClock.elapsedRealtimeNanos()+java.util.concurrent.TimeUnit.SECONDS.toNanos(if(mode=="lockdown_control") 3 else 12)
                        while(android.os.SystemClock.elapsedRealtimeNanos()<deadline) {
                            attempts++
                            // Recreate the FD on every attempt: a socket bound to the dead VPN
                            // cannot prove that newly opened connections are blocked by lockdown.
                            try {
                                DatagramSocket().use { socket ->
                                    socket.soTimeout=10
                                    socket.send(DatagramPacket(packet,packet.size,InetSocketAddress("10.0.2.2",28084)))
                                    val answer=DatagramPacket(ByteArray(128),128)
                                    try {
                                        socket.receive(answer)
                                        check(answer.data.copyOf(answer.length).contentEquals(packet))
                                        escaped=true
                                    } catch(_: SocketTimeoutException) { }
                                }
                            } catch(e: java.io.IOException) { if(permissionDenied(e)) denied++ else throw e }
                            if(escaped) break
                            Thread.sleep(10)
                        }
                        if(mode=="lockdown_probe") check(attempts>=100) { "Insufficient process-death probes: $attempts" }
                        result.putString("status",if(escaped) "ESCAPED" else "BLOCKED")
                        result.putString("metrics","attempts=$attempts denied=$denied uid=${android.os.Process.myUid()}")
                    }
                    else -> error("Unknown control mode")
                }
                finish(Activity.RESULT_OK,result); return
            }
            if(mode in listOf("system_dns","system_dns_mobile")) {
                stage="android-network-readiness"; awaitNetworkAccess()
                stage="system-dns"
                val name=if(mode=="system_dns_mobile") "example.com" else "firewall-test.invalid"
                val addresses=java.net.InetAddress.getAllByName(name)
                check(if(mode=="system_dns_mobile") addresses.isNotEmpty() else addresses.any { it.hostAddress=="192.0.2.123" })
                result.putString("status","OK"); finish(Activity.RESULT_OK,result); return
            }
            if(mode=="half_close") {
                stage="client-first-half-close"
                transfer(1024*1024)
                result.putString("status","OK"); finish(Activity.RESULT_OK,result); return
            }
            if(mode=="dns_block") {
                awaitNetworkAccess()
                val name="blocked-"+java.util.UUID.randomUUID().toString().replace("-","")+".firewall-test.invalid"
                try {
                    java.net.InetAddress.getAllByName(name)
                    result.putString("status","ESCAPED")
                } catch(_: java.net.UnknownHostException) { result.putString("status","BLOCKED") }
                finish(Activity.RESULT_OK,result); return
            }
            if(mode in listOf("direct_socket","direct_channel")) {
                check(android.os.Build.HARDWARE in listOf("ranchu","goldfish"))
                stage="android-network-readiness"; awaitNetworkAccess()
                stage="direct-system-dns"
                check(java.net.InetAddress.getAllByName("firewall-test.invalid").any { it.hostAddress=="192.0.2.123" })
                stage="direct-half-close"
                transfer(1024*1024)
                result.putString("status","OK"); finish(Activity.RESULT_OK,result); return
            }
            val payload=ByteArray(1200) { (it*17).toByte() }
            if(mode in listOf("stress","stress_payload","soak")) {
                val started=android.os.SystemClock.elapsedRealtimeNanos()
                val cpu=android.os.Process.getElapsedCpuTime()
                val pssBefore=android.os.Debug.getPss()
                var persistentEchoes=0
                if(mode!="soak") {
                    for(size in listOf(1,10,100)) {
                        stage="${size}MiB"; val begin=android.os.SystemClock.elapsedRealtimeNanos(); transfer(size*1024*1024); completed+=size.toLong()*1024*1024
                        sendStatus(0,Bundle().apply { putString("measurement","$stage bytes=${size*1024*1024} elapsedMs=${(android.os.SystemClock.elapsedRealtimeNanos()-begin)/1000000}") })
                    }
                    Socket().use { latencySocket ->
                        latencySocket.tcpNoDelay=true; latencySocket.soTimeout=5000
                        latencySocket.connect(InetSocketAddress("10.0.2.2",28080),5000)
                        val samples=LongArray(32) {
                            val began=android.os.SystemClock.elapsedRealtimeNanos()
                            latencySocket.getOutputStream().write(42)
                            check(latencySocket.getInputStream().read()==42)
                            (android.os.SystemClock.elapsedRealtimeNanos()-began)/1000
                        }.sorted()
                        sendStatus(0,Bundle().apply { putString("measurement","latency samples=32 medianUs=${samples[16]} p95Us=${samples[30]}") })
                    }
                    stage="concurrent"; val errors=java.util.concurrent.ConcurrentLinkedQueue<Throwable>()
                    val threads=(1..4).map { Thread { try { transfer(1024*1024) } catch(t: Throwable) { errors.add(t) } }.apply { start() } }
                    threads.forEach { it.join(120000); check(!it.isAlive) }; check(errors.isEmpty()) { errors.toString() }; completed+=4*1024*1024
                } else {
                    check(durationSeconds>=3600) { "Soak requires at least 60 minutes" }
                    val deadline=android.os.SystemClock.elapsedRealtimeNanos()+java.util.concurrent.TimeUnit.SECONDS.toNanos(durationSeconds.toLong())
                    var heartbeatAt=android.os.SystemClock.elapsedRealtimeNanos()
                    Socket().use { persistent ->
                    persistent.soTimeout=15000; persistent.tcpNoDelay=true
                    persistent.connect(InetSocketAddress("10.0.2.2",28080),5000)
                    while(android.os.SystemClock.elapsedRealtimeNanos()<deadline) {
                        persistent.getOutputStream().write(payload)
                        val response=ByteArray(payload.size)
                        var offset=0
                        while(offset<response.size) { val count=persistent.getInputStream().read(response,offset,response.size-offset); check(count>0); offset+=count }
                        check(response.contentEquals(payload)); persistentEchoes++
                        stage="soak-transfer"; transfer(65536); completed+=65536
                        DatagramSocket().use { udp -> udp.soTimeout=5000; udp.connect(InetSocketAddress("10.0.2.2",28081)); udp.send(DatagramPacket(payload,payload.size)); val answer=DatagramPacket(ByteArray(1500),1500); udp.receive(answer); check(answer.data.copyOf(answer.length).contentEquals(payload)) }
                        if(android.os.SystemClock.elapsedRealtimeNanos()-heartbeatAt>=java.util.concurrent.TimeUnit.SECONDS.toNanos(60)) {
                            heartbeatAt=android.os.SystemClock.elapsedRealtimeNanos()
                            sendStatus(0,Bundle().apply { putString("heartbeat","elapsedMs=${(android.os.SystemClock.elapsedRealtimeNanos()-started)/1000000} bytes=$completed pssKiB=${android.os.Debug.getPss()}") })
                        }
                        Thread.sleep(5000)
                    }
                    }
                }
                result.putString("status","OK")
                result.putString("metrics","mode=$mode bytes=$completed concurrentConnections=${if(mode!="soak") 4 else 1} halfCloseRequired=${mode!="stress_payload"} persistentEchoes=$persistentEchoes elapsedMs=${(android.os.SystemClock.elapsedRealtimeNanos()-started)/1000000} cpuMs=${android.os.Process.getElapsedCpuTime()-cpu} pssBeforeKiB=$pssBefore pssAfterKiB=${android.os.Debug.getPss()}")
                finish(Activity.RESULT_OK,result); return
            }
            val tcpPayload=if(allowedMode()) ByteArray(65536) { (it*37).toByte() } else payload
            if(allowedMode() || mode=="tcp_hold") {
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
            if(allowedMode()) { stage="dns-transports"; dnsTransports() }
            if(allowedMode() || mode=="udp_block") {
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
