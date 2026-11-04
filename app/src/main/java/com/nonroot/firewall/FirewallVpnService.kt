package com.nonroot.firewall

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.content.Intent
import android.net.ConnectivityManager
import android.net.Network
import android.net.NetworkCapabilities
import android.net.NetworkRequest
import android.net.VpnService
import android.os.ParcelFileDescriptor
import android.system.Os
import android.system.OsConstants
import android.system.StructPollfd
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.Executors
import java.util.concurrent.atomic.AtomicBoolean

/** Local VPN. No tunnel is established until protected bidirectional preflight passes. */
class FirewallVpnService : VpnService() {
    companion object { const val STOP="com.nonroot.firewall.STOP" }
    private val stopped=AtomicBoolean(false)
    private val started=AtomicBoolean(false)
    @Volatile private var rulesValid=false
    @Volatile private var routeVersion=0L
    @Volatile private var installedVersion=-1L
    @Volatile private var networkDns: List<java.net.InetAddress> = emptyList()
    @Volatile private var networkInterface: String?=null
    private val trafficLogs=TrafficLogLimiter()
    private val worker=Executors.newSingleThreadExecutor()
    @Volatile private var selectedNetwork: Network?=null
    @Volatile private var underlyingMtu=1500
    @Volatile private var classifiedKind=NetworkKind.OTHER
    private var tun: ParcelFileDescriptor?=null
    @Volatile private var forwarder: PacketForwarder?=null
    @Volatile private var rules=RuleEngine()
    private data class Attribution(val uid: Int,val connection: Connection)
    @Volatile private var policyReady=false
    private val owners=ConcurrentHashMap<PacketParser.Header,Attribution>()
    private val connectivity by lazy { getSystemService(ConnectivityManager::class.java) }
    private val resolver by lazy { ConnectionOwnerResolver(this) }
    private val ruleListener: ()->Unit={ reload() }
    private val callback=object: ConnectivityManager.NetworkCallback() {
        override fun onAvailable(network: Network) { updateNetwork() }
        override fun onLost(network: Network) { updateNetwork(network) }
        override fun onCapabilitiesChanged(network: Network, caps: NetworkCapabilities) { updateNetwork() }
        override fun onLinkPropertiesChanged(network: Network, properties: android.net.LinkProperties) { updateNetwork() }
    }
    override fun onCreate() {
        super.onCreate()
        RuleChangeBus.register(ruleListener)
        connectivity.registerNetworkCallback(NetworkRequest.Builder()
            .addCapability(NetworkCapabilities.NET_CAPABILITY_NOT_VPN).build(),callback)
    }
    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        if(intent?.action==STOP) { stopSelf(); return START_NOT_STICKY }
        if(!started.compareAndSet(false,true)) return START_NOT_STICKY
        getSystemService(NotificationManager::class.java).createNotificationChannel(
            NotificationChannel("firewall","Firewall",NotificationManager.IMPORTANCE_LOW))
        val open=PendingIntent.getActivity(this,0,Intent(this,MainActivity::class.java),PendingIntent.FLAG_IMMUTABLE)
        startForeground(1,Notification.Builder(this,"firewall").setContentTitle("NonRoot Firewall")
            .setContentText("Validating packet engine").setSmallIcon(android.R.drawable.ic_lock_lock)
            .setContentIntent(open).setOngoing(true).build())
        EngineEvents.status="Verifying protected transports"
        worker.execute { startTunnel() }
        return START_NOT_STICKY
    }
    private fun tcp()=SocketProtection.tcp { protect(it) }.also { socket ->
        try { checkNotNull(selectedNetwork) { "No underlying network" }.bindSocket(socket) }
        catch(e: Exception) { socket.close(); throw e }
    }
    private fun udp()=SocketProtection.udp { protect(it) }.also { socket ->
        try { checkNotNull(selectedNetwork) { "No underlying network" }.bindSocket(socket) }
        catch(e: Exception) { socket.close(); throw e }
    }
    @Synchronized private fun reload() {
        policyReady=false
        rulesValid=false
        rules=try { RuleEngine(RuleStore(this).load(strict=true),AppRuleStore(this).load(strict=true)) }
        catch(e: Exception) {
            forwarder?.invalidate(); owners.clear()
            EngineEvents.status="ERROR — malformed saved rules; forwarding blocked"
            EngineEvents.record(null,EngineEvents.status)
            throw e
        }
        rulesValid=true
        forwarder?.invalidate()
        owners.clear()
        updateNetwork()
        trafficLogs.clear()
        refreshReady()
        if(tun!=null) EngineEvents.status=if(policyReady) "RUNNING" else "WAITING — forwarding blocked"
        EngineEvents.pending.snapshot().filter { rules.decide(it.connection)!=Decision.PENDING }
            .forEach { EngineEvents.pending.resolve(it.connection) }
    }
    /** Signal-strength/capability refreshes must not terminate unchanged paths. */
    @Synchronized private fun updateNetwork(excluded: Network?=null) {
        val candidates=connectivity.allNetworks.filter { n ->
            if(n==excluded) return@filter false
            val c=connectivity.getNetworkCapabilities(n)
            c?.hasCapability(NetworkCapabilities.NET_CAPABILITY_NOT_VPN)==true &&
                c.hasCapability(NetworkCapabilities.NET_CAPABILITY_INTERNET)
        }
        val validated=candidates.filter { n ->
            connectivity.getNetworkCapabilities(n)?.hasCapability(NetworkCapabilities.NET_CAPABILITY_VALIDATED)==true
        }
        val preferred=validated.ifEmpty { candidates }
        val next=connectivity.activeNetwork?.takeIf { it in preferred }
            ?: selectedNetwork?.takeIf { it in preferred } ?: preferred.firstOrNull()
        val kind=classify(next)
        val properties=next?.let { connectivity.getLinkProperties(it) }
        val dns=properties?.dnsServers.orEmpty().toList()
        networkInterface=properties?.interfaceName
        underlyingMtu=properties?.mtu?.takeIf { it>0 } ?: 1500
        if(next==selectedNetwork && kind==classifiedKind && dns==networkDns) return
        policyReady=false
        forwarder?.invalidate()
        owners.clear()
        routeVersion++
        networkDns=dns
        selectedNetwork=next
        classifiedKind=kind
        EngineEvents.network=if(next==null) null else kind
        if(tun!=null) setUnderlyingNetworks(next?.let { arrayOf(it) } ?: emptyArray())
        // The worker installs new DNS/routes while the old TUN remains a closed gate.
        refreshReady()
    }
    private fun refreshReady() {
        policyReady=!stopped.get() && rulesValid && installedVersion==routeVersion && selectedNetwork!=null && networkDns.isNotEmpty()
    }
    private fun classify(network: Network?): NetworkKind {
        val caps=network?.let { connectivity.getNetworkCapabilities(it) }
        return when {
            caps?.hasTransport(NetworkCapabilities.TRANSPORT_WIFI)==true -> NetworkKind.WIFI
            caps?.hasTransport(NetworkCapabilities.TRANSPORT_CELLULAR)==true -> NetworkKind.MOBILE
            else -> NetworkKind.OTHER
        }
    }
    private fun network()=classifiedKind
    private fun policyAllows(h: PacketParser.Header): Boolean {
        if(!policyReady || stopped.get() || selectedNetwork==null) return false
        val c=owners[h]?.connection ?: return false
        return c.network==network() && rules.decide(c)==Decision.ALLOW
    }
    private fun allowed(h: PacketParser.Header): Boolean {
        if(!policyReady || stopped.get() || selectedNetwork==null) return false
        val owner=owners[h] ?: return false
        val c=owner.connection
        val current=resolver.resolve(h) ?: return false
        return c.network==network() && rules.decide(c)==Decision.ALLOW &&
            current.uid==owner.uid && current.unambiguousPackage==c.packageName
    }
    private fun outboundHeader(bytes: ByteArray): PacketParser.Header? {
        val h=PacketParser.parse(bytes) ?: return null
        return if(h.protocol in listOf(6,17)) TransportPacket.reverse(h) else PathMtu.originatingHeader(bytes)
    }
    /** Establish replacement before releasing old route ownership: no deliberate fail-open gap. */
    private fun replaceTunnel(): ParcelFileDescriptor? {
        val config=synchronized(this) { Triple(routeVersion,selectedNetwork,networkDns.toList()) }
        if(stopped.get()) return null
        val builder=Builder().setSession("NonRoot Firewall").setMtu(1500)
            .addAddress("10.23.0.1",32).addAddress("fd23:23::1",128)
            .addRoute("0.0.0.0",0).addRoute("::",0)
            .setUnderlyingNetworks(config.second?.let { arrayOf(it) } ?: emptyArray()).setBlocking(false)
        // Offline placeholders keep routing captured; the gate stays closed until real network DNS exists.
        if(config.third.isEmpty()) builder.addDnsServer("10.23.0.53")
        else config.third.forEach { builder.addDnsServer(it) }
        val next=builder.establish() ?: error("TUN creation rejected")
        synchronized(this) {
            if(stopped.get()) { next.close(); return null }
            val old=tun
            tun=next; installedVersion=config.first
            refreshReady()
            try { old?.close() } catch(_: Exception) { }
        }
        return next
    }
    private fun startTunnel() {
        try {
            check(prepare(this)==null) { "VPN permission required" }
            EngineSelfTest.verify({ SocketProtection.tcp { protect(it) } },{ SocketProtection.udp { protect(it) } })
            check(!stopped.get())
            EngineEvents.record(null,"Protected TCP/UDP preflight passed before TUN")
            reload()
            while(!stopped.get()) {
                try {
                    val descriptor=replaceTunnel() ?: break
                    runTunnel(descriptor)
                } catch(e: Exception) {
                    policyReady=false
                    forwarder?.close(); forwarder=null; owners.clear()
                    EngineEvents.status="ERROR — ${e.message ?: e.javaClass.simpleName}; traffic blocked"
                    EngineEvents.record(null,EngineEvents.status)
                    // Keep any established TUN as a blackhole while retrying; only STOP/revoke releases it.
                    if(tun==null) throw e
                    Thread.sleep(1000)
                }
            }
        } catch(e: Exception) {
            if(!stopped.get()) {
                EngineEvents.status="ERROR — ${e.message ?: e.javaClass.simpleName}"
                EngineEvents.record(null,EngineEvents.status)
            }
        } finally { stopSelf() }
    }
    private fun runTunnel(descriptor: ParcelFileDescriptor) {
        var input: ParcelFileDescriptor.AutoCloseInputStream?=null
        var output: ParcelFileDescriptor.AutoCloseOutputStream?=null
        try {
            val out=ParcelFileDescriptor.AutoCloseOutputStream(ParcelFileDescriptor.dup(descriptor.fileDescriptor))
            output=out
            val incoming=ParcelFileDescriptor.AutoCloseInputStream(ParcelFileDescriptor.dup(descriptor.fileDescriptor))
            input=incoming
            val poll=StructPollfd().apply { fd=incoming.fd; events=OsConstants.POLLIN.toShort() }
            val writePoll=StructPollfd().apply { fd=out.fd; events=OsConstants.POLLOUT.toShort() }
            val writer=TunWriter({ bytes ->
                try {
                    val count=Os.write(out.fd,bytes,0,bytes.size)
                    check(count==bytes.size) { "Partial TUN packet write" }; true
                } catch(e: android.system.ErrnoException) { if(e.errno==OsConstants.EAGAIN) false else throw e }
            },{ timeout -> Os.poll(arrayOf(writePoll),timeout); Unit },{ bytes ->
                !stopped.get() && outboundHeader(bytes)?.let { allowed(it) }==true
            })
            val engine=PacketForwarder(::tcp,::udp,::policyAllows,{ bytes ->
                if(!writer.write(bytes)) throw java.io.InterruptedIOException("TUN reply revoked")
                val h=outboundHeader(bytes)
                val ipSize=if(bytes[0].toInt() ushr 4 and 15==4) 20 else 40
                val payloadReply=h?.protocol==6 && bytes.size>ipSize+((bytes[ipSize+12].toInt() ushr 4 and 15)*4)
                if(trafficLogs.allow(h,if(payloadReply) 3 else 1)) EngineEvents.record(h?.let { owners[it]?.connection },"REPLY ${bytes.size} bytes",h?.protocol)
            },onError={ error ->
                EngineEvents.record(null,"Transport failure: ${error.javaClass.simpleName}: ${error.message}")
            },pathMtu={ underlyingMtu },authorizeIo=::allowed,destination={ NetworkDestination.resolve(it,networkInterface) },
                onFlowError={ h,error -> EngineEvents.record(owners[h]?.connection,"Transport failure: ${error.javaClass.simpleName}: ${error.message}",h.protocol) })
            forwarder=engine
            EngineEvents.liveConnections={ engine.snapshot().mapNotNull { flow ->
                owners[flow.header]?.connection?.let { c -> EngineEvents.LiveConnection(c,flow.header.protocol,flow.header.sourcePort,flow.status,flow.tunInputBytes,flow.tunOutputBytes) }
            } }
            EngineEvents.status=if(policyReady) "RUNNING" else "WAITING — underlying network/DNS unavailable; traffic blocked"
            startForeground(1,
                Notification.Builder(this,"firewall").setContentTitle("NonRoot Firewall")
                    .setContentText("Active — unknown connections blocked")
                    .setSmallIcon(android.R.drawable.ic_lock_lock).setOngoing(true).build())
            val buffer=ByteArray(65535)
            while(!stopped.get() && installedVersion==routeVersion) {
                if(Os.poll(arrayOf(poll),250)==0) continue
                if(stopped.get()) break
                val size=incoming.read(buffer)
                if(size<0) break
                val bytes=buffer.copyOf(size)
                val p=TransportPacket.parse(bytes)
                if(p==null) { if(trafficLogs.allow(null,2)) EngineEvents.record(null,"DROP malformed/unsupported packet"); continue }
                val h=p.header
                val owner=resolver.resolve(h)
                val pkg=owner?.unambiguousPackage
                if(pkg==null) {
                    owners.remove(h)
                    engine.accept(bytes) // Revoke a previously attributed flow, if any.
                    if(trafficLogs.allow(h,2)) EngineEvents.record(null,"DROP unknown/shared UID uid=${owner?.uid} packages=${owner?.packageNames?.size} proto=${h.protocol} destination=${h.destination}:${h.destinationPort}"); continue
                }
                val connection=Connection(pkg,h.destination,h.destinationPort!!,network())
                val decision=rules.decide(connection)
                if(decision==Decision.PENDING) EngineEvents.pending.record(connection,System.currentTimeMillis())
                else EngineEvents.pending.resolve(connection)
                if(decision==Decision.ALLOW) {
                    // Bound the attribution cache as well as the socket table.
                    if(owners.size>=128 && !owners.containsKey(h)) {
                        // Evict stale metadata without terminating unrelated active transfers.
                        owners.keys.retainAll(engine.activeHeaders())
                    }
                    val previous=owners[h]
                    if(previous!=null && previous!=Attribution(owner!!.uid,connection)) { engine.invalidate(); owners.clear() }
                    owners[h]=Attribution(owner!!.uid,connection)
                } else owners.remove(h)
                val forwarded=engine.accept(bytes)
                if(trafficLogs.allow(h,if(forwarded) 0 else 2)) EngineEvents.record(connection,if(forwarded) "QUEUED" else if(decision==Decision.ALLOW) "DROP transport capacity/state" else decision.name+" / dropped",h.protocol)
            }
        } finally {
            policyReady=false
            forwarder?.close(); forwarder=null; owners.clear()
            EngineEvents.liveConnections={ emptyList() }
            try { input?.close() } catch(_: Exception) { }
            try { output?.close() } catch(_: Exception) { }
        }
    }
    override fun onRevoke() { policyReady=false; stopped.set(true); forwarder?.close(); stopSelf(); super.onRevoke() }
    override fun onDestroy() {
        policyReady=false
        stopped.set(true)
        forwarder?.close(); forwarder=null
        synchronized(this) { tun?.close(); tun=null }
        owners.clear()
        EngineEvents.liveConnections={ emptyList() }
        EngineEvents.network=null
        RuleChangeBus.unregister(ruleListener)
        try { connectivity.unregisterNetworkCallback(callback) } catch(_: Exception) { }
        worker.shutdownNow()
        if(!EngineEvents.status.startsWith("ERROR")) EngineEvents.status="OFF"
        super.onDestroy()
    }
}
