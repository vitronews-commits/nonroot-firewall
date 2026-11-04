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
    private val worker=Executors.newSingleThreadExecutor()
    @Volatile private var selectedNetwork: Network?=null
    private var classifiedKind=NetworkKind.OTHER
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
        override fun onLost(network: Network) { updateNetwork() }
        override fun onCapabilitiesChanged(network: Network, caps: NetworkCapabilities) { updateNetwork() }
    }
    override fun onCreate() {
        super.onCreate()
        RuleChangeBus.register(ruleListener)
        connectivity.registerNetworkCallback(NetworkRequest.Builder()
            .addCapability(NetworkCapabilities.NET_CAPABILITY_NOT_VPN).build(),callback)
    }
    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        if(intent?.action==STOP) { stopSelf(); return START_NOT_STICKY }
        if(EngineEvents.status=="RUNNING" || EngineEvents.status=="Verifying protected transports") return START_NOT_STICKY
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
        rules=RuleEngine(RuleStore(this).load(),AppRuleStore(this).load())
        forwarder?.invalidate()
        owners.clear()
        updateNetwork()
        policyReady=true
        EngineEvents.pending.snapshot().filter { rules.decide(it.connection)!=Decision.PENDING }
            .forEach { EngineEvents.pending.resolve(it.connection) }
    }
    /** Signal-strength/capability refreshes must not terminate unchanged paths. */
    @Synchronized private fun updateNetwork() {
        val candidates=connectivity.allNetworks.filter { n ->
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
        if(next==selectedNetwork && kind==classifiedKind) return
        forwarder?.invalidate()
        owners.clear()
        selectedNetwork=next
        classifiedKind=kind
        if(tun!=null) setUnderlyingNetworks(next?.let { arrayOf(it) } ?: emptyArray())
    }
    private fun classify(network: Network?): NetworkKind {
        val caps=network?.let { connectivity.getNetworkCapabilities(it) }
        return when {
            caps?.hasTransport(NetworkCapabilities.TRANSPORT_WIFI)==true -> NetworkKind.WIFI
            caps?.hasTransport(NetworkCapabilities.TRANSPORT_CELLULAR)==true -> NetworkKind.MOBILE
            else -> NetworkKind.OTHER
        }
    }
    private fun network()=classify(selectedNetwork)
    private fun allowed(h: PacketParser.Header): Boolean {
        if(!policyReady || stopped.get() || selectedNetwork==null) return false
        val owner=owners[h] ?: return false
        val c=owner.connection
        val current=resolver.resolve(h) ?: return false
        return c.network==network() && rules.decide(c)==Decision.ALLOW &&
            current.uid==owner.uid && current.unambiguousPackage==c.packageName
    }
    private fun startTunnel() {
        var input: ParcelFileDescriptor.AutoCloseInputStream?=null
        var output: ParcelFileDescriptor.AutoCloseOutputStream?=null
        try {
            check(prepare(this)==null) { "VPN permission required" }
            EngineSelfTest.verify({ SocketProtection.tcp { protect(it) } },{ SocketProtection.udp { protect(it) } })
            check(!stopped.get())
            EngineEvents.record(null,"Protected TCP/UDP preflight passed before TUN")
            reload()
            val descriptor=Builder().setSession("NonRoot Firewall").setMtu(1500)
                .addAddress("10.23.0.1",32).addAddress("fd23:23::1",128)
                .addRoute("0.0.0.0",0).addRoute("::",0)
                .addDnsServer("1.1.1.1").addDnsServer("2606:4700:4700::1111")
                .setUnderlyingNetworks(selectedNetwork?.let { arrayOf(it) } ?: emptyArray()).setBlocking(false).establish() ?: error("TUN creation rejected")
            synchronized(this) {
                if(stopped.get()) { descriptor.close(); return }
                tun=descriptor
            }
            val out=ParcelFileDescriptor.AutoCloseOutputStream(ParcelFileDescriptor.dup(descriptor.fileDescriptor))
            output=out
            val incoming=ParcelFileDescriptor.AutoCloseInputStream(ParcelFileDescriptor.dup(descriptor.fileDescriptor))
            input=incoming
            val poll=StructPollfd().apply { fd=incoming.fd; events=OsConstants.POLLIN.toShort() }
            val writeLock=Any()
            val engine=PacketForwarder(::tcp,::udp,::allowed,{ bytes ->
                synchronized(writeLock) {
                    if(!stopped.get()) {
                        out.write(bytes)
                        val h=PacketParser.parse(bytes)?.let { TransportPacket.reverse(it) }
                        EngineEvents.record(h?.let { owners[it]?.connection },"REPLY ${bytes.size} bytes")
                    }
                }
            },onError={ error ->
                EngineEvents.record(null,"Transport failure: ${error.javaClass.simpleName}: ${error.message}")
            })
            forwarder=engine
            EngineEvents.status="RUNNING"
            startForeground(1,
                Notification.Builder(this,"firewall").setContentTitle("NonRoot Firewall")
                    .setContentText("Active — unknown connections blocked")
                    .setSmallIcon(android.R.drawable.ic_lock_lock).setOngoing(true).build())
            val buffer=ByteArray(65535)
            while(!stopped.get()) {
                if(Os.poll(arrayOf(poll),250)==0) continue
                if(stopped.get()) break
                val size=incoming.read(buffer)
                if(size<0) break
                val bytes=buffer.copyOf(size)
                val p=TransportPacket.parse(bytes)
                if(p==null) { EngineEvents.record(null,"DROP malformed/unsupported packet"); continue }
                val h=p.header
                val owner=resolver.resolve(h)
                val pkg=owner?.unambiguousPackage
                if(pkg==null) {
                    owners.remove(h)
                    engine.accept(bytes) // Revoke a previously attributed flow, if any.
                    EngineEvents.record(null,"DROP unknown/shared UID"); continue
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
                EngineEvents.record(connection,if(forwarded) "QUEUED" else if(decision==Decision.ALLOW) "DROP transport capacity/state" else decision.name+" / dropped")
            }
        } catch(e: Exception) {
            if(!stopped.get()) {
                EngineEvents.status="ERROR — ${e.message ?: e.javaClass.simpleName}"
                EngineEvents.record(null,EngineEvents.status)
            }
        } finally {
            try { input?.close() } catch(_: Exception) { }
            try { output?.close() } catch(_: Exception) { }
            stopSelf()
        }
    }
    override fun onRevoke() { stopSelf(); super.onRevoke() }
    override fun onDestroy() {
        policyReady=false
        stopped.set(true)
        forwarder?.close(); forwarder=null
        synchronized(this) { tun?.close(); tun=null }
        owners.clear()
        RuleChangeBus.unregister(ruleListener)
        try { connectivity.unregisterNetworkCallback(callback) } catch(_: Exception) { }
        worker.shutdownNow()
        if(!EngineEvents.status.startsWith("ERROR")) EngineEvents.status="OFF"
        super.onDestroy()
    }
}
