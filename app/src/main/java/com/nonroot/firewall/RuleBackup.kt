package com.nonroot.firewall

import android.content.Context
import org.json.JSONArray
import org.json.JSONObject
import java.nio.ByteBuffer
import java.nio.charset.CodingErrorAction

/** Versioned metadata only, bounded input, all-or-nothing validation and one atomic preference commit. */
object RuleBackup {
    const val MAX_BYTES=131072
    private const val MAX_RULES=1000
    data class Data(val ips: List<IpRule>,val apps: List<AppRule>)
    private fun validPackage(name: String)=name=="android" || name.length<=255 && name.matches(Regex("[A-Za-z_][A-Za-z0-9_]*(\\.[A-Za-z_][A-Za-z0-9_]*)+"))
    private fun network(obj: JSONObject): NetworkKind? {
        val name=obj.getString("network")
        return if(name.isEmpty()) null else NetworkKind.valueOf(name)
    }
    fun encode(data: Data): ByteArray {
        val ips=JSONArray(); val apps=JSONArray()
        data.ips.forEach { r -> ips.put(JSONObject().put("packageName",r.packageName ?: "").put("cidr",r.cidr).put("network",r.network?.name ?: "").put("decision",r.decision.name).put("port",r.port ?: -1)) }
        data.apps.forEach { r -> apps.put(JSONObject().put("packageName",r.packageName).put("network",r.network?.name ?: "").put("decision",r.decision.name)) }
        val bytes=JSONObject().put("format","nonroot-firewall-rules").put("version",1).put("ipRules",ips).put("appRules",apps).toString(2).toByteArray(Charsets.UTF_8)
        decode(bytes) // Never emit an archive which our bounded importer cannot restore.
        return bytes
    }
    fun decode(bytes: ByteArray): Data {
        require(bytes.size in 1..MAX_BYTES) { "Backup must be at most 128 KiB" }
        val text=Charsets.UTF_8.newDecoder().onMalformedInput(CodingErrorAction.REPORT).onUnmappableCharacter(CodingErrorAction.REPORT).decode(ByteBuffer.wrap(bytes)).toString()
        JsonEnvelope.validate(text)
        val tokener=org.json.JSONTokener(text)
        val obj=tokener.nextValue() as? JSONObject ?: error("Backup must be an object")
        require(tokener.nextClean()==0.toChar()) { "Trailing JSON content" }
        require(obj.getString("format")=="nonroot-firewall-rules" && obj.get("version")==1) { "Unsupported backup version" }
        val ipArray=obj.getJSONArray("ipRules"); val appArray=obj.getJSONArray("appRules")
        require(ipArray.length()+appArray.length()<=MAX_RULES) { "Too many rules" }
        val ips=(0 until ipArray.length()).map { i ->
            val r=ipArray.getJSONObject(i)
            for(key in listOf("packageName","cidr","network","decision")) require(r.get(key) is String) { "Invalid string field" }
            val pkg=r.getString("packageName").takeIf { it.isNotEmpty() }
            require(pkg==null || validPackage(pkg)) { "Invalid package" }
            val cidr=r.getString("cidr"); require(cidr.length<=80 && RuleEngine.isValidCidr(cidr)) { "Invalid numeric CIDR" }
            val rawPort=r.get("port"); require(rawPort is Int && rawPort in -1..65535) { "Invalid port" }
            IpRule(pkg,cidr,network(r),Decision.valueOf(r.getString("decision")),rawPort.takeIf { it>=0 })
        }
        val apps=(0 until appArray.length()).map { i ->
            val r=appArray.getJSONObject(i); for(key in listOf("packageName","network","decision")) require(r.get(key) is String) { "Invalid string field" }; val pkg=r.getString("packageName"); require(validPackage(pkg)) { "Invalid package" }
            val decision=Decision.valueOf(r.getString("decision")); require(decision!=Decision.PENDING)
            AppRule(pkg,network(r),decision)
        }
        require(apps.map { it.packageName to it.network }.distinct().size==apps.size) { "Duplicate application/network rule" }
        return Data(ips,apps)
    }
    fun apply(context: Context,data: Data): Boolean {
        val archive=JSONObject(String(encode(data),Charsets.UTF_8))
        val saved=context.getSharedPreferences("firewall_rules",Context.MODE_PRIVATE).edit()
            .putString("ip_rules",archive.getJSONArray("ipRules").toString())
            .putString("app_rules",archive.getJSONArray("appRules").toString()).commit()
        if(saved) RuleChangeBus.notifySaved()
        return saved
    }
}
