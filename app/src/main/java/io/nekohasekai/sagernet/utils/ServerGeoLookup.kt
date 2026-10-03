package io.nekohasekai.sagernet.utils

import com.google.gson.Gson
import com.google.gson.annotations.SerializedName
import io.nekohasekai.sagernet.SagerNet
import io.nekohasekai.sagernet.database.DataStore
import io.nekohasekai.sagernet.ktx.Logs
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import kotlinx.coroutines.withContext
import java.io.File
import java.net.HttpURLConnection
import java.net.InetSocketAddress
import java.net.Proxy
import java.net.URL
import java.util.concurrent.ConcurrentHashMap

object ServerGeoLookup {

    const val SOURCE_IPINFO = 0
    const val SOURCE_LOCAL_MMDB = 1

    private val gson = Gson()
    private val baseDir by lazy { File(SagerNet.application.filesDir, "geoip").apply { mkdirs() } }
    private val cacheFile get() = File(baseDir, "location_cache.json")
    private val memoryCache = ConcurrentHashMap<String, GeoIPManager.Info>()
    private val cacheLock = Mutex()
    private var diskCache: MutableMap<String, CachedEntry> = mutableMapOf()

    data class MockLookupResult(
        val info: GeoIPManager.Info?,
        val ipinfoStatus: String? = null,
    )

    private data class CachedEntry(
        @SerializedName("cc") val countryCode: String? = null,
        @SerializedName("cn") val countryName: String? = null,
        @SerializedName("city") val city: String? = null,
        @SerializedName("lat") val latitude: Double,
        @SerializedName("lon") val longitude: Double,
        @SerializedName("src") val source: String,
        @SerializedName("at") val fetchedAt: Long = System.currentTimeMillis(),
    ) {
        fun toInfo() = GeoIPManager.Info(countryCode, countryName, null, null, city, latitude, longitude)
    }

    private data class CacheFile(@SerializedName("e") val entries: Map<String, CachedEntry> = emptyMap())

    private fun loadDiskCache() {
        if (!cacheFile.exists()) {
            diskCache = mutableMapOf()
            return
        }
        try {
            diskCache = gson.fromJson(cacheFile.readText(), CacheFile::class.java)?.entries?.toMutableMap()
                ?: mutableMapOf()
        } catch (e: Throwable) {
            Logs.w(e)
            diskCache = mutableMapOf()
        }
    }

    private fun persistDiskCache() {
        try {
            cacheFile.writeText(gson.toJson(CacheFile(diskCache)))
        } catch (e: Throwable) {
            Logs.w(e)
        }
    }

    fun getCached(host: String): GeoIPManager.Info? {
        val ip = HostResolver.cached(host) ?: return null
        return memoryCache[ip] ?: diskCache[ip]?.toInfo()
    }

    suspend fun lookupForMock(host: String): GeoIPManager.Info? = lookupForMockResult(host).info

    suspend fun lookupForMockResult(host: String): MockLookupResult = withContext(Dispatchers.IO) {
        if (DataStore.geoLocationSource == SOURCE_IPINFO) {
            return@withContext lookupCurrentProxyIpinfo()
        }

        val ip = HostResolver.resolve(host) ?: return@withContext MockLookupResult(null, "DNS error")
        memoryCache[ip]?.let { return@withContext MockLookupResult(it) }
        if (diskCache.isEmpty() && cacheFile.exists()) loadDiskCache()
        diskCache[ip]?.let { entry ->
            val info = entry.toInfo()
            memoryCache[ip] = info
            return@withContext MockLookupResult(info)
        }

        val lookup = GeoIPManager.lookupCityMmdb(ip)
            ?.let { MockLookupResult(it) } ?: MockLookupResult(null)
        val info = lookup.info ?: return@withContext lookup

        val entry = CachedEntry(
            countryCode = info.countryCode,
            countryName = info.countryName,
            city = info.city,
            latitude = info.latitude!!,
            longitude = info.longitude!!,
            source = if (DataStore.geoLocationSource == SOURCE_LOCAL_MMDB) "mmdb" else "ipinfo",
        )
        memoryCache[ip] = info
        cacheLock.withLock {
            diskCache[ip] = entry
            persistDiskCache()
        }
        MockLookupResult(info)
    }

    private fun ipinfoStatus(json: Map<String, Any?>): String? {
        return when (val status = json["status"]) {
            is Number -> status.toInt().toString()
            is String -> status
            else -> null
        }
    }

    private suspend fun lookupCurrentProxyIpinfo(): MockLookupResult {
        val token = DataStore.ipinfoApiKey.trim()
        val url = buildString {
            append("https://ipinfo.io/json")
            if (token.isNotEmpty()) append("?token=").append(token)
        }
        if (!SagerNet.started || DataStore.startedProfile <= 0) {
            return MockLookupResult(null, "proxy not connected")
        }
        if (!DataStore.requireSocks) {
            return MockLookupResult(null, "SOCKS inbound disabled")
        }
        return try {
            val proxy = Proxy(Proxy.Type.SOCKS, InetSocketAddress("127.0.0.1", DataStore.socksPort))
            val connection = (URL(url).openConnection(proxy) as HttpURLConnection).apply {
                connectTimeout = 10_000
                readTimeout = 10_000
                requestMethod = "GET"
                setRequestProperty("User-Agent", "BetterExclave/0.17 (GeoLocation)")
            }
            val statusCode = connection.responseCode
            val body = try {
                (if (statusCode in 200..299) connection.inputStream else connection.errorStream)
                    ?.bufferedReader()
                    ?.use { it.readText() }
                    .orEmpty()
            } finally {
                connection.disconnect()
            }
            if (statusCode !in 200..299) return MockLookupResult(null, statusCode.toString())
            if (body.isBlank()) return MockLookupResult(null, statusCode.toString())
            @Suppress("UNCHECKED_CAST")
            val json = gson.fromJson(body, Map::class.java) as? Map<String, Any?>
                ?: return MockLookupResult(null, statusCode.toString())
            val ip = json["ip"] as? String ?: return MockLookupResult(null, ipinfoStatus(json) ?: statusCode.toString())
            memoryCache[ip]?.let { return MockLookupResult(it) }
            if (diskCache.isEmpty() && cacheFile.exists()) loadDiskCache()
            diskCache[ip]?.let { entry ->
                val info = entry.toInfo()
                memoryCache[ip] = info
                return MockLookupResult(info)
            }
            val loc = json["loc"] as? String ?: return MockLookupResult(null, ipinfoStatus(json) ?: statusCode.toString())
            val parts = loc.split(',')
            if (parts.size != 2) return MockLookupResult(null, ipinfoStatus(json) ?: statusCode.toString())
            val lat = parts[0].trim().toDoubleOrNull()
            val lon = parts[1].trim().toDoubleOrNull()
            if (lat == null || lon == null) return MockLookupResult(null, ipinfoStatus(json) ?: statusCode.toString())
            val info = GeoIPManager.Info(
                countryCode = json["country"] as? String,
                countryName = null,
                asn = null,
                asnName = json["org"] as? String,
                city = json["city"] as? String,
                latitude = lat,
                longitude = lon,
            )
            val entry = CachedEntry(
                countryCode = info.countryCode,
                countryName = info.countryName,
                city = info.city,
                latitude = lat,
                longitude = lon,
                source = "ipinfo",
            )
            memoryCache[ip] = info
            cacheLock.withLock {
                diskCache[ip] = entry
                persistDiskCache()
            }
            MockLookupResult(info)
        } catch (e: Throwable) {
            Logs.w(e)
            MockLookupResult(null, e.message ?: "network error")
        }
    }
}
