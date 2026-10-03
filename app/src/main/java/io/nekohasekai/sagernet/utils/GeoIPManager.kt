package io.nekohasekai.sagernet.utils

import com.maxmind.db.Reader
import io.nekohasekai.sagernet.SagerNet
import io.nekohasekai.sagernet.ktx.Logs
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import kotlinx.coroutines.withContext
import java.io.File
import java.io.FileInputStream
import java.io.FileOutputStream
import java.net.InetAddress
import java.util.concurrent.ConcurrentHashMap
import java.util.zip.GZIPInputStream

object GeoIPManager {

    private val baseDir by lazy { File(SagerNet.application.filesDir, "geoip").apply { mkdirs() } }
    private val countryFile get() = File(baseDir, "country.mmdb")
    private val asnFile get() = File(baseDir, "asn.mmdb")
    private val cityFile get() = File(baseDir, "city.mmdb")

    private var countryReader: Reader? = null
    private var asnReader: Reader? = null
    private var cityReader: Reader? = null
    private val readerLock = Mutex()

    data class Info(
        val countryCode: String?,
        val countryName: String?,
        val asn: Long?,
        val asnName: String?,
        val city: String? = null,
        val latitude: Double? = null,
        val longitude: Double? = null,
    )

    private val ipCache = ConcurrentHashMap<String, Info>()

    suspend fun ensureLoaded(): Boolean = readerLock.withLock {
        if (countryReader != null && asnReader != null) return@withLock true
        if (!countryFile.exists() || !asnFile.exists()) return@withLock false
        try {
            countryReader = Reader(countryFile, Reader.FileMode.MEMORY_MAPPED)
            asnReader = Reader(asnFile, Reader.FileMode.MEMORY_MAPPED)
            true
        } catch (e: Throwable) {
            Logs.w(e)
            false
        }
    }

    suspend fun ensureCityLoaded(): Boolean = readerLock.withLock {
        if (cityReader != null) return@withLock true
        if (!cityFile.exists()) return@withLock false
        try {
            cityReader = Reader(cityFile, Reader.FileMode.MEMORY_MAPPED)
            true
        } catch (e: Throwable) {
            Logs.w(e)
            false
        }
    }

    fun isReady(): Boolean = countryFile.exists() && asnFile.exists()

    fun isCityReady(): Boolean = cityFile.exists()

    fun close() {
        try { countryReader?.close() } catch (_: Throwable) {}
        try { asnReader?.close() } catch (_: Throwable) {}
        try { cityReader?.close() } catch (_: Throwable) {}
        countryReader = null
        asnReader = null
        cityReader = null
        ipCache.clear()
        HostResolver.clear()
    }

    suspend fun lookup(host: String): Info? = withContext(Dispatchers.IO) {
        if (!ensureLoaded()) return@withContext null
        val ip = HostResolver.resolve(host) ?: return@withContext null
        ipCache[ip]?.let { return@withContext it }
        val addr = try { InetAddress.getByName(ip) } catch (_: Throwable) { return@withContext null }

        val cc = try {
            @Suppress("UNCHECKED_CAST")
            val r = countryReader?.get(addr, Map::class.java) as? Map<String, Any?>
            val country = r?.get("country") as? Map<*, *>
            val code = (country?.get("iso_code") as? String) ?: (country?.get("isoCode") as? String)
            val name = (country?.get("names") as? Map<*, *>)?.get("en") as? String
            code to name
        } catch (_: Throwable) { null to null }

        val asn = try {
            @Suppress("UNCHECKED_CAST")
            val r = asnReader?.get(addr, Map::class.java) as? Map<String, Any?>
            val n = (r?.get("autonomous_system_number") as? Number)?.toLong()
            val name = r?.get("autonomous_system_organization") as? String
            n to name
        } catch (_: Throwable) { null to null }

        val cachedLoc = ServerGeoLookup.getCached(host)
        val info = Info(
            cc.first ?: cachedLoc?.countryCode,
            cc.second ?: cachedLoc?.countryName,
            asn.first,
            asn.second,
            cachedLoc?.city,
            cachedLoc?.latitude,
            cachedLoc?.longitude,
        )
        ipCache[ip] = info
        info
    }

    suspend fun lookupCityMmdb(ip: String): Info? = withContext(Dispatchers.IO) {
        if (!ensureCityLoaded()) return@withContext null
        val addr = try { InetAddress.getByName(ip) } catch (_: Throwable) { return@withContext null }
        try {
            @Suppress("UNCHECKED_CAST")
            val r = cityReader?.get(addr, Map::class.java) as? Map<String, Any?> ?: return@withContext null
            val country = r["country"] as? Map<*, *>
            val countryCode = (country?.get("iso_code") as? String) ?: (country?.get("isoCode") as? String)
            val countryName = (country?.get("names") as? Map<*, *>)?.get("en") as? String
            val city = (r["city"] as? Map<*, *>)?.let { c ->
                (c["names"] as? Map<*, *>)?.get("en") as? String
            }
            val location = r["location"] as? Map<*, *>
            val lat = (location?.get("latitude") as? Number)?.toDouble() ?: return@withContext null
            val lon = (location?.get("longitude") as? Number)?.toDouble() ?: return@withContext null
            Info(countryCode, countryName, null, null, city, lat, lon)
        } catch (_: Throwable) {
            null
        }
    }

    fun countryFlag(code: String?): String {
        if (code.isNullOrBlank() || code.length != 2) return ""
        val base = 0x1F1E6 - 'A'.code
        val sb = StringBuilder(4)
        for (ch in code.uppercase()) {
            if (ch !in 'A'..'Z') return ""
            sb.appendCodePoint(base + ch.code)
        }
        return sb.toString()
    }

    suspend fun downloadDatabases(
        downloadCity: Boolean = false,
        progress: (String) -> Unit = {},
    ): Boolean = withContext(Dispatchers.IO) {
        var success = true
        success = success and downloadOne("country", dbipUrls("country"), countryFile, progress)
        success = success and downloadOne("asn", dbipUrls("asn"), asnFile, progress)
        if (downloadCity) {
            success = success and downloadOne("city", dbipUrls("city"), cityFile, progress)
        }
        if (success) {
            close()
            ensureLoaded()
            if (downloadCity) ensureCityLoaded()
        }
        success
    }

    /** db-ip publishes monthly; the current month may not be out yet, so fall back to the previous one. */
    private fun dbipUrls(kind: String): List<String> {
        val now = java.time.YearMonth.now()
        val urls = listOf(now, now.minusMonths(1)).map {
            "https://download.db-ip.com/free/dbip-$kind-lite-%04d-%02d.mmdb.gz".format(it.year, it.monthValue)
        }
        return if (kind == "city") {
            urls + "https://cdn.jsdelivr.net/npm/dbip-city-lite@latest/dbip-city-lite.mmdb.gz"
        } else urls
    }

    private suspend fun downloadOne(label: String, urls: List<String>, target: File, progress: (String) -> Unit): Boolean {
        val client = HostResolver.newClient()
        for (url in urls) {
            val gz = File(target.parentFile, "${target.name}.gz.tmp")
            val tmp = File(target.parentFile, "${target.name}.tmp")
            try {
                progress(label)
                val response = client.newRequest().apply {
                    setURL(url)
                    setUserAgent("BetterExclave/0.17 (GeoIP)")
                }.execute()
                response.writeTo(gz.canonicalPath)
                if (!gz.exists() || gz.length() < 1024) {
                    gz.delete()
                    continue
                }
                FileInputStream(gz).use { fin ->
                    GZIPInputStream(fin).use { input ->
                        FileOutputStream(tmp).use { output ->
                            input.copyTo(output)
                        }
                    }
                }
                gz.delete()
                if (target.exists()) target.delete()
                tmp.renameTo(target)
                client.close()
                return true
            } catch (e: Throwable) {
                Logs.w(e)
                gz.delete()
                tmp.delete()
            }
        }
        client.close()
        return false
    }

    suspend fun downloadCityMmdb(progress: (String) -> Unit = {}): Boolean = withContext(Dispatchers.IO) {
        val success = downloadOne("city", dbipUrls("city"), cityFile, progress)
        if (success) {
            try { cityReader?.close() } catch (_: Throwable) {}
            cityReader = null
            ensureCityLoaded()
        }
        success
    }
}
