package io.nekohasekai.sagernet.fmt.wireguard

import com.google.gson.JsonObject
import com.google.gson.JsonParser
import java.io.ByteArrayOutputStream
import java.util.zip.Inflater
import kotlin.io.encoding.Base64

/**
 * AmneziaWG parameters. Stored in [WireGuardBean.amnezia] the way they appear in an AmneziaWG .conf
 * [Interface] section ("Jc = 4"), and handed to the core as amneziawg-go UAPI keys ("jc" -> "4").
 */
object AmneziaWG {

    /** UAPI key to the spelling used in .conf files, in the order amneziawg-go expects them. */
    private val keys = linkedMapOf(
        "jc" to "Jc", "jmin" to "Jmin", "jmax" to "Jmax",
        "s1" to "S1", "s2" to "S2", "s3" to "S3", "s4" to "S4",
        "h1" to "H1", "h2" to "H2", "h3" to "H3", "h4" to "H4",
        "i1" to "I1", "i2" to "I2", "i3" to "I3", "i4" to "I4", "i5" to "I5",
        "header_protection_key" to "HeaderProtectionKey",
        "content_padding_addition" to "ContentPaddingAddition",
        "rekey_after_time" to "RekeyAfterTime",
        "rekey_timeout" to "RekeyTimeout",
        "reject_after_time" to "RejectAfterTime",
        "keepalive_timeout" to "KeepaliveTimeout",
        "max_handshake_attempts" to "MaxHandshakeAttempts",
        "random_trailers" to "RandomTrailers",
        "disable_cookies" to "DisableCookies",
    )

    // "HeaderProtectionKey", "header_protection_key" and "headerprotectionkey" all mean the same key
    private val byNormalized = keys.keys.associateBy { it.replace("_", "") }

    private fun normalize(key: String) = byNormalized[key.trim().lowercase().replace("_", "")]

    /**
     * Parses "Key = Value" lines into UAPI keys. Unknown keys are dropped, including the AWG 1.5
     * J1-J3 and Itime that current amneziawg-go rejects.
     */
    @JvmStatic
    fun parse(text: String?): Map<String, String> {
        val result = linkedMapOf<String, String>()
        text?.lineSequence()?.forEach { line ->
            val eq = line.indexOf('=')
            if (eq <= 0) return@forEach
            val key = normalize(line.substring(0, eq)) ?: return@forEach
            val value = line.substring(eq + 1).trim()
            if (value.isNotEmpty()) result[key] = value
        }
        return keys.keys.filter { it in result }.associateWith { result[it]!! }
    }

    /** UAPI values for the core. The header protection key is base64 in configs but hex in UAPI. */
    fun toUapi(text: String?): Map<String, String> = parse(text).mapValues { (key, value) ->
        when {
            key == "header_protection_key" && !isHex(value) -> Base64.decode(value).toHexString()
            key == "random_trailers" || key == "disable_cookies" -> value.lowercase()
            else -> value
        }
    }

    private fun isHex(s: String) = s.length % 2 == 0 && s.all { it in '0'..'9' || it in 'a'..'f' || it in 'A'..'F' }

    fun confKey(uapiKey: String) = keys[uapiKey] ?: uapiKey

    val uapiKeys: List<String> get() = keys.keys.toList()

    // A disabled profile keeps its parameters as commented-out lines, which parse() ignores.
    private const val DISABLED_PREFIX = "# "

    fun isEnabled(text: String?) = parse(text).isNotEmpty()

    /** Parameters regardless of whether they are currently switched off. */
    fun parseAll(text: String?) = parse(text?.lines()?.joinToString("\n") { it.removePrefix(DISABLED_PREFIX.trim()).trim() })

    fun build(params: Map<String, String>, enabled: Boolean): String {
        val text = format(params.filterValues { it.isNotBlank() })
        return if (enabled || text.isEmpty()) text else text.lines().joinToString("\n") { DISABLED_PREFIX + it }
    }

    /**
     * I1 "signature" packets sent before the handshake, imitating other protocols. Like Jc/Jmin/Jmax they
     * are client-side only (the server drops them), so they are safe to try. Empty = no I-packets.
     */
    val signaturePresets = linkedMapOf(
        "none" to "",
        // QUIC v1 Initial: long header, 8-byte DCID, no SCID/token, 1232-byte payload (same shape as WARP's)
        "QUIC" to "<b 0xc700000001><b 0x08><r 8><b 0x0000><b 0x44d0><r 1232>",
        // DNS query for www.apple.com A with a random transaction ID
        "DNS" to "<r 2><b 0x01000001000000000000><b 0x03777777056170706c6503636f6d00><b 0x00010001>",
        // STUN binding request: type, length 0, magic cookie, random transaction ID
        "STUN" to "<b 0x00010000><b 0x2112a442><r 12>",
        // SIP INVITE (as in public WARP AmneziaWG configs)
        "SIP" to "<b 0x494e56495445207369703a626f624062696c6f78692e636f6d205349502f322e300d0a5669613a205349502f322e302f55445020706333332e61746c616e74612e636f6d3b6272616e63683d7a39684734624b3737366173646864730d0a4d61782d466f7277617264733a2037300d0a546f3a20426f62203c7369703a626f624062696c6f78692e636f6d3e0d0a46726f6d3a20416c696365203c7369703a616c6963654061746c616e74612e636f6d3e3b7461673d313932383330313737340d0a43616c6c2d49443a20613834623463373665363637313040706333332e61746c616e74612e636f6d0d0a435365713a2033313431353920494e564954450d0a436f6e74656e742d4c656e6774683a20300d0a0d0a>",
    )

    /**
     * Fresh junk-packet settings. Only Jc/Jmin/Jmax are randomized: they are client-side only, while
     * S1-S4 and H1-H4 must match the server (plain WireGuard servers such as WARP need S = 0, H = 1..4).
     */
    fun randomJunk(): Map<String, String> {
        val random = java.security.SecureRandom()
        val jc = 3 + random.nextInt(8)         // 3..10 packets
        val jmin = 20 + random.nextInt(61)     // 20..80 bytes
        val jmax = (jmin + 20 + random.nextInt(231)).coerceAtMost(1280)
        return mapOf("jc" to jc.toString(), "jmin" to jmin.toString(), "jmax" to jmax.toString())
    }

    /** Back to the .conf form. */
    fun format(params: Map<String, String>): String =
        params.entries.joinToString("\n") { (key, value) -> "${confKey(key)} = $value" }

    /** Picks AmneziaWG keys out of a .conf [Interface] section or link query parameters. */
    fun collect(get: (String) -> String?): String {
        val params = linkedMapOf<String, String>()
        for ((uapi, conf) in keys) {
            val value = get(conf) ?: get(uapi) ?: get(uapi.replace("_", "")) ?: continue
            if (value.isNotBlank()) params[uapi] = value.trim()
        }
        return format(params)
    }

    /**
     * AmneziaVPN share link: vpn://<base64url of a Qt qCompress'ed JSON>. The JSON holds
     * containers[].<protocol>.last_config, itself a JSON string whose "config" is a .conf text.
     */
    fun parseVpnLink(link: String): List<WireGuardBean> {
        val payload = link.substringAfter("://").trim()
        val bytes = try {
            Base64.UrlSafe.withPadding(Base64.PaddingOption.ABSENT_OPTIONAL).decode(payload)
        } catch (_: IllegalArgumentException) {
            Base64.withPadding(Base64.PaddingOption.ABSENT_OPTIONAL).decode(payload)
        }
        val json = JsonParser.parseString(qUncompress(bytes)).asJsonObject
        val beans = mutableListOf<WireGuardBean>()
        val description = json.get("description")?.takeIf { it.isJsonPrimitive }?.asString
        for (container in json.getAsJsonArray("containers") ?: return beans) {
            for ((_, proto) in container.asJsonObject.entrySet()) {
                if (!proto.isJsonObject) continue
                val lastConfig = proto.asJsonObject.get("last_config") ?: continue
                val configJson = if (lastConfig.isJsonPrimitive) {
                    JsonParser.parseString(lastConfig.asString).asJsonObject
                } else lastConfig as? JsonObject ?: continue
                val conf = configJson.get("config")?.takeIf { it.isJsonPrimitive }?.asString ?: continue
                parseWireGuardConfig(conf).forEach { bean ->
                    if (!description.isNullOrBlank()) bean.name = description
                    beans.add(bean)
                }
            }
        }
        return beans
    }

    /** Qt qCompress: 4-byte big-endian uncompressed length, then a zlib stream. */
    private fun qUncompress(data: ByteArray): String {
        val inflater = Inflater()
        inflater.setInput(data, 4, data.size - 4)
        val out = ByteArrayOutputStream()
        val buf = ByteArray(8192)
        while (!inflater.finished()) {
            val n = inflater.inflate(buf)
            if (n == 0 && (inflater.needsInput() || inflater.needsDictionary())) break
            out.write(buf, 0, n)
        }
        inflater.end()
        return out.toString(Charsets.UTF_8.name())
    }
}
