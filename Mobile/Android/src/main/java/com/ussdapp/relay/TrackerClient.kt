package com.ussdapp.relay

import android.content.Context
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import android.util.Base64
import java.io.BufferedReader
import java.io.InputStreamReader
import java.net.HttpURLConnection
import java.net.URI
import java.net.URL
import java.security.KeyStore
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec

data class TrackerReply(val ok: Boolean, val status: Int, val body: String)
data class TrackerCredentials(val deviceId: String, val token: String)

/**
 * Consent-only bridge to laptop-tracker HTTP endpoints.
 * This client performs no stealth capture and no background startup by itself.
 */
class TrackerClient(baseUrl: String, private val token: String? = null) {
    private val root = baseUrl.trimEnd('/').also {
        val uri = URI(it)
        require(uri.scheme == "https" && !uri.host.isNullOrBlank() && uri.userInfo == null) {
            "Tracker URL must use HTTPS and must not contain embedded credentials."
        }
    }

    fun generatePair(deviceType: String): TrackerReply =
        post("/api/v2/pair/generate", """{"deviceType":"${esc(deviceType)}"}""")
    fun verifyPair(pairCode: String): TrackerReply =
        post("/api/v2/pair/verify", """{"pairCode":"${esc(pairCode)}","deviceType":"phone"}""")
    fun pairInfo(deviceId: String): TrackerReply =
        get("/api/v2/pair-info?deviceId=" + java.net.URLEncoder.encode(deviceId, "UTF-8"))
    fun heartbeat(deviceId: String, lat: Double?, lng: Double?, source: String): TrackerReply {
        val loc = if (lat != null && lng != null)
            """{"lat":$lat,"lng":$lng,"source":"${esc(source)}"}""" else "null"
        return post("/api/v2/heartbeat", """{"deviceId":"${esc(deviceId)}","location":$loc}""")
    }
    fun lostMode(deviceId: String, active: Boolean): TrackerReply =
        post("/api/v2/lost-mode", """{"deviceId":"${esc(deviceId)}","active":$active}""")

    fun revokeDevice(deviceId: String, targetDeviceId: String): TrackerReply =
        post("/api/v2/revoke-device",
            """{"deviceId":"${esc(deviceId)}","targetDeviceId":"${esc(targetDeviceId)}"}""")

    private fun get(path: String): TrackerReply {
        val conn = URL(root + path).openConnection() as HttpURLConnection
        conn.requestMethod = "GET"
        conn.instanceFollowRedirects = false
        setAuthorization(conn)
        conn.connectTimeout = 10000
        conn.readTimeout = 10000
        val code = conn.responseCode
        val body = read(conn)
        return TrackerReply(code in 200..299 && body.contains("\"success\":true"), code, body)
    }

    private fun post(path: String, body: String): TrackerReply {
        val conn = URL(root + path).openConnection() as HttpURLConnection
        conn.requestMethod = "POST"
        conn.instanceFollowRedirects = false
        conn.setRequestProperty("Content-Type", "application/json")
        conn.setRequestProperty("Accept", "application/json")
        setAuthorization(conn)
        conn.doOutput = true
        conn.connectTimeout = 10000
        conn.readTimeout = 10000
        conn.outputStream.use { it.write(body.toByteArray(Charsets.UTF_8)) }
        val code = conn.responseCode
        val text = read(conn)
        return TrackerReply(code in 200..299 && text.contains("\"success\":true"), code, text)
    }

    private fun read(conn: HttpURLConnection): String {
        val stream = try { conn.inputStream } catch (_: Exception) { conn.errorStream }
        if (stream == null) return ""
        return BufferedReader(InputStreamReader(stream, Charsets.UTF_8)).use { it.readText() }
    }

    private fun esc(s: String): String = s.replace("\\", "\\\\").replace("\"", "\\\"")

    private fun setAuthorization(conn: HttpURLConnection) {
        if (token != null) {
            require(token.isNotBlank()) { "Tracker device credential is empty." }
            conn.setRequestProperty("Authorization", "Bearer $token")
        }
    }
}

class TrackerCredentialStore(context: Context) {
    companion object {
        private const val KEY_ALIAS = "ussd.mobile.tracker.device-token"
        private const val PREFS = "secure_tracker"
        private const val DEVICE_ID = "device_id"
        private const val TOKEN = "encrypted_device_token"
    }

    private val appContext = context.applicationContext
    private val preferences = appContext.getSharedPreferences(PREFS, Context.MODE_PRIVATE)

    fun save(deviceId: String, token: String) {
        require(deviceId.isNotBlank() && token.isNotBlank()) { "Tracker credentials are incomplete." }
        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        cipher.init(Cipher.ENCRYPT_MODE, getOrCreateKey())
        val encrypted = cipher.iv + cipher.doFinal(token.toByteArray(Charsets.UTF_8))
        val committed = preferences.edit()
            .putString(DEVICE_ID, deviceId)
            .putString(TOKEN, Base64.encodeToString(encrypted, Base64.NO_WRAP))
            .commit()
        check(committed) { "Could not securely save tracker credentials." }
    }

    fun load(): TrackerCredentials? {
        val deviceId = preferences.getString(DEVICE_ID, null) ?: return null
        val encoded = preferences.getString(TOKEN, null)
            ?: throw IllegalStateException("Tracker credentials are incomplete. Pair this device again.")
        val stored = Base64.decode(encoded, Base64.NO_WRAP)
        require(stored.size > 12) { "Saved tracker credentials are invalid. Pair this device again." }
        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        cipher.init(Cipher.DECRYPT_MODE, getOrCreateKey(), GCMParameterSpec(128, stored.copyOfRange(0, 12)))
        val token = String(cipher.doFinal(stored.copyOfRange(12, stored.size)), Charsets.UTF_8)
        return TrackerCredentials(deviceId, token)
    }

    fun clear() {
        check(preferences.edit().remove(DEVICE_ID).remove(TOKEN).commit()) {
            "Could not remove saved tracker credentials."
        }
    }

    private fun getOrCreateKey(): SecretKey {
        val store = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }
        val existing = store.getKey(KEY_ALIAS, null) as? SecretKey
        if (existing != null) return existing
        val generator = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, "AndroidKeyStore")
        generator.init(
            KeyGenParameterSpec.Builder(
                KEY_ALIAS,
                KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT
            )
                .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
                .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
                .setRandomizedEncryptionRequired(true)
                .build()
        )
        return generator.generateKey()
    }
}
