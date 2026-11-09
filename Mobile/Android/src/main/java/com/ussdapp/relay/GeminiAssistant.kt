package com.ussdapp.relay

import android.content.Context
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import android.util.Base64
import org.json.JSONArray
import org.json.JSONObject
import java.io.ByteArrayOutputStream
import java.net.HttpURLConnection
import java.net.URL
import java.security.KeyStore
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec

/**
 * Explicitly invoked Gemini client. The key is encrypted with an Android
 * Keystore AES key and is sent only in the HTTPS request header.
 */
class GeminiAssistant(context: Context) {
    companion object {
        const val DEFAULT_MODEL = "gemini-2.5-flash"
        private const val KEY_ALIAS = "ussd.mobile.gemini.api-key"
        private const val PREFS = "secure_ai"
        private const val KEY_VALUE = "encrypted_api_key"
        private const val MAX_PROMPT_CHARS = 10000
        private const val MAX_RESPONSE_BYTES = 1024 * 1024
    }

    private val preferences = context.applicationContext
        .getSharedPreferences(PREFS, Context.MODE_PRIVATE)

    fun hasApiKey(): Boolean = preferences.contains(KEY_VALUE)

    fun saveApiKey(value: String) {
        val apiKey = value.trim()
        require(apiKey.length in 20..512) { "API key length is invalid." }
        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        cipher.init(Cipher.ENCRYPT_MODE, getOrCreateKey())
        val encrypted = cipher.doFinal(apiKey.toByteArray(Charsets.UTF_8))
        val stored = cipher.iv + encrypted
        check(preferences.edit().putString(KEY_VALUE, Base64.encodeToString(stored, Base64.NO_WRAP)).commit()) {
            "Could not securely save the API key."
        }
    }

    fun removeApiKey() {
        check(preferences.edit().remove(KEY_VALUE).commit()) { "Could not remove the saved API key." }
    }

    fun ask(prompt: String, completion: (Result<String>) -> Unit) {
        val userPrompt = prompt.trim()
        if (userPrompt.isEmpty() || userPrompt.length > MAX_PROMPT_CHARS) {
            completion(Result.failure(IllegalArgumentException("Prompt must contain 1 to 10000 characters.")))
            return
        }

        Thread({
            try {
                val apiKey = readApiKey()
                val response = generate(apiKey, userPrompt)
                completion(Result.success(response))
            } catch (error: Exception) {
                completion(Result.failure(error))
            }
        }, "ussd-gemini-request").start()
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

    private fun readApiKey(): String {
        val encoded = preferences.getString(KEY_VALUE, null)
            ?: throw IllegalStateException("Add your Gemini API key in AI settings first.")
        val stored = Base64.decode(encoded, Base64.NO_WRAP)
        require(stored.size > 12) { "Saved API key data is invalid; remove it and save the key again." }
        val iv = stored.copyOfRange(0, 12)
        val ciphertext = stored.copyOfRange(12, stored.size)
        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        cipher.init(Cipher.DECRYPT_MODE, getOrCreateKey(), GCMParameterSpec(128, iv))
        return String(cipher.doFinal(ciphertext), Charsets.UTF_8)
    }

    private fun generate(apiKey: String, prompt: String): String {
        val endpoint = URL(
            "https://generativelanguage.googleapis.com/v1beta/models/" +
                "$DEFAULT_MODEL:generateContent"
        )
        val requestBody = JSONObject()
            .put(
                "contents",
                JSONArray().put(
                    JSONObject().put(
                        "parts",
                        JSONArray().put(JSONObject().put("text", prompt))
                    )
                )
            )
            .put("generationConfig", JSONObject().put("maxOutputTokens", 1024))
            .toString()
            .toByteArray(Charsets.UTF_8)

        val connection = endpoint.openConnection() as HttpURLConnection
        try {
            connection.instanceFollowRedirects = false
            connection.requestMethod = "POST"
            connection.connectTimeout = 15000
            connection.readTimeout = 45000
            connection.setRequestProperty("Content-Type", "application/json; charset=utf-8")
            connection.setRequestProperty("Accept", "application/json")
            connection.setRequestProperty("x-goog-api-key", apiKey)
            connection.doOutput = true
            connection.outputStream.use { it.write(requestBody) }

            val status = connection.responseCode
            val input = if (status in 200..299) connection.inputStream else connection.errorStream
            if (input == null) throw IllegalStateException("AI provider returned HTTP $status with no response.")
            val bytes = input.use { readBounded(it) }
            if (status !in 200..299) {
                throw IllegalStateException("AI provider returned HTTP $status. Check the key, model access, and quota.")
            }
            val root = JSONObject(String(bytes, Charsets.UTF_8))
            val text = root.optJSONArray("candidates")
                ?.optJSONObject(0)
                ?.optJSONObject("content")
                ?.optJSONArray("parts")
                ?.optJSONObject(0)
                ?.optString("text")
                ?.trim()
                .orEmpty()
            if (text.isEmpty()) throw IllegalStateException("AI provider returned no text response.")
            return text
        } finally {
            connection.disconnect()
        }
    }

    private fun readBounded(input: java.io.InputStream): ByteArray {
        val output = ByteArrayOutputStream()
        val buffer = ByteArray(8192)
        var total = 0
        while (true) {
            val count = input.read(buffer)
            if (count < 0) break
            total += count
            if (total > MAX_RESPONSE_BYTES) {
                throw IllegalStateException("AI provider response exceeded the 1 MiB limit.")
            }
            output.write(buffer, 0, count)
        }
        return output.toByteArray()
    }
}
