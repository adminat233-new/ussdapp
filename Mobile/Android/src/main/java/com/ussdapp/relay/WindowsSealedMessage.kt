package com.ussdapp.relay
import java.math.BigInteger
import java.security.KeyFactory
import java.security.MessageDigest
import java.security.SecureRandom
import java.security.Signature
import java.security.SignatureException
import java.security.spec.RSAPublicKeySpec
import javax.crypto.Cipher
import javax.crypto.Mac
import javax.crypto.spec.IvParameterSpec
import javax.crypto.spec.SecretKeySpec

/**
 * Windows-compatible ECHATK sealed mail. This deliberately uses the existing
 * Windows envelope rather than inventing a relay payload the Windows app cannot
 * open. It provides offline confidentiality, not forward secrecy.
 */
object WindowsSealedMessage {
    private const val VERB = "ECHATK"
    private const val AES_BYTES = 16
    private const val MAC_BYTES = 32
    private const val IV_BYTES = 16
    private val random = SecureRandom()

    data class Opened(val from: String, val to: String, val text: String)

    fun fingerprint(publicXmlBase64: String): String {
        require(publicXmlBase64.length <= 8192)
        val digest = MessageDigest.getInstance("SHA-256")
            .digest(publicXmlBase64.toByteArray(Charsets.UTF_8))
        val hex = digest.take(8).joinToString("") { "%02X".format(it.toInt() and 0xff) }
        return hex.chunked(4).joinToString("-")
    }

    fun seal(identity: MobileIdentityCrypto, toNumber: String, toPublicXmlBase64: String, text: String): String {
        require(text.isNotEmpty() && text.length <= 10000)
        require(toNumber.matches(Regex("[0-9]{4,20}")))
        require(toPublicXmlBase64.length <= 8192)
        val ticks = BigInteger.valueOf(System.currentTimeMillis())
            .multiply(BigInteger.valueOf(10000L))
            .add(BigInteger("621355968000000000"))
            .toString()
        val body = "${identity.number}|$toNumber|$ticks|CHAT|$text".toByteArray(Charsets.UTF_8)
        val key = ByteArray(AES_BYTES + MAC_BYTES).also(random::nextBytes)
        val iv = ByteArray(IV_BYTES).also(random::nextBytes)
        val ciphertext = aesCtr(key.copyOfRange(0, AES_BYTES), body, iv)
        val tag = hmac(key.copyOfRange(AES_BYTES, key.size), iv + ciphertext).copyOf(IV_BYTES)
        val wrappedKey = rsaEncrypt(toPublicXmlBase64, key)
        val encoder = java.util.Base64.getEncoder()
        val box = encoder.encodeToString(wrappedKey + iv + tag + ciphertext)
        val signature = encoder.encodeToString(identity.sign("$VERB|$box"))
        return "$VERB|$box|$signature"
    }

    fun open(
        identity: MobileIdentityCrypto,
        expectedFrom: String,
        expectedTo: String,
        senderPublicXmlBase64: String,
        wire: String
    ): Opened? {
        if (wire.length > 65536 || senderPublicXmlBase64.length > 8192 ||
            !expectedFrom.matches(Regex("[0-9]{4,20}")) ||
            !expectedTo.matches(Regex("[0-9]{4,20}"))) return null
        val fields = wire.split('|', limit = 3)
        if (fields.size != 3 || fields[0] != VERB) return null
        val decoder = java.util.Base64.getDecoder()
        val signature = try { decoder.decode(fields[2]) } catch (_: Exception) { return null }
        val signer = try { decodePublicKey(senderPublicXmlBase64) } catch (_: Exception) { return null }
        val verifier = Signature.getInstance("SHA256withRSA")
        verifier.initVerify(signer)
        verifier.update("$VERB|${fields[1]}".toByteArray(Charsets.UTF_8))
        val signatureValid = try {
            verifier.verify(signature)
        } catch (_: SignatureException) {
            false
        }
        if (!signatureValid) return null

        val sealed = try { decoder.decode(fields[1]) } catch (_: Exception) { return null }
        val cipherBytes = identity.cipherBytes
        if (sealed.size < cipherBytes + IV_BYTES + IV_BYTES + 1) return null
        val wrapped = sealed.copyOfRange(0, cipherBytes)
        val key = try { identity.decryptOaep(wrapped) } catch (_: Exception) { return null }
        if (key.size != AES_BYTES + MAC_BYTES) return null
        val iv = sealed.copyOfRange(cipherBytes, cipherBytes + IV_BYTES)
        val tag = sealed.copyOfRange(cipherBytes + IV_BYTES, cipherBytes + IV_BYTES * 2)
        val ciphertext = sealed.copyOfRange(cipherBytes + IV_BYTES * 2, sealed.size)
        val wanted = hmac(key.copyOfRange(AES_BYTES, key.size), iv + ciphertext).copyOf(IV_BYTES)
        if (!MessageDigest.isEqual(tag, wanted)) return null
        val plain = String(aesCtr(key.copyOfRange(0, AES_BYTES), ciphertext, iv), Charsets.UTF_8)
        val body = plain.split('|', limit = 4)
        if (body.size != 4 || body[0] != expectedFrom || body[1] != expectedTo) return null
        if (body[3].length < 5 || !body[3].startsWith("CHAT|")) return null
        return Opened(body[0], body[1], body[3].substring(5))
    }

    fun verifyPublishedKey(number: String, publicXmlBase64: String, signatureBase64: String): Boolean {
        return try {
            if (!number.matches(Regex("[0-9]{4,20}")) ||
                publicXmlBase64.length > 8192 || signatureBase64.length > 2048) return false
            val key = decodePublicKey(publicXmlBase64)
            val signature = Signature.getInstance("SHA256withRSA")
            signature.initVerify(key)
            signature.update("PUBK|$number".toByteArray(Charsets.UTF_8))
            signature.verify(java.util.Base64.getDecoder().decode(signatureBase64))
        } catch (_: Exception) {
            false
        }
    }

    private fun rsaEncrypt(publicXmlBase64: String, value: ByteArray): ByteArray {
        val publicKey = decodePublicKey(publicXmlBase64)
        val cipher = Cipher.getInstance("RSA/ECB/OAEPWithSHA-1AndMGF1Padding")
        cipher.init(
            Cipher.ENCRYPT_MODE,
            publicKey,
            javax.crypto.spec.OAEPParameterSpec(
                "SHA-1", "MGF1", java.security.spec.MGF1ParameterSpec.SHA1,
                javax.crypto.spec.PSource.PSpecified.DEFAULT
            )
        )
        return cipher.doFinal(value)
    }

    private fun decodePublicKey(value: String): java.security.interfaces.RSAPublicKey {
        val xml = String(java.util.Base64.getDecoder().decode(value), Charsets.UTF_8)
        fun component(name: String): BigInteger {
            val match = Regex("<$name>([^<]+)</$name>").find(xml)
                ?: error("RSA public key is missing $name.")
            return BigInteger(1, java.util.Base64.getDecoder().decode(match.groupValues[1]))
        }
        return KeyFactory.getInstance("RSA").generatePublic(
            RSAPublicKeySpec(component("Modulus"), component("Exponent"))
        ) as java.security.interfaces.RSAPublicKey
    }

    private fun aesCtr(key: ByteArray, input: ByteArray, iv: ByteArray): ByteArray {
        val cipher = Cipher.getInstance("AES/CTR/NoPadding")
        cipher.init(Cipher.ENCRYPT_MODE, SecretKeySpec(key, "AES"), IvParameterSpec(iv))
        return cipher.doFinal(input)
    }

    private fun hmac(key: ByteArray, data: ByteArray): ByteArray {
        val mac = Mac.getInstance("HmacSHA256")
        mac.init(SecretKeySpec(key, "HmacSHA256"))
        return mac.doFinal(data)
    }
}
