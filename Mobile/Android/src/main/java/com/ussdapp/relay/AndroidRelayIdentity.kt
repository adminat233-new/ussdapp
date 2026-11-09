package com.ussdapp.relay

import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import android.util.Base64
import java.security.MessageDigest
import java.security.KeyPairGenerator
import java.security.KeyStore
import java.security.Signature
import java.security.interfaces.RSAPublicKey
import java.security.spec.RSAKeyGenParameterSpec

/** RSA-2048 identity compatible with the Windows app's RSA XML identity format. */
class AndroidRelayIdentity(
    number: String
) : RelayIdentity, MobileIdentityCrypto {
    companion object {
        private const val STORE = "AndroidKeyStore"
    }

    override val number: String = number.also {
        require(it.matches(Regex("[0-9]{4,20}"))) { "App number must contain 4 to 20 digits." }
    }
    private val alias = "ussd.mobile.identity.rsa2048." + MessageDigest.getInstance("SHA-256")
        .digest(number.toByteArray(Charsets.UTF_8))
        .take(12)
        .joinToString("") { "%02x".format(it) }
    private val keyStore: KeyStore = KeyStore.getInstance(STORE).apply { load(null) }
    private val privateKey = loadOrCreatePrivateKey()
    override val publicKey: String = encodePublicKey(publicKeyObject())
    override val cipherBytes: Int = 256

    override fun signOwnsClaim(): String = signRaw("OWNS|$number")

    override fun sign(value: String): ByteArray = signRawBytes(value)

    override fun decryptOaep(ciphertext: ByteArray): ByteArray {
        val cipher = javax.crypto.Cipher.getInstance("RSA/ECB/OAEPWithSHA-1AndMGF1Padding")
        cipher.init(
            javax.crypto.Cipher.DECRYPT_MODE,
            privateKey,
            javax.crypto.spec.OAEPParameterSpec(
                "SHA-1",
                "MGF1",
                java.security.spec.MGF1ParameterSpec.SHA1,
                javax.crypto.spec.PSource.PSpecified.DEFAULT
            )
        )
        return cipher.doFinal(ciphertext)
    }

    private fun signRaw(value: String): String = Base64.encodeToString(signRawBytes(value), Base64.NO_WRAP)

    private fun signRawBytes(value: String): ByteArray {
        val signer = Signature.getInstance("SHA256withRSA")
        signer.initSign(privateKey)
        signer.update(value.toByteArray(Charsets.UTF_8))
        return signer.sign()
    }

    private fun loadOrCreatePrivateKey(): java.security.PrivateKey {
        val existing = keyStore.getKey(alias, null) as? java.security.PrivateKey
        if (existing != null) return existing
        val generator = KeyPairGenerator.getInstance("RSA", STORE)
        generator.initialize(
            KeyGenParameterSpec.Builder(
                alias,
                KeyProperties.PURPOSE_SIGN or KeyProperties.PURPOSE_DECRYPT
            )
                .setAlgorithmParameterSpec(RSAKeyGenParameterSpec(2048, RSAKeyGenParameterSpec.F4))
                .setDigests(KeyProperties.DIGEST_SHA256, KeyProperties.DIGEST_SHA1)
                .setSignaturePaddings(KeyProperties.SIGNATURE_PADDING_RSA_PKCS1)
                .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_RSA_OAEP)
                .setRandomizedEncryptionRequired(true)
                .build()
        )
        generator.generateKeyPair()
        keyStore.load(null)
        return keyStore.getKey(alias, null) as? java.security.PrivateKey
            ?: error("Android Keystore did not return the generated identity key.")
    }

    private fun publicKeyObject(): RSAPublicKey {
        val certificate = keyStore.getCertificate(alias)
            ?: error("Android Keystore identity certificate is missing.")
        return certificate.publicKey as? RSAPublicKey
            ?: error("Android Keystore identity is not RSA.")
    }

    private fun encodePublicKey(key: RSAPublicKey): String {
        val xml = "<RSAKeyValue><Modulus>${unsignedBase64(key.modulus.toByteArray())}</Modulus>" +
            "<Exponent>${unsignedBase64(key.publicExponent.toByteArray())}</Exponent></RSAKeyValue>"
        return Base64.encodeToString(xml.toByteArray(Charsets.UTF_8), Base64.NO_WRAP)
    }

    private fun unsignedBase64(value: ByteArray): String {
        val unsigned = if (value.size > 1 && value[0] == 0.toByte()) value.copyOfRange(1, value.size) else value
        return Base64.encodeToString(unsigned, Base64.NO_WRAP)
    }
}
