import com.ussdapp.relay.MobileIdentityCrypto
import com.ussdapp.relay.WindowsSealedMessage
import java.security.KeyPair
import java.security.KeyPairGenerator
import java.security.Signature
import java.security.interfaces.RSAPublicKey
import java.security.spec.RSAKeyGenParameterSpec
import javax.crypto.Cipher

class TestIdentity(override val number: String, private val pair: KeyPair) : MobileIdentityCrypto {
    override val cipherBytes = 256
    override val publicKey: String
        get() {
            val key = pair.public as RSAPublicKey
            val xml = "<RSAKeyValue><Modulus>${key.modulus.toByteArray().let {
                java.util.Base64.getEncoder().encodeToString(if (it.first() == 0.toByte()) it.drop(1).toByteArray() else it)
            }}</Modulus><Exponent>${java.util.Base64.getEncoder().encodeToString(key.publicExponent.toByteArray())}</Exponent></RSAKeyValue>"
            return java.util.Base64.getEncoder().encodeToString(xml.toByteArray(Charsets.UTF_8))
        }

    override fun sign(value: String): ByteArray =
        Signature.getInstance("SHA256withRSA").run {
            initSign(pair.private)
            update(value.toByteArray(Charsets.UTF_8))
            sign()
        }

    override fun decryptOaep(ciphertext: ByteArray): ByteArray =
        Cipher.getInstance("RSA/ECB/OAEPWithSHA-1AndMGF1Padding").run {
            init(Cipher.DECRYPT_MODE, pair.private, javax.crypto.spec.OAEPParameterSpec(
                "SHA-1", "MGF1", java.security.spec.MGF1ParameterSpec.SHA1,
                javax.crypto.spec.PSource.PSpecified.DEFAULT
            ))
            doFinal(ciphertext)
        }
}

fun identity(number: String): TestIdentity {
    val generator = KeyPairGenerator.getInstance("RSA")
    generator.initialize(RSAKeyGenParameterSpec(2048, RSAKeyGenParameterSpec.F4))
    return TestIdentity(number, generator.generateKeyPair())
}

val alice = identity("7001000001")
val bob = identity("7001000002")
check(WindowsSealedMessage.fingerprint(alice.publicKey).matches(Regex("[0-9A-F]{4}(-[0-9A-F]{4}){3}")))
check(WindowsSealedMessage.verifyPublishedKey(
    alice.number,
    alice.publicKey,
    java.util.Base64.getEncoder().encodeToString(alice.sign("PUBK|${alice.number}"))
))
val wire = WindowsSealedMessage.seal(alice, bob.number, bob.publicKey, "cross-platform hello")
val opened = WindowsSealedMessage.open(bob, alice.number, bob.number, alice.publicKey, wire)
check(opened?.text == "cross-platform hello")
check(WindowsSealedMessage.open(bob, "7001000003", bob.number, alice.publicKey, wire) == null)
val fields = wire.split('|')
val badSignature = (if (fields[2][0] == 'A') "B" else "A") + fields[2].drop(1)
check(WindowsSealedMessage.open(
    bob, alice.number, bob.number, alice.publicKey, "${fields[0]}|${fields[1]}|$badSignature"
) == null)
check(WindowsSealedMessage.open(
    bob, alice.number, bob.number, alice.publicKey, "${fields[0]}|${fields[1]}|AA"
) == null)
val tamperedBox = java.util.Base64.getDecoder().decode(fields[1]).also {
    it[it.lastIndex] = (it.last().toInt() xor 1).toByte()
}
val tamperedBoxBase64 = java.util.Base64.getEncoder().encodeToString(tamperedBox)
val validSignatureBadMac = java.util.Base64.getEncoder()
    .encodeToString(alice.sign("ECHATK|$tamperedBoxBase64"))
check(WindowsSealedMessage.open(
    bob, alice.number, bob.number, alice.publicKey,
    "${fields[0]}|$tamperedBoxBase64|$validSignatureBadMac"
) == null)
println("WINDOWS ECHATK ENVELOPE CHECKS: PASS")
