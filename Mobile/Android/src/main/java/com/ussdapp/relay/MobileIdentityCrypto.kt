package com.ussdapp.relay

interface MobileIdentityCrypto {
    val number: String
    val publicKey: String
    val cipherBytes: Int
    fun sign(value: String): ByteArray
    fun decryptOaep(ciphertext: ByteArray): ByteArray
}
