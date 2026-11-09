package com.ussdapp.relay

/**
 * Identity operations are supplied by the platform keystore adapter.
 * The transport must never invent a token or send an unproved registration.
 */
interface RelayIdentity {
    val number: String
    val publicKey: String
    fun signOwnsClaim(): String
}
