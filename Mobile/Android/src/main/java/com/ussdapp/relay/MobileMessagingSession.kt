package com.ussdapp.relay

import android.content.Context
import java.util.concurrent.ConcurrentHashMap

/**
 * Mobile-to-Windows secure text messaging using the existing relay REG,
 * PUBK/PKQ and ECHATK formats. Missing peer keys are requested, never bypassed.
 */
class MobileMessagingSession(
    context: Context,
    private val relay: RelayClient,
    private val identity: AndroidRelayIdentity,
    private val onEvent: (String) -> Unit
) {
    private val preferences = context.applicationContext.getSharedPreferences("trusted_peers", Context.MODE_PRIVATE)
    private val peerKeys = ConcurrentHashMap<String, String>()
    private val blockedPeers = ConcurrentHashMap.newKeySet<String>()
    private val pending = ArrayList<Pair<String, String>>()
    private val lock = Any()

    fun connect(token: String) {
        relay.connect()
        val verdict = relay.register(token)
        if (!verdict.startsWith("OK|")) error("Relay refused mobile registration: $verdict")
        val ownSignature = java.util.Base64.getEncoder()
            .encodeToString(identity.sign("PUBK|${identity.number}"))
        relay.sendControl("PUBK|${identity.number}|${identity.publicKey}|$ownSignature")
        relay.startListening(::receiveLine) { error ->
            onEvent("Relay connection failed: ${error.message ?: "connection closed"}")
        }
        onEvent("Registered #${identity.number}; encrypted messages use Windows-compatible ECHATK.")
    }

    fun sendChat(to: String, text: String): Boolean {
        require(to.matches(Regex("[0-9]{4,20}"))) { "Enter a valid app number." }
        require(text.isNotBlank() && text.length <= 10000) { "Message must contain 1 to 10000 characters." }
        check(to !in blockedPeers) { "This peer's identity key changed; messaging is blocked." }
        val key = peerKeys[to]
        if (key == null) {
            val queued = to to text
            synchronized(lock) {
                if (pending.size >= 20) error("Too many messages are waiting for peer keys.")
                pending.add(queued)
            }
            try {
                relay.sendControl("PKQ|$to")
            } catch (error: Exception) {
                synchronized(lock) { pending.remove(queued) }
                throw error
            }
            onEvent("Requesting #$to's signed identity key; message remains in memory until it arrives.")
            return true
        }
        relay.sendMessage(to, WindowsSealedMessage.seal(identity, to, key, text))
        onEvent("CHAT|You|$text")
        return true
    }

    fun close() = relay.close()

    private fun receiveLine(line: String) {
        val fields = line.split('|', limit = 4)
        when (fields.firstOrNull()) {
            "PKPUB" -> {
                if (fields.size < 4) return
                val number = fields[1]
                val publicKey = fields[2]
                if (!WindowsSealedMessage.verifyPublishedKey(number, publicKey, fields[3])) {
                    onEvent("Rejected an invalid identity-key proof for #$number.")
                    return
                }
                val old = preferences.getString(number, null)
                if (old != null && old != publicKey) {
                    peerKeys.remove(number)
                    blockedPeers.add(number)
                    discardPending(number)
                    val fingerprint = WindowsSealedMessage.fingerprint(publicKey)
                    onEvent("SECURITY WARNING: #$number's identity key changed to $fingerprint. Messages are blocked until verified.")
                    return
                }
                if (old == null) {
                    check(preferences.edit().putString(number, publicKey).commit()) {
                        "Could not persist the peer identity pin."
                    }
                    onEvent("First-seen identity key pinned for #$number: ${WindowsSealedMessage.fingerprint(publicKey)}. Verify this fingerprint out of band.")
                }
                blockedPeers.remove(number)
                peerKeys[number] = publicKey
                flushPending(number, publicKey)
            }
            "PKNONE" -> {
                val number = fields.getOrElse(1) { "?" }
                discardPending(number)
                onEvent("Relay has no published identity key for #$number; queued messages were not sent.")
            }
            "MSG" -> if (fields.size >= 4) receiveMessage(fields[2], fields[3])
            "ERR" -> onEvent("Relay error: $line")
            "UNDELIVERABLE" -> onEvent("Message could not be delivered: $line")
        }
    }

    private fun receiveMessage(from: String, wire: String) {
        if (from in blockedPeers) {
            onEvent("Rejected message from #$from because its identity key changed.")
            return
        }
        if (!wire.startsWith("ECHATK|")) {
            onEvent("Rejected unsealed or unsupported message content from #$from.")
            return
        }
        val senderKey = peerKeys[from] ?: preferences.getString(from, null)
        if (senderKey == null) {
            relay.sendControl("PKQ|$from")
            onEvent("Message from #$from held until its signed identity key arrives.")
            return
        }
        val opened = WindowsSealedMessage.open(
            identity,
            from,
            identity.number,
            senderKey,
            wire
        )
        if (opened == null) {
            onEvent("Rejected an unauthenticated or misaddressed message from #$from.")
            return
        }
        onEvent("CHAT|$from|${opened.text}")
        relay.sendMessage(from, "CHATACK|")
    }

    private fun flushPending(number: String, publicKey: String) {
        val ready = synchronized(lock) {
            val matches = pending.filter { it.first == number }
            pending.removeAll(matches.toSet())
            matches
        }
        for ((to, text) in ready) {
            try {
                relay.sendMessage(to, WindowsSealedMessage.seal(identity, to, publicKey, text))
                onEvent("CHAT|You|$text")
            } catch (error: Exception) {
                onEvent("Queued message to #$to could not be sent: ${error.message ?: "relay error"}")
            }
        }
    }

    private fun discardPending(number: String) {
        synchronized(lock) { pending.removeAll { it.first == number } }
    }
}
