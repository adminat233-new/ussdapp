package com.ussdapp.relay

import java.io.BufferedReader
import java.io.BufferedWriter
import java.io.Closeable
import java.io.InputStreamReader
import java.io.OutputStreamWriter
import java.net.InetSocketAddress
import java.net.Socket
import java.io.IOException
import javax.net.ssl.HttpsURLConnection
import javax.net.ssl.SSLPeerUnverifiedException
import javax.net.ssl.SSLSocket
import javax.net.ssl.SSLSocketFactory

/**
 * Minimal relay transport. UI, lifecycle, crypto, and media are intentionally
 * outside this class so network permission is only used after user action.
 */
class RelayClient(
    private val host: String,
    private val port: Int,
    private val identity: RelayIdentity,
    private val machineName: String
) : Closeable {
    private var socket: Socket? = null
    private var writer: BufferedWriter? = null
    private var reader: BufferedReader? = null
    @Volatile private var listening = false

    fun connect(timeoutMs: Int = 5000) {
        require(host.isNotBlank())
        require(port in 1..65535)
        val s = SSLSocketFactory.getDefault().createSocket() as SSLSocket
        try {
            s.connect(InetSocketAddress(host, port), timeoutMs)
            s.soTimeout = timeoutMs
            s.startHandshake()
            if (!HttpsURLConnection.getDefaultHostnameVerifier().verify(host, s.session)) {
                throw SSLPeerUnverifiedException("Relay certificate does not match $host")
            }
            s.soTimeout = 0
            socket = s
            writer = BufferedWriter(OutputStreamWriter(s.getOutputStream(), Charsets.UTF_8))
            reader = BufferedReader(InputStreamReader(s.getInputStream(), Charsets.UTF_8))
        } catch (error: Exception) {
            try { s.close() } catch (_: Exception) { }
            throw error
        }
    }

    fun register(token: String): String {
        requireConnected()
        require(token.isNotBlank())
        val proof = identity.signOwnsClaim()
        require(proof.isNotBlank())
        send("REG|${field(identity.number)}|${field(token)}|${field(machineName)}|" +
            "${field(identity.publicKey)}|${field(proof)}")
        val activeSocket = socket ?: error("relay is not connected")
        activeSocket.soTimeout = 5000
        return try {
            readRequired()
        } finally {
            activeSocket.soTimeout = 0
        }
    }

    fun keepAlive() {
        send("KA|")
    }

    fun sendMessage(to: String, line: String) {
        require(to.isNotBlank())
        require(line.startsWith("ECHAT|") || line.startsWith("ECHATK|") || line.startsWith("KEYX|") ||
            line.startsWith("KEYXOK|") || line.startsWith("CALL|") ||
            line == "CHATACK|")
        send("MSG|${field(to)}|${field(identity.number)}|$line")
    }

    fun sendControl(line: String) {
        require(line.startsWith("PUBK|") || line.startsWith("PKQ|"))
        send(line)
    }

    fun startListening(onLine: (String) -> Unit, onFailure: (Exception) -> Unit = {}) {
        check(!listening) { "relay listener already started" }
        requireConnected()
        listening = true
        Thread({
            try {
                while (listening) {
                    val line = reader?.readLine() ?: throw IOException("relay closed the connection")
                    onLine(line)
                }
            } catch (error: Exception) {
                if (listening) onFailure(error)
            } finally {
                listening = false
            }
        }, "ussd-mobile-relay-reader").apply { isDaemon = true }.start()
    }

    fun readLine(): String = readRequired()

    override fun close() {
        listening = false
        try {
            if (socket != null) send("QUIT|")
        } catch (_: Exception) {
        }
        try { reader?.close() } catch (_: Exception) {
        }
        try { writer?.close() } catch (_: Exception) {
        }
        try { socket?.close() } catch (_: Exception) {
        }
        reader = null
        writer = null
        socket = null
    }

    private fun send(line: String) {
        requireConnected()
        require(!line.contains('\n') && !line.contains('\r'))
        synchronized(this) {
            val w = writer ?: error("relay writer unavailable")
            w.write(line)
            w.newLine()
            w.flush()
        }
    }

    private fun readRequired(): String {
        requireConnected()
        return reader?.readLine() ?: error("relay closed the connection")
    }

    private fun requireConnected() {
        check(socket?.isConnected == true && socket?.isClosed == false) {
            "relay is not connected"
        }
    }

    private fun field(value: String): String {
        require(!value.contains('|') && !value.contains('\n') && !value.contains('\r'))
        return value
    }
}
