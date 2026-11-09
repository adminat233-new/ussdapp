package com.ussdapp.relay

import java.io.File
import java.util.concurrent.ConcurrentLinkedQueue

data class ChatMessage(val to: String, val payload: String)

class OfflineQueue(private val file: File) {
    private val pending = ConcurrentLinkedQueue<ChatMessage>().apply {
        if (file.exists()) {
            file.readLines().forEach { line ->
                val split = line.indexOf('\t')
                if (split > 0) add(ChatMessage(line.substring(0, split), line.substring(split + 1)))
            }
        }
    }

    fun enqueue(message: ChatMessage) { pending.add(message); persist() }
    fun drain(send: (ChatMessage) -> Unit) {
        while (true) {
            val item = pending.poll() ?: break
            try { send(item) } catch (error: Exception) {
                pending.add(item)
                throw error
            }
        }
        persist()
    }
    private fun persist() {
        file.parentFile?.mkdirs()
        file.writeText(pending.joinToString("\n") { it.to + "\t" + it.payload })
    }
}

interface CallEngine {
    fun startVoice(peer: String)
    fun startVideo(peer: String)
    fun stop()
}

interface GroupCallEngine {
    fun join(room: String)
    fun leave(room: String)
    fun setMuted(muted: Boolean)
}

interface EncryptedFileTransfer {
    fun offer(peer: String, file: File)
    fun accept(id: String, destination: File)
    fun cancel(id: String)
}

interface NotificationGateway {
    fun show(title: String, body: String)
}
