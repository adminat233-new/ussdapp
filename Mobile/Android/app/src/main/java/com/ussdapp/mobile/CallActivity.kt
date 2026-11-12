package com.ussdapp.mobile

import android.Manifest
import android.app.Activity
import android.content.Intent
import android.content.pm.PackageManager
import android.database.Cursor
import android.graphics.Color
import android.graphics.drawable.GradientDrawable
import android.net.Uri
import android.os.Bundle
import android.os.Looper
import android.provider.OpenableColumns
import android.view.Gravity
import android.view.View
import android.widget.Button
import android.widget.EditText
import android.widget.FrameLayout
import android.widget.GridLayout
import android.widget.LinearLayout
import android.widget.ScrollView
import android.widget.TextView
import org.json.JSONObject
import io.livekit.android.LiveKit
import io.livekit.android.events.RoomEvent
import io.livekit.android.events.collect
import io.livekit.android.renderer.SurfaceViewRenderer
import io.livekit.android.room.Room
import io.livekit.android.room.track.VideoTrack
import io.livekit.android.room.track.DataPublishReliability
import java.io.File
import java.io.FileOutputStream
import java.net.HttpURLConnection
import java.net.URL
import java.security.SecureRandom
import java.util.UUID
import javax.crypto.Cipher
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.SecretKeySpec
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.cancel
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

class CallActivity : Activity() {
    private val requestMediaPermissions = 61
    private val requestChooseFile = 62
    private val requestSaveFile = 63
    private val maxFileBytes = 50L * 1024L * 1024L
    private val chunkBytes = 6 * 1024
    private val dataTopic = "ussd.e2e.v1"
    private val scope = CoroutineScope(SupervisorJob() + Dispatchers.Main.immediate)

    private lateinit var apiInput: EditText
    private lateinit var nameInput: EditText
    private lateinit var inviteInput: EditText
    private lateinit var callStatus: TextView
    private lateinit var inviteView: TextView
    private lateinit var tiles: GridLayout
    private lateinit var chatLog: TextView
    private lateinit var chatInput: EditText
    private lateinit var cameraButton: Button
    private lateinit var microphoneButton: Button
    private lateinit var transferButton: Button
    private lateinit var saveIncomingButton: Button
    private var room: Room? = null
    private var eventJob: kotlinx.coroutines.Job? = null
    private var pendingAction: (() -> Unit)? = null
    private var cameraEnabled = false
    private var microphoneEnabled = true
    private var callKey: ByteArray? = null
    private var invitationCode = ""
    private val participants = LinkedHashMap<String, String>()
    private val remoteVideos = LinkedHashMap<String, Pair<String, VideoTrack>>()
    private val tileRenderers = LinkedHashMap<String, Pair<SurfaceViewRenderer, VideoTrack>>()
    private var activeIncomingFile: File? = null
    private var activeIncomingId: String? = null
    private var activeIncomingSize = 0L
    private var activeIncomingBytes = 0L
    private var completedIncomingFile: File? = null
    private var completedIncomingName = ""

    override fun onCreate(state: Bundle?) {
        super.onCreate(state)
        val preferences = getSharedPreferences("assistant", MODE_PRIVATE)
        window.statusBarColor = Color.rgb(9, 15, 27)
        window.navigationBarColor = Color.rgb(9, 15, 27)
        val root = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            setPadding(dp(16), dp(18), dp(16), dp(20))
            setBackgroundColor(Color.rgb(9, 15, 27))
        }
        root.addView(TextView(this).apply {
            text = "Calls and video"
            textSize = 24f
            setTextColor(Color.rgb(238, 243, 251))
            setTypeface(typeface, android.graphics.Typeface.BOLD)
        })
        root.addView(TextView(this).apply {
            text = "Create or join an invitation. Voice stays connected when video is toggled. Calls support up to eight people. Audio/video are encrypted in transit but are not app-level end-to-end encrypted yet; chat and files use the invitation key."
            textSize = 13f
            setTextColor(Color.rgb(160, 174, 195))
            setPadding(0, dp(6), 0, dp(14))
        })
        val setupPanel = sectionCard("Start or join a call")
        root.addView(setupPanel)
        apiInput = EditText(this).apply {
            hint = "Call service URL (https://api.your-domain)"
            isSingleLine = true
            setText(preferences.getString("call_api_url", ""))
        }
        setupPanel.addView(apiInput)
        nameInput = EditText(this).apply {
            hint = "Your display name"
            isSingleLine = true
            setText(preferences.getString("call_display_name", android.os.Build.MODEL ?: "Android"))
        }
        setupPanel.addView(nameInput)
        val createActions = LinearLayout(this).apply { orientation = LinearLayout.HORIZONTAL }
        createActions.addView(Button(this).apply {
            text = "Start voice call"
            isAllCaps = false
            primaryAction()
            setOnClickListener { requestMicrophone { createRoomAndJoin(false) } }
        }, LinearLayout.LayoutParams(0, LinearLayout.LayoutParams.WRAP_CONTENT, 1f))
        createActions.addView(Button(this).apply {
            text = "Start video call"
            isAllCaps = false
            primaryAction()
            setOnClickListener { requestCameraAndMicrophone { createRoomAndJoin(true) } }
        }, LinearLayout.LayoutParams(0, LinearLayout.LayoutParams.WRAP_CONTENT, 1f))
        setupPanel.addView(createActions)
        inviteView = TextView(this).apply {
            text = "Your invitation code appears here after creating a call."
            setTextIsSelectable(true)
            setPadding(0, 8, 0, 8)
        }
        setupPanel.addView(inviteView)
        setupPanel.addView(Button(this).apply {
            text = "Share invitation"
            isAllCaps = false
            setOnClickListener { shareInvitation() }
        })
        inviteInput = EditText(this).apply {
            hint = "Paste invitation code from a friend"
            isSingleLine = true
        }
        setupPanel.addView(inviteInput)
        setupPanel.addView(Button(this).apply {
            text = "Join call"
            isAllCaps = false
            primaryAction()
            setOnClickListener { requestMicrophone { joinInvitation(inviteInput.text.toString(), false) } }
        })
        val callPanel = sectionCard("In-call workspace")
        root.addView(callPanel)
        callStatus = TextView(this).apply {
            text = "Not in a call."
            setPadding(0, dp(8), 0, dp(8))
        }
        callPanel.addView(callStatus)

        val controls = LinearLayout(this).apply { orientation = LinearLayout.HORIZONTAL }
        microphoneButton = Button(this).apply {
            text = "Mute microphone"
            isAllCaps = false
            isEnabled = false
            setOnClickListener { toggleMicrophone() }
        }
        cameraButton = Button(this).apply {
            text = "Turn video on"
            isAllCaps = false
            isEnabled = false
            setOnClickListener { toggleCamera() }
        }
        controls.addView(microphoneButton, LinearLayout.LayoutParams(0, -2, 1f))
        controls.addView(cameraButton, LinearLayout.LayoutParams(0, -2, 1f))
        callPanel.addView(controls)

        tiles = GridLayout(this).apply {
            columnCount = 1
            useDefaultMargins = true
        }
        callPanel.addView(tiles)
        chatLog = TextView(this).apply {
            text = "In-call chat is end-to-end encrypted with the invitation's private key."
            setTextIsSelectable(true)
            setPadding(0, 8, 0, 8)
        }
        callPanel.addView(chatLog)
        chatInput = EditText(this).apply {
            hint = "Message people in this call"
        }
        callPanel.addView(chatInput)
        val chatActions = LinearLayout(this).apply { orientation = LinearLayout.HORIZONTAL }
        chatActions.addView(Button(this).apply {
            text = "Send encrypted chat"
            isAllCaps = false
            primaryAction()
            setOnClickListener { sendChat() }
        }, LinearLayout.LayoutParams(0, -2, 1f))
        transferButton = Button(this).apply {
            text = "Send encrypted file"
            isEnabled = false
            setOnClickListener {
                startActivityForResult(
                    Intent(Intent.ACTION_OPEN_DOCUMENT).apply {
                        addCategory(Intent.CATEGORY_OPENABLE)
                        type = "*/*"
                    },
                    requestChooseFile
                )
            }
        }
        chatActions.addView(transferButton, LinearLayout.LayoutParams(0, -2, 1f))
        callPanel.addView(chatActions)
        saveIncomingButton = Button(this).apply {
            text = "Save received file"
            setOnClickListener { chooseIncomingFileDestination() }
            visibility = View.GONE
        }
        callPanel.addView(saveIncomingButton)
        callPanel.addView(Button(this).apply {
            text = "Leave call"
            isAllCaps = false
            setOnClickListener { leaveCall() }
        })

        setContentView(ScrollView(this).apply {
            setBackgroundColor(Color.rgb(9, 15, 27))
            addView(root)
        })
        rebuildTiles()
    }

    private fun sectionCard(title: String): LinearLayout = LinearLayout(this).apply {
        orientation = LinearLayout.VERTICAL
        setPadding(dp(16), dp(14), dp(16), dp(14))
        background = GradientDrawable().apply {
            setColor(Color.rgb(17, 27, 43))
            cornerRadius = dp(16).toFloat()
            setStroke(dp(1), Color.rgb(42, 57, 78))
        }
        layoutParams = LinearLayout.LayoutParams(
            LinearLayout.LayoutParams.MATCH_PARENT,
            LinearLayout.LayoutParams.WRAP_CONTENT
        ).apply {
            bottomMargin = dp(14)
        }
        addView(TextView(this@CallActivity).apply {
            text = title
            textSize = 17f
            setTextColor(Color.rgb(238, 243, 251))
            setTypeface(typeface, android.graphics.Typeface.BOLD)
            setPadding(0, 0, 0, dp(10))
        })
    }

    private fun dp(value: Int): Int =
        (value * resources.displayMetrics.density + 0.5f).toInt()

    private fun Button.primaryAction() {
        background = getDrawable(R.drawable.button_primary)
        setTextColor(Color.WHITE)
        minHeight = dp(48)
        minimumHeight = dp(48)
    }

    private fun requestMicrophone(continuation: () -> Unit) {
        if (checkSelfPermission(Manifest.permission.RECORD_AUDIO) == PackageManager.PERMISSION_GRANTED) {
            continuation()
        } else {
            pendingAction = continuation
            requestPermissions(arrayOf(Manifest.permission.RECORD_AUDIO), requestMediaPermissions)
        }
    }

    private fun requestCameraAndMicrophone(continuation: () -> Unit) {
        val missing = arrayOf(Manifest.permission.RECORD_AUDIO, Manifest.permission.CAMERA)
            .filter { checkSelfPermission(it) != PackageManager.PERMISSION_GRANTED }
        if (missing.isEmpty()) continuation()
        else {
            pendingAction = continuation
            requestPermissions(missing.toTypedArray(), requestMediaPermissions)
        }
    }

    override fun onRequestPermissionsResult(
        requestCode: Int,
        permissions: Array<out String>,
        grantResults: IntArray
    ) {
        super.onRequestPermissionsResult(requestCode, permissions, grantResults)
        if (requestCode != requestMediaPermissions) return
        val action = pendingAction
        pendingAction = null
        if (grantResults.isNotEmpty() && grantResults.all { it == PackageManager.PERMISSION_GRANTED }) {
            action?.invoke()
        } else {
            setStatus("Microphone/camera permission was denied. No call media was started.")
        }
    }

    private fun createRoomAndJoin(withVideo: Boolean) {
        val api = validatedApiUrl() ?: return
        val displayName = validatedDisplayName() ?: return
        persistSettings(api, displayName)
        setStatus("Creating a private invitation…")
        scope.launch {
            try {
                val created = postJson(api, "/api/rooms", JSONObject())
                invitationCode = created.getString("invitationCode")
                val key = ByteArray(32).also { SecureRandom().nextBytes(it) }
                callKey = key
                val invite = invitationCode + ":" + encodeBase64Url(key)
                inviteView.text = "Private call invitation (share this whole code):\n$invite"
                joinWithCode(api, displayName, invitationCode, withVideo)
            } catch (error: Exception) {
                setStatus("Could not create call: ${error.message ?: "service unavailable"}")
            }
        }
    }

    private fun joinInvitation(raw: String, withVideo: Boolean) {
        val api = validatedApiUrl() ?: return
        val displayName = validatedDisplayName() ?: return
        val parts = raw.trim().split(':')
        if (parts.size != 2 || !parts[0].matches(Regex("[a-f0-9]{48}"))) {
            setStatus("Invitation format is invalid. Ask the caller to share the complete private invitation code.")
            return
        }
        val key = decodeBase64Url(parts[1])
        if (key == null || key.size != 32) {
            setStatus("Invitation's private key is invalid.")
            return
        }
        invitationCode = parts[0]
        callKey = key
        inviteView.text = "Private call invitation (share this whole code):\n${parts[0]}:${encodeBase64Url(key)}"
        persistSettings(api, displayName)
        scope.launch {
            joinWithCode(api, displayName, invitationCode, withVideo)
        }
    }

    private suspend fun joinWithCode(api: String, displayName: String, code: String, withVideo: Boolean) {
        try {
            setStatus("Joining call…")
            val body = JSONObject().put("invitationCode", code).put("displayName", displayName)
            val credentials = postJson(api, "/api/token", body)
            val newRoom = LiveKit.create(applicationContext)
            room = newRoom
            eventJob?.cancel()
            eventJob = scope.launch {
                newRoom.events.collect { event -> onRoomEvent(event) }
            }
            newRoom.connect(credentials.getString("serverUrl"), credentials.getString("token"))
            newRoom.localParticipant.setMicrophoneEnabled(true)
            microphoneEnabled = true
            if (withVideo) {
                newRoom.localParticipant.setCameraEnabled(true)
                cameraEnabled = true
            }
            microphoneButton.isEnabled = true
            cameraButton.isEnabled = true
            transferButton.isEnabled = true
            microphoneButton.text = "Mute microphone"
            cameraButton.text = if (cameraEnabled) "Turn video off" else "Turn video on"
            setStatus("Connected. Audio continues while video is switched on or off.")
            for (participant in newRoom.remoteParticipants.values) {
                val identity = participant.identity?.value ?: continue
                participants[identity] = participant.name.orEmpty().ifBlank { identity }
                for (publication in participant.trackPublications.values) {
                    val track = publication.track as? VideoTrack ?: continue
                    remoteVideos[identity] = participants.getValue(identity) to track
                }
            }
            rebuildTiles()
        } catch (error: CancellationException) {
            throw error
        } catch (error: Exception) {
            val failure = "Could not join call: ${error.message ?: "connection failed"}"
            leaveCall()
            setStatus(failure)
        }
    }

    private suspend fun onRoomEvent(event: RoomEvent) {
        when (event) {
            is RoomEvent.ParticipantConnected -> {
                val participant = event.participant
                val identity = participant.identity?.value ?: return
                participants[identity] = participant.name.orEmpty().ifBlank { identity }
                rebuildTiles()
            }
            is RoomEvent.ParticipantDisconnected -> {
                val identity = event.participant.identity?.value ?: return
                participants.remove(identity)
                remoteVideos.remove(identity)
                rebuildTiles()
            }
            is RoomEvent.TrackSubscribed -> {
                val track = event.track
                if (track is VideoTrack) {
                    val identity = event.participant.identity?.value ?: return
                    val name = event.participant.name.orEmpty().ifBlank { identity }
                    participants[identity] = name
                    remoteVideos[identity] = name to track
                    rebuildTiles()
                }
            }
            is RoomEvent.TrackUnsubscribed -> {
                val identity = event.participant.identity?.value ?: return
                remoteVideos.remove(identity)
                rebuildTiles()
            }
            is RoomEvent.DataReceived -> {
                if (event.topic == dataTopic) {
                    withContext(Dispatchers.IO) { receiveEncryptedData(event.data) }
                }
            }
            else -> { }
        }
    }

    private fun rebuildTiles() {
        if (!::tiles.isInitialized) return
        val liveRoom = room
        tileRenderers.values.forEach { (renderer, track) ->
            track.removeRenderer(renderer)
            renderer.release()
        }
        tileRenderers.clear()
        val all = LinkedHashMap<String, Pair<String, VideoTrack?>>()
        val localParticipant = liveRoom?.localParticipant
        val localVideo = if (cameraEnabled) {
            localParticipant?.trackPublications?.values
                ?.mapNotNull { it.track as? VideoTrack }
                ?.firstOrNull()
        } else {
            null
        }
        all["local"] = (localParticipant?.name.orEmpty()
            .ifBlank { nameInput.text.toString().ifBlank { "You" } }) to localVideo
        participants.forEach { (id, name) -> all[id] = name to remoteVideos[id]?.second }
        val count = all.size.coerceAtLeast(1)
        val columns = when {
            count == 1 -> 1
            count <= 4 -> 2
            else -> 3
        }
        tiles.removeAllViews()
        tiles.columnCount = columns
        val tileWidth = (resources.displayMetrics.widthPixels - 64) / columns
        all.forEach { (id, item) ->
            val frame = FrameLayout(this)
            frame.setBackgroundColor(0xff202a3a.toInt())
            val label = TextView(this).apply {
                text = item.first
                setTextColor(0xffffffff.toInt())
                setBackgroundColor(0xaa000000.toInt())
                setPadding(8, 4, 8, 4)
                gravity = Gravity.BOTTOM
            }
            val track = item.second
            if (track != null && liveRoom != null) {
                val renderer = SurfaceViewRenderer(this)
                liveRoom.initVideoRenderer(renderer)
                track.addRenderer(renderer)
                tileRenderers[id] = renderer to track
                frame.addView(renderer, FrameLayout.LayoutParams(-1, -1))
            } else {
                frame.setBackgroundColor(0xff202a3a.toInt())
            }
            frame.addView(label, FrameLayout.LayoutParams(-1, -2, Gravity.BOTTOM))
            tiles.addView(frame, GridLayout.LayoutParams().apply {
                width = tileWidth
                height = (tileWidth * 0.72).toInt()
                columnSpec = GridLayout.spec(GridLayout.UNDEFINED, 1f)
                rowSpec = GridLayout.spec(GridLayout.UNDEFINED, 1f)
                setMargins(4, 4, 4, 4)
            })
        }
    }

    private fun toggleMicrophone() {
        val liveRoom = room ?: return
        scope.launch {
            try {
                microphoneEnabled = !microphoneEnabled
                liveRoom.localParticipant.setMicrophoneEnabled(microphoneEnabled)
                microphoneButton.text = if (microphoneEnabled) "Mute microphone" else "Unmute microphone"
            } catch (error: Exception) {
                microphoneEnabled = !microphoneEnabled
                setStatus("Could not change microphone: ${error.message}")
            }
        }
    }

    private fun toggleCamera() {
        if (!cameraEnabled && checkSelfPermission(Manifest.permission.CAMERA) != PackageManager.PERMISSION_GRANTED) {
            requestCameraAndMicrophone { toggleCamera() }
            return
        }
        val liveRoom = room ?: return
        scope.launch {
            try {
                val enabled = !cameraEnabled
                liveRoom.localParticipant.setCameraEnabled(enabled)
                cameraEnabled = enabled
                cameraButton.text = if (enabled) "Turn video off" else "Turn video on"
                rebuildTiles()
                setStatus(if (enabled) "Video enabled; your voice call stayed connected." else "Video disabled; your voice call stayed connected.")
            } catch (error: Exception) {
                setStatus("Could not change video: ${error.message}")
            }
        }
    }

    private fun sendChat() {
        val message = chatInput.text.toString().trim()
        if (message.isEmpty()) return
        scope.launch {
            try {
                val payload = JSONObject().put("kind", "chat").put("text", message)
                publishEncrypted(payload)
                appendChat("You: $message")
                chatInput.text.clear()
            } catch (error: Exception) {
                setStatus("Could not send encrypted chat: ${error.message}")
            }
        }
    }

    private fun sendFile(uri: Uri) {
        if (room == null) return
        if (callKey == null) return setStatus("This call has no private invitation key.")
        val name = queryDisplayName(uri).take(100)
        scope.launch {
            val stagedFile = File(cacheDir, "call-send-${UUID.randomUUID()}.tmp")
            try {
                withContext(Dispatchers.IO) {
                    contentResolver.openInputStream(uri)?.use { input ->
                        FileOutputStream(stagedFile).use { output ->
                            val buffer = ByteArray(16 * 1024)
                            var total = 0L
                            while (true) {
                                val read = input.read(buffer)
                                if (read < 0) break
                                total += read
                                require(total <= maxFileBytes) { "Files are limited to 50 MB." }
                                output.write(buffer, 0, read)
                            }
                        }
                    } ?: error("Unable to read the selected file.")
                }
                val size = stagedFile.length()
                val id = UUID.randomUUID().toString()
                publishEncrypted(JSONObject().put("kind", "file-start").put("id", id)
                    .put("name", name).put("size", size))
                stagedFile.inputStream().use { input ->
                    val buffer = ByteArray(chunkBytes)
                    while (true) {
                        val read = withContext(Dispatchers.IO) { input.read(buffer) }
                        if (read < 0) break
                        val chunk = buffer.copyOf(read)
                        publishEncrypted(JSONObject().put("kind", "file-chunk").put("id", id)
                            .put("data", android.util.Base64.encodeToString(chunk, android.util.Base64.NO_WRAP)))
                    }
                }
                publishEncrypted(JSONObject().put("kind", "file-end").put("id", id))
                appendChat("You shared a file: $name")
                setStatus("Encrypted file sent: $name ($size bytes).")
            } catch (error: Exception) {
                setStatus("File was not sent: ${error.message ?: "transfer failed"}")
            } finally {
                stagedFile.delete()
            }
        }
    }

    private suspend fun publishEncrypted(payload: JSONObject) {
        val liveRoom = room ?: error("Not connected to a call.")
        val key = callKey ?: error("Call private key is missing.")
        val iv = ByteArray(12).also { SecureRandom().nextBytes(it) }
        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        cipher.init(Cipher.ENCRYPT_MODE, SecretKeySpec(key, "AES"), GCMParameterSpec(128, iv))
        cipher.updateAAD(invitationCode.toByteArray(Charsets.UTF_8))
        val encrypted = cipher.doFinal(payload.toString().toByteArray(Charsets.UTF_8))
        val envelope = JSONObject()
            .put("v", 1)
            .put("iv", android.util.Base64.encodeToString(iv, android.util.Base64.NO_WRAP))
            .put("ct", android.util.Base64.encodeToString(encrypted, android.util.Base64.NO_WRAP))
            .toString()
        require(envelope.toByteArray(Charsets.UTF_8).size < 14000) { "Message chunk exceeded the transport limit." }
        liveRoom.localParticipant.publishData(
            envelope.toByteArray(Charsets.UTF_8),
            reliability = DataPublishReliability.RELIABLE,
            topic = dataTopic
        ).getOrThrow()
    }

    private fun receiveEncryptedData(data: ByteArray) {
        try {
            val key = callKey ?: return
            val envelope = JSONObject(data.toString(Charsets.UTF_8))
            require(envelope.optInt("v") == 1)
            val iv = android.util.Base64.decode(envelope.getString("iv"), android.util.Base64.DEFAULT)
            val encrypted = android.util.Base64.decode(envelope.getString("ct"), android.util.Base64.DEFAULT)
            require(iv.size == 12 && encrypted.size <= 14000)
            val cipher = Cipher.getInstance("AES/GCM/NoPadding")
            cipher.init(Cipher.DECRYPT_MODE, SecretKeySpec(key, "AES"), GCMParameterSpec(128, iv))
            cipher.updateAAD(invitationCode.toByteArray(Charsets.UTF_8))
            val payload = JSONObject(String(cipher.doFinal(encrypted), Charsets.UTF_8))
            when (payload.getString("kind")) {
                "chat" -> appendChat("Friend: " + payload.getString("text").take(2000))
                "file-start" -> beginIncomingFile(payload)
                "file-chunk" -> appendIncomingChunk(payload)
                "file-end" -> finishIncomingFile(payload)
            }
        } catch (error: Exception) {
            appendChat("Rejected invalid or unauthenticated in-call data.")
        }
    }

    private fun beginIncomingFile(payload: JSONObject) {
        val id = payload.getString("id")
        val size = payload.getLong("size")
        require(id.matches(Regex("[a-fA-F0-9-]{36}")) && size in 0..maxFileBytes)
        activeIncomingFile?.delete()
        val file = File(cacheDir, "call-receive-$id.part")
        file.outputStream().use { }
        activeIncomingId = id
        activeIncomingSize = size
        activeIncomingBytes = 0
        activeIncomingFile = file
        completedIncomingName = payload.getString("name").replace(Regex("[\\\\/:*?\"<>|\\p{Cntrl}]"), "_").take(100)
        appendChat("Receiving encrypted file: $completedIncomingName")
    }

    private fun appendIncomingChunk(payload: JSONObject) {
        require(payload.getString("id") == activeIncomingId)
        val bytes = android.util.Base64.decode(payload.getString("data"), android.util.Base64.DEFAULT)
        val file = activeIncomingFile ?: error("No active file transfer.")
        require(bytes.size <= chunkBytes)
        require(activeIncomingBytes + bytes.size <= activeIncomingSize)
        FileOutputStream(file, true).use { it.write(bytes) }
        activeIncomingBytes += bytes.size
    }

    private fun finishIncomingFile(payload: JSONObject) {
        require(payload.getString("id") == activeIncomingId)
        require(activeIncomingBytes == activeIncomingSize) { "Received file size did not match." }
        completedIncomingFile = activeIncomingFile
        activeIncomingFile = null
        activeIncomingId = null
        runOnUiThread { saveIncomingButton.visibility = View.VISIBLE }
        setStatus("Encrypted file received: $completedIncomingName. Choose Save received file to keep it.")
    }

    private fun chooseIncomingFileDestination() {
        if (completedIncomingFile == null) return
        startActivityForResult(Intent(Intent.ACTION_CREATE_DOCUMENT).apply {
            addCategory(Intent.CATEGORY_OPENABLE)
            type = "*/*"
            putExtra(Intent.EXTRA_TITLE, completedIncomingName)
        }, requestSaveFile)
    }

    private fun shareInvitation() {
        val code = inviteView.text.toString().substringAfter(":\n", "")
        if (!code.contains(":")) {
            setStatus("Create a call before sharing an invitation.")
            return
        }
        startActivity(Intent.createChooser(Intent(Intent.ACTION_SEND).apply {
            type = "text/plain"
            putExtra(Intent.EXTRA_TEXT, "Join my private USSD Manager call:\n$code")
        }, "Share call invitation"))
    }

    private suspend fun postJson(api: String, path: String, body: JSONObject): JSONObject =
        withContext(Dispatchers.IO) {
            val connection = (URL(api.trimEnd('/') + path).openConnection() as HttpURLConnection).apply {
                requestMethod = "POST"
                connectTimeout = 10000
                readTimeout = 15000
                doOutput = true
                setRequestProperty("Content-Type", "application/json")
                setRequestProperty("Accept", "application/json")
            }
            try {
                connection.outputStream.use { it.write(body.toString().toByteArray(Charsets.UTF_8)) }
                val code = connection.responseCode
                val stream = if (code in 200..299) connection.inputStream else connection.errorStream
                val text = stream?.bufferedReader(Charsets.UTF_8)?.use { it.readText() } ?: ""
                if (code !in 200..299) {
                    val reason = try { JSONObject(text).optString("error") } catch (_: Exception) { "" }
                    error(reason.ifBlank { "HTTP $code" })
                }
                JSONObject(text)
            } finally {
                connection.disconnect()
            }
        }

    private fun validatedApiUrl(): String? {
        val raw = apiInput.text.toString().trim()
        val url = try { URL(raw) } catch (_: Exception) { null }
        if (url == null || url.protocol != "https" || url.host.isBlank()) {
            setStatus("Enter the HTTPS call service URL from the app administrator.")
            return null
        }
        return raw
    }

    private fun validatedDisplayName(): String? {
        val value = nameInput.text.toString().trim()
        if (value.isEmpty() || value.length > 32 || value.any { it.isISOControl() }) {
            setStatus("Enter a display name of 1-32 characters.")
            return null
        }
        return value
    }

    private fun persistSettings(api: String, name: String) {
        getSharedPreferences("assistant", MODE_PRIVATE).edit()
            .putString("call_api_url", api)
            .putString("call_display_name", name)
            .apply()
    }

    private fun queryDisplayName(uri: Uri): String {
        var result = "shared-file"
        val cursor: Cursor? = contentResolver.query(uri, arrayOf(OpenableColumns.DISPLAY_NAME), null, null, null)
        cursor?.use {
            if (it.moveToFirst()) result = it.getString(0) ?: result
        }
        return result.replace(Regex("[\\\\/:*?\"<>|\\p{Cntrl}]"), "_")
    }

    private fun encodeBase64Url(bytes: ByteArray): String =
        android.util.Base64.encodeToString(bytes, android.util.Base64.URL_SAFE or android.util.Base64.NO_PADDING or android.util.Base64.NO_WRAP)

    private fun decodeBase64Url(value: String): ByteArray? = try {
        android.util.Base64.decode(value, android.util.Base64.URL_SAFE or android.util.Base64.NO_PADDING or android.util.Base64.NO_WRAP)
    } catch (_: Exception) { null }

    private fun appendChat(line: String) {
        if (Looper.myLooper() != Looper.getMainLooper()) {
            runOnUiThread { appendChat(line) }
            return
        }
        val combined = chatLog.text.toString() + "\n" + line
        chatLog.text = if (combined.length > 12000) combined.takeLast(12000) else combined
    }

    private fun setStatus(message: String) {
        if (Looper.myLooper() != Looper.getMainLooper()) {
            runOnUiThread { setStatus(message) }
            return
        }
        if (::callStatus.isInitialized) callStatus.text = message
    }

    private fun leaveCall() {
        eventJob?.cancel()
        eventJob = null
        val oldRoom = room
        room = null
        val cleanupScope = CoroutineScope(SupervisorJob() + Dispatchers.Main.immediate)
        cleanupScope.launch {
            try {
                oldRoom?.disconnect()
            } catch (error: Exception) {
                setStatus("Call ended; disconnect reported: ${error.message}")
            } finally {
                cleanupScope.cancel()
            }
        }
        tileRenderers.values.forEach { (renderer, track) ->
            try { track.removeRenderer(renderer) } catch (_: Exception) { }
            try { renderer.release() } catch (_: Exception) { }
        }
        tileRenderers.clear()
        remoteVideos.clear()
        participants.clear()
        callKey?.fill(0)
        callKey = null
        invitationCode = ""
        inviteView.text = "Your invitation code appears here after creating a call."
        activeIncomingFile?.delete()
        activeIncomingFile = null
        activeIncomingId = null
        completedIncomingFile?.delete()
        completedIncomingFile = null
        if (::saveIncomingButton.isInitialized) saveIncomingButton.visibility = View.GONE
        cameraEnabled = false
        microphoneEnabled = true
        if (::microphoneButton.isInitialized) microphoneButton.isEnabled = false
        if (::cameraButton.isInitialized) cameraButton.isEnabled = false
        if (::transferButton.isInitialized) transferButton.isEnabled = false
        setStatus("Not in a call.")
        rebuildTiles()
    }

    override fun onActivityResult(requestCode: Int, resultCode: Int, data: Intent?) {
        super.onActivityResult(requestCode, resultCode, data)
        if (resultCode != RESULT_OK || data?.data == null) return
        when (requestCode) {
            requestChooseFile -> sendFile(data.data!!)
            requestSaveFile -> saveIncomingFile(data.data!!)
        }
    }

    private fun saveIncomingFile(destination: Uri) {
        val file = completedIncomingFile ?: return
        scope.launch {
            try {
                withContext(Dispatchers.IO) {
                    contentResolver.openOutputStream(destination)?.use { output ->
                        file.inputStream().use { input -> input.copyTo(output) }
                    } ?: error("Could not open selected destination.")
                }
                file.delete()
                completedIncomingFile = null
                saveIncomingButton.visibility = View.GONE
                setStatus("Saved $completedIncomingName.")
            } catch (error: Exception) {
                setStatus("Could not save received file: ${error.message}")
            }
        }
    }

    override fun onDestroy() {
        leaveCall()
        scope.cancel()
        super.onDestroy()
    }
}
