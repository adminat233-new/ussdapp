package com.ussdapp.mobile

import android.Manifest
import android.app.Activity
import android.os.Bundle
import android.content.Intent
import android.content.pm.PackageManager
import android.location.Location
import android.location.LocationListener
import android.location.LocationManager
import android.os.Handler
import android.os.Looper
import android.speech.RecognizerIntent
import android.speech.tts.TextToSpeech
import android.widget.Button
import android.widget.EditText
import android.widget.LinearLayout
import android.widget.ScrollView
import android.widget.TextView
import org.json.JSONObject
import com.ussdapp.relay.AgentReply
import com.ussdapp.relay.AndroidRelayIdentity
import com.ussdapp.relay.GeminiAssistant
import com.ussdapp.relay.MobileAgent
import com.ussdapp.relay.MobileMessagingSession
import com.ussdapp.relay.RelayClient
import com.ussdapp.relay.TrackerClient
import com.ussdapp.relay.TrackerCredentialStore
import com.ussdapp.relay.TrackerReply
import java.net.URI
import java.util.Locale

/**
 * The voice assistant is local and user-triggered. No microphone or relay
 * connection is started until the user chooses the corresponding action.
 */
class MainActivity : Activity(), TextToSpeech.OnInitListener {
    private val requestAudioPermission = 41
    private val requestSpeechInput = 42
    private val requestLocationPermission = 43
    private lateinit var agent: MobileAgent
    private lateinit var wakeNameInput: EditText
    private lateinit var commandInput: EditText
    private lateinit var apiKeyInput: EditText
    private lateinit var aiPromptInput: EditText
    private lateinit var responseView: TextView
    private lateinit var relayEventsView: TextView
    private lateinit var relayHostInput: EditText
    private lateinit var relayPortInput: EditText
    private lateinit var relayNumberInput: EditText
    private lateinit var relayTokenInput: EditText
    private lateinit var recipientInput: EditText
    private lateinit var chatInput: EditText
    private lateinit var trackerUrlInput: EditText
    private lateinit var trackerPairInput: EditText
    private lateinit var trackerDeviceInput: EditText
    private lateinit var trackerStatusView: TextView
    private lateinit var trackerOutputView: TextView
    private lateinit var locationButton: Button
    private lateinit var ai: GeminiAssistant
    private val trackerCredentials by lazy { TrackerCredentialStore(this) }
    private val trackerButtons = mutableListOf<Button>()
    private val mainHandler = Handler(Looper.getMainLooper())
    private var trackerBusy = false
    private var locationListener: LocationListener? = null
    private var locationTimeout: Runnable? = null
    private var locationTargetUrl = ""
    private var locationTargetDeviceId = ""
    private var messaging: MobileMessagingSession? = null
    @Volatile private var relayConnectGeneration = 0
    private var speech: TextToSpeech? = null
    private var speechReady = false
    private var pendingSpeech: String? = null

    override fun onCreate(state: Bundle?) {
        super.onCreate(state)
        val preferences = getSharedPreferences("assistant", MODE_PRIVATE)
        agent = MobileAgent(preferences.getString("wake_name", "Ussd") ?: "Ussd")
        ai = GeminiAssistant(this)
        speech = TextToSpeech(this, this)

        val content = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            setPadding(32, 36, 32, 24)
        }
        content.addView(TextView(this).apply {
            text = "USSD Manager\nLocal voice assistant"
            textSize = 22f
        })
        content.addView(TextView(this).apply {
            text = "Voice recognition uses your installed Android speech service; offline " +
                "processing depends on that service. Nothing listens in the background."
            setPadding(0, 12, 0, 12)
        })
        content.addView(Button(this).apply {
            text = "Calls, video, chat and file transfer"
            setOnClickListener {
                startActivity(Intent(this@MainActivity, CallActivity::class.java))
            }
        })

        wakeNameInput = EditText(this).apply {
            hint = "Voice wake name"
            setText(agent.wakeName)
            isSingleLine = true
        }
        content.addView(wakeNameInput)
        content.addView(Button(this).apply {
            text = "Save wake name"
            setOnClickListener {
                val value = wakeNameInput.text.toString().trim()
                if (value.isBlank()) {
                    showReply(AgentReply("Wake name cannot be empty."))
                } else {
                    agent.wakeName = value
                    preferences.edit().putString("wake_name", value).apply()
                    showReply(AgentReply("Wake name saved as \"$value\"."))
                }
            }
        })

        commandInput = EditText(this).apply {
            hint = "Type /agent help"
            isSingleLine = true
        }
        content.addView(commandInput)
        content.addView(Button(this).apply {
            text = "Run /agent command"
            setOnClickListener {
                val value = commandInput.text.toString()
                val prompt = agent.aiPromptForText(value)
                if (prompt != null) {
                    askAi(prompt)
                } else {
                    showReply(agent.handleText(value))
                }
                commandInput.text.clear()
            }
        })
        content.addView(Button(this).apply {
            text = "Speak command"
            setOnClickListener { requestVoiceInput() }
        })
        content.addView(Button(this).apply {
            text = "Speak response"
            setOnClickListener { speak(responseView.text.toString()) }
        })
        content.addView(TextView(this).apply {
            text = "AI model: ${GeminiAssistant.DEFAULT_MODEL}\nPrompts are sent to Google only when you ask. " +
                "A provider API key is required; any free quota is controlled by the provider."
            setPadding(0, 20, 0, 4)
        })
        apiKeyInput = EditText(this).apply {
            hint = "Gemini API key"
            inputType = android.text.InputType.TYPE_CLASS_TEXT or
                android.text.InputType.TYPE_TEXT_VARIATION_PASSWORD
            isSingleLine = true
        }
        content.addView(apiKeyInput)
        content.addView(Button(this).apply {
            text = "Save API key securely"
            setOnClickListener {
                try {
                    ai.saveApiKey(apiKeyInput.text.toString())
                    apiKeyInput.text.clear()
                    showReply(AgentReply("API key encrypted and saved on this device."))
                } catch (error: Exception) {
                    showReply(AgentReply("Could not save API key: ${error.message ?: "storage error"}"))
                }
            }
        })
        content.addView(Button(this).apply {
            text = "Remove saved API key"
            setOnClickListener {
                try {
                    ai.removeApiKey()
                    apiKeyInput.text.clear()
                    showReply(AgentReply("Saved API key removed."))
                } catch (error: Exception) {
                    showReply(AgentReply("Could not remove API key: ${error.message ?: "storage error"}"))
                }
            }
        })
        aiPromptInput = EditText(this).apply {
            hint = "Ask the AI a question"
            minLines = 2
            maxLines = 5
            inputType = android.text.InputType.TYPE_CLASS_TEXT or
                android.text.InputType.TYPE_TEXT_FLAG_MULTI_LINE or
                android.text.InputType.TYPE_TEXT_FLAG_CAP_SENTENCES
        }
        content.addView(aiPromptInput)
        content.addView(Button(this).apply {
            text = "Ask AI"
            setOnClickListener {
                askAi(aiPromptInput.text.toString())
                aiPromptInput.text.clear()
            }
        })

        content.addView(TextView(this).apply {
            text = "Secure relay chat\nUses the Windows ECHATK format. Enter your relay endpoint and app registration details; the network is contacted only when you tap Connect."
            textSize = 18f
            setPadding(0, 24, 0, 8)
        })
        content.addView(TextView(this).apply {
            text = "Relay transport uses TLS with system certificate and hostname validation. Use a DNS name covered by the relay certificate; never bypass certificate warnings."
            textSize = 13f
            setPadding(0, 0, 0, 8)
        })
        relayHostInput = EditText(this).apply {
            hint = "Relay hostname or IP"
            isSingleLine = true
        }
        content.addView(relayHostInput)
        relayPortInput = EditText(this).apply {
            hint = "Relay TCP port"
            inputType = android.text.InputType.TYPE_CLASS_NUMBER
            isSingleLine = true
        }
        content.addView(relayPortInput)
        relayNumberInput = EditText(this).apply {
            hint = "Your app number"
            inputType = android.text.InputType.TYPE_CLASS_NUMBER
            isSingleLine = true
        }
        content.addView(relayNumberInput)
        relayTokenInput = EditText(this).apply {
            hint = "Relay registration token"
            inputType = android.text.InputType.TYPE_CLASS_TEXT or
                android.text.InputType.TYPE_TEXT_VARIATION_PASSWORD
            isSingleLine = true
        }
        content.addView(relayTokenInput)
        content.addView(Button(this).apply {
            text = "Connect to relay (TLS)"
            setOnClickListener { connectRelay() }
        })
        recipientInput = EditText(this).apply {
            hint = "Recipient app number"
            inputType = android.text.InputType.TYPE_CLASS_NUMBER
            isSingleLine = true
        }
        content.addView(recipientInput)
        chatInput = EditText(this).apply {
            hint = "Secure message"
            minLines = 2
            maxLines = 4
        }
        content.addView(chatInput)
        content.addView(Button(this).apply {
            text = "Send encrypted message"
            setOnClickListener { sendSecureMessage() }
        })
        relayEventsView = TextView(this).apply {
            text = "Secure chat is disconnected."
            setPadding(0, 8, 0, 12)
            setTextIsSelectable(true)
        }
        content.addView(relayEventsView)

        content.addView(TextView(this).apply {
            text = "Device tracking session"
            textSize = 18f
            setPadding(0, 24, 0, 8)
        })
        content.addView(TextView(this).apply {
            text = "Pair this device with your tracker service using authenticated, one-time credentials. Lost mode is a server-side status only and does not lock or command a device. Location is read only after you tap the one-time location button and grant foreground permission."
            textSize = 13f
            setPadding(0, 0, 0, 8)
        })
        trackerUrlInput = EditText(this).apply {
            hint = "Tracker service URL (https://...)"
            isSingleLine = true
            setText(preferences.getString("tracker_url", ""))
        }
        content.addView(trackerUrlInput)
        trackerPairInput = EditText(this).apply {
            hint = "Pairing code"
            isSingleLine = true
        }
        content.addView(trackerPairInput)
        trackerDeviceInput = EditText(this).apply {
            hint = "Device ID"
            isSingleLine = true
            setText(preferences.getString("tracker_device_id", ""))
        }
        content.addView(trackerDeviceInput)
        addTrackerButton(content, "Generate pairing code") { client, _, _ ->
            client.generatePair("phone")
        }
        addTrackerButton(content, "Verify pairing") { client, pair, _ ->
            client.verifyPair(pair)
        }
        addTrackerButton(content, "Refresh status") { client, _, device ->
            client.pairInfo(device)
        }
        addTrackerButton(content, "Send status-only check-in") { client, _, device ->
            client.heartbeat(device, null, null, "ussd-app-status")
        }
        locationButton = Button(this).apply {
            text = "Share current location once"
            setOnClickListener { requestLocationCheckin() }
        }
        content.addView(locationButton)
        addTrackerButton(content, "Enable lost mode") { client, _, device ->
            client.lostMode(device, true)
        }
        addTrackerButton(content, "Disable lost mode") { client, _, device ->
            client.lostMode(device, false)
        }
        trackerStatusView = TextView(this).apply {
            text = "Not connected."
            setPadding(0, 8, 0, 4)
        }
        content.addView(trackerStatusView)
        trackerOutputView = TextView(this).apply {
            text = ""
            setTextIsSelectable(true)
            setPadding(0, 4, 0, 12)
        }
        content.addView(trackerOutputView)

        responseView = TextView(this).apply {
            text = "Ready. Try /agent help."
            textSize = 16f
            setPadding(0, 20, 0, 12)
        }
        content.addView(responseView)
        setContentView(ScrollView(this).apply { addView(content) })
    }

    private fun addTrackerButton(
        parent: LinearLayout,
        label: String,
        request: (TrackerClient, String, String) -> TrackerReply
    ) {
        val button = Button(this).apply {
            text = label
            setOnClickListener { runTrackerAction(label, request) }
        }
        trackerButtons.add(button)
        parent.addView(button)
    }

    private fun runTrackerAction(
        action: String,
        request: (TrackerClient, String, String) -> TrackerReply
    ) {
        runTrackerAction(
            action,
            trackerUrlInput.text.toString().trim(),
            trackerPairInput.text.toString().trim(),
            trackerDeviceInput.text.toString().trim(),
            request
        )
    }

    private fun runTrackerAction(
        action: String,
        server: String,
        pair: String,
        device: String,
        request: (TrackerClient, String, String) -> TrackerReply
    ) {
        if (trackerBusy) return
        val needsPair = action == "Verify pairing"
        val needsDevice = action == "Send status-only check-in" ||
            action == "Refresh status" ||
            action == "Share current location once" ||
            action == "Enable lost mode" || action == "Disable lost mode"
        val uri = try { URI(server) } catch (_: Exception) { null }
        if (uri == null || uri.scheme != "https" || uri.host.isNullOrBlank() ||
            !uri.userInfo.isNullOrEmpty()) {
            showTrackerResult("Enter a valid HTTPS tracker URL.", "")
            return
        }
        if (needsPair && pair.isBlank()) {
            showTrackerResult("Enter the pairing code first.", "")
            return
        }
        val credentials = try {
            trackerCredentials.load()
        } catch (error: Exception) {
            showTrackerResult("Could not read the saved device credential.", error.message ?: "")
            return
        }
        val needsCredential = needsDevice
        if (needsCredential && credentials == null) {
            showTrackerResult("Pair this device before requesting authenticated tracker actions.", "")
            return
        }
        if (needsDevice && (device.isBlank() || credentials?.deviceId != device)) {
            showTrackerResult("The device ID must match this device's saved pairing.", "")
            return
        }

        getSharedPreferences("assistant", MODE_PRIVATE).edit()
            .putString("tracker_url", server)
            .putString("tracker_device_id", device)
            .apply()
        trackerBusy = true
        trackerButtons.forEach { it.isEnabled = false }
        showTrackerResult("$action in progress...", "")
        Thread({
            val reply = try {
                val client = TrackerClient(server, if (needsCredential) credentials?.token else null)
                request(client, pair, device).also {
                    if (it.ok && (action == "Generate pairing code" || action == "Verify pairing")) {
                        val payload = JSONObject(it.body)
                        val savedId = payload.getString("deviceId")
                        val savedToken = payload.getString("deviceToken")
                        trackerCredentials.save(savedId, savedToken)
                        runOnUiThread {
                            trackerDeviceInput.setText(savedId)
                            if (action == "Generate pairing code") {
                                trackerPairInput.setText(payload.getString("pairCode"))
                            }
                        }
                    }
                }
            } catch (error: Exception) {
                TrackerReply(false, 0, error.message ?: "Tracker request failed.")
            }
            runOnUiThread {
                trackerBusy = false
                trackerButtons.forEach { it.isEnabled = true }
                val heading = "$action ${if (reply.ok) "completed" else "failed"}" +
                    if (reply.status > 0) " (HTTP ${reply.status})." else "."
                showTrackerResult(heading, trackerDisplayBody(reply.body))
            }
        }, "ussd-tracker-action").start()
    }

    private fun requestLocationCheckin() {
        if (trackerBusy || locationListener != null) return
        val server = trackerUrlInput.text.toString().trim()
        val device = trackerDeviceInput.text.toString().trim()
        val uri = try { URI(server) } catch (_: Exception) { null }
        if (uri == null || uri.scheme != "https" || uri.host.isNullOrBlank() ||
            !uri.userInfo.isNullOrEmpty()) {
            showTrackerResult("Enter a valid HTTPS tracker URL.", "")
            return
        }
        if (device.isBlank()) {
            showTrackerResult("Enter the device ID first.", "")
            return
        }
        val credentials = try { trackerCredentials.load() } catch (error: Exception) {
            showTrackerResult("Could not read the saved device credential.", error.message ?: "")
            return
        }
        if (credentials == null || credentials.deviceId != device) {
            showTrackerResult("Pair this device before sharing a location.", "")
            return
        }
        getSharedPreferences("assistant", MODE_PRIVATE).edit()
            .putString("tracker_url", server)
            .putString("tracker_device_id", device)
            .apply()
        locationTargetUrl = server
        locationTargetDeviceId = device
        val fine = checkSelfPermission(Manifest.permission.ACCESS_FINE_LOCATION) ==
            PackageManager.PERMISSION_GRANTED
        val coarse = checkSelfPermission(Manifest.permission.ACCESS_COARSE_LOCATION) ==
            PackageManager.PERMISSION_GRANTED
        if (!fine && !coarse) {
            requestPermissions(
                arrayOf(Manifest.permission.ACCESS_FINE_LOCATION, Manifest.permission.ACCESS_COARSE_LOCATION),
                requestLocationPermission
            )
            return
        }
        startOneTimeLocationRequest()
    }

    @Suppress("DEPRECATION")
    private fun startOneTimeLocationRequest() {
        val manager = getSystemService(LOCATION_SERVICE) as LocationManager
        val providers = try {
            val providers = if (checkSelfPermission(Manifest.permission.ACCESS_FINE_LOCATION) ==
                PackageManager.PERMISSION_GRANTED) {
                listOf(LocationManager.GPS_PROVIDER, LocationManager.NETWORK_PROVIDER)
            } else {
                listOf(LocationManager.NETWORK_PROVIDER)
            }
            providers
                .filter { manager.isProviderEnabled(it) }
        } catch (error: Exception) {
            locationTargetUrl = ""
            locationTargetDeviceId = ""
            showTrackerResult("Could not check location providers: ${error.message}", "")
            return
        }
        if (providers.isEmpty()) {
            locationTargetUrl = ""
            locationTargetDeviceId = ""
            showTrackerResult("Location is unavailable. Turn on a location provider and try again.", "")
            return
        }

        showTrackerResult("Waiting for one location fix. Nothing is shared until the fix is sent.", "")
        locationButton.isEnabled = false
        trackerButtons.forEach { it.isEnabled = false }
        val handler = mainHandler
        val listener = object : LocationListener {
            override fun onLocationChanged(location: Location) {
                val targetUrl = locationTargetUrl
                val targetDevice = locationTargetDeviceId
                finishOneTimeLocationRequest(manager, handler, this)
                locationTargetUrl = ""
                locationTargetDeviceId = ""
                runTrackerAction("Share current location once", targetUrl, "", targetDevice) { client, _, device ->
                    client.heartbeat(
                        device, location.latitude, location.longitude,
                        "ussd-app-user-approved-${location.provider ?: "device"}"
                    )
                }
            }

            @Deprecated("Deprecated in Android")
            override fun onStatusChanged(provider: String?, status: Int, extras: android.os.Bundle?) { }
            override fun onProviderEnabled(provider: String) { }
            override fun onProviderDisabled(provider: String) { }
        }
        locationListener = listener
        locationTimeout = Runnable {
            finishOneTimeLocationRequest(manager, handler, listener)
            showTrackerResult("No location fix arrived within 30 seconds. Nothing was shared.", "")
        }
        try {
            for (provider in providers) {
                manager.requestSingleUpdate(provider, listener, Looper.getMainLooper())
            }
            handler.postDelayed(locationTimeout!!, 30000)
        } catch (error: SecurityException) {
            finishOneTimeLocationRequest(manager, handler, listener)
            showTrackerResult("Location permission is unavailable. Nothing was shared.", error.message ?: "")
        } catch (error: Exception) {
            finishOneTimeLocationRequest(manager, handler, listener)
            showTrackerResult("Could not request a location fix: ${error.message}", "")
        }
    }

    @Suppress("DEPRECATION")
    private fun finishOneTimeLocationRequest(
        manager: LocationManager,
        handler: Handler,
        listener: LocationListener
    ) {
        if (locationListener !== listener) return
        locationListener = null
        locationTimeout?.let { handler.removeCallbacks(it) }
        locationTimeout = null
        locationTargetUrl = ""
        locationTargetDeviceId = ""
        try {
            manager.removeUpdates(listener)
        } catch (_: SecurityException) {
            // Permission may have been revoked while the one-shot request was active.
        }
        if (::locationButton.isInitialized) locationButton.isEnabled = true
        if (!trackerBusy) trackerButtons.forEach { it.isEnabled = true }
    }

    private fun showTrackerResult(status: String, body: String) {
        if (::trackerStatusView.isInitialized) trackerStatusView.text = status
        if (::trackerOutputView.isInitialized) {
            trackerOutputView.text = if (body.length > 6000) body.take(6000) + "\n[response truncated]" else body
        }
    }

    private fun trackerDisplayBody(body: String): String {
        return try {
            val payload = JSONObject(body)
            if (payload.has("deviceToken")) {
                payload.put("deviceToken", "[stored securely]")
            }
            payload.toString(2)
        } catch (_: Exception) {
            if (body.contains("\"deviceToken\"")) "Credential response stored securely; details hidden." else body
        }
    }

    private fun connectRelay() {
        val host = relayHostInput.text.toString().trim()
        val port = relayPortInput.text.toString().toIntOrNull()
        val number = relayNumberInput.text.toString().trim()
        val token = relayTokenInput.text.toString()
        if (host.isBlank() || port == null || port !in 1..65535 ||
            !number.matches(Regex("[0-9]{4,20}")) || token.isBlank()) {
            appendRelayEvent("Enter a relay host, valid TCP port, 4-20 digit app number, and registration token.")
            return
        }
        val generation = ++relayConnectGeneration
        messaging?.close()
        messaging = null
        relayTokenInput.text.clear()
        appendRelayEvent("Connecting to $host:$port...")
        Thread({
            var pendingSession: MobileMessagingSession? = null
            try {
                val identity = AndroidRelayIdentity(number)
                val client = RelayClient(host, port, identity, android.os.Build.MODEL ?: "Android")
                val session = MobileMessagingSession(this, client, identity) { event ->
                    runOnUiThread {
                        if (generation == relayConnectGeneration) appendRelayEvent(event)
                    }
                }
                pendingSession = session
                session.connect(token)
                runOnUiThread {
                    if (generation == relayConnectGeneration) messaging = session else session.close()
                }
            } catch (error: Exception) {
                pendingSession?.close()
                runOnUiThread {
                    if (generation == relayConnectGeneration) {
                        appendRelayEvent("Secure relay connection failed: ${error.message ?: "unknown error"}")
                    }
                }
            }
        }, "ussd-mobile-connect").start()
    }

    private fun sendSecureMessage() {
        val to = recipientInput.text.toString().trim()
        val text = chatInput.text.toString()
        val session = messaging
        if (session == null) {
            appendRelayEvent("Connect to a relay before sending a message.")
            return
        }
        Thread({
            try {
                session.sendChat(to, text)
                runOnUiThread { chatInput.text.clear() }
            } catch (error: Exception) {
                runOnUiThread {
                    appendRelayEvent("Secure message was not sent: ${error.message ?: "unknown error"}")
                }
            }
        }, "ussd-mobile-send").start()
    }

    private fun appendRelayEvent(event: String) {
        if (!::relayEventsView.isInitialized) return
        val updated = relayEventsView.text.toString() + "\n" + event
        relayEventsView.text = if (updated.length > 20000) updated.takeLast(20000) else updated
    }

    private fun requestVoiceInput() {
        if (checkSelfPermission(Manifest.permission.RECORD_AUDIO) != PackageManager.PERMISSION_GRANTED) {
            requestPermissions(arrayOf(Manifest.permission.RECORD_AUDIO), requestAudioPermission)
            return
        }
        launchSpeechInput()
    }

    private fun launchSpeechInput() {
        val intent = Intent(RecognizerIntent.ACTION_RECOGNIZE_SPEECH).apply {
            putExtra(RecognizerIntent.EXTRA_LANGUAGE_MODEL, RecognizerIntent.LANGUAGE_MODEL_FREE_FORM)
            putExtra(RecognizerIntent.EXTRA_LANGUAGE, Locale.getDefault())
            putExtra(RecognizerIntent.EXTRA_PROMPT, "Say ${agent.wakeName}, then a command")
            putExtra(RecognizerIntent.EXTRA_PREFER_OFFLINE, true)
        }
        try {
            startActivityForResult(intent, requestSpeechInput)
        } catch (_: android.content.ActivityNotFoundException) {
            showReply(AgentReply("No compatible speech recognition service is installed."))
        }
    }

    override fun onRequestPermissionsResult(
        requestCode: Int,
        permissions: Array<out String>,
        grantResults: IntArray
    ) {
        super.onRequestPermissionsResult(requestCode, permissions, grantResults)
        if (requestCode == requestAudioPermission) {
            if (grantResults.isNotEmpty() && grantResults[0] == PackageManager.PERMISSION_GRANTED) {
                launchSpeechInput()
            } else {
                showReply(AgentReply("Microphone permission was denied. Voice input was not started."))
            }
        } else if (requestCode == requestLocationPermission) {
            if (checkSelfPermission(Manifest.permission.ACCESS_FINE_LOCATION) == PackageManager.PERMISSION_GRANTED ||
                checkSelfPermission(Manifest.permission.ACCESS_COARSE_LOCATION) == PackageManager.PERMISSION_GRANTED) {
                startOneTimeLocationRequest()
            } else {
                locationTargetUrl = ""
                locationTargetDeviceId = ""
                showTrackerResult("Location permission was denied. Nothing was read or shared.", "")
            }
        }
    }

    @Suppress("DEPRECATION")
    override fun onActivityResult(requestCode: Int, resultCode: Int, data: Intent?) {
        super.onActivityResult(requestCode, resultCode, data)
        if (requestCode != requestSpeechInput) return
        val recognized = if (resultCode == RESULT_OK) {
            data?.getStringArrayListExtra(RecognizerIntent.EXTRA_RESULTS)?.firstOrNull()
        } else null
        if (recognized.isNullOrBlank()) {
            showReply(AgentReply("No speech command was recognized."))
        } else {
            val prompt = agent.aiPromptForVoice(recognized)
            if (prompt != null) {
                askAi(prompt, speakResponse = true)
            } else {
                showReply(agent.handleVoice(recognized), speakResponse = true)
            }
        }
    }

    private fun askAi(prompt: String, speakResponse: Boolean = false) {
        if (prompt.isBlank()) {
            showReply(AgentReply("Enter a question or say a question after the wake name."))
            return
        }
        if (!ai.hasApiKey()) {
            showReply(AgentReply("Add a Gemini API key above. No shared or bundled API key is provided."))
            return
        }
        responseView.text = "Contacting ${GeminiAssistant.DEFAULT_MODEL}…"
        ai.ask(prompt) { result ->
            runOnUiThread {
                result.fold(
                    onSuccess = { answer -> showReply(AgentReply(answer), speakResponse) },
                    onFailure = { error ->
                        showReply(AgentReply("AI request failed: ${error.message ?: "unknown provider error"}"))
                    }
                )
            }
        }
    }

    private fun showReply(reply: AgentReply, speakResponse: Boolean = false) {
        responseView.text = reply.text
        if (speakResponse || reply.speech != null) {
            speak(reply.speech ?: reply.text)
        }
    }

    private fun speak(text: String) {
        if (!speechReady) {
            pendingSpeech = text
            return
        }
        val result = speech?.speak(text, TextToSpeech.QUEUE_FLUSH, null, "ussd-agent-response")
        if (result != TextToSpeech.SUCCESS && ::responseView.isInitialized) {
            responseView.text = "The installed text-to-speech service could not speak this response."
        }
    }

    override fun onInit(status: Int) {
        speechReady = status == TextToSpeech.SUCCESS
        if (speechReady) {
            val languageStatus = speech?.setLanguage(Locale.getDefault())
            if (languageStatus == TextToSpeech.LANG_MISSING_DATA ||
                languageStatus == TextToSpeech.LANG_NOT_SUPPORTED) {
                speechReady = false
                if (::responseView.isInitialized) {
                    responseView.text = "Text-to-speech is not available for the device language."
                }
                return
            }
            pendingSpeech?.let {
                pendingSpeech = null
                speak(it)
            }
        } else if (::responseView.isInitialized) {
            responseView.text = "The installed text-to-speech service could not be initialized."
        }
    }

    override fun onDestroy() {
        relayConnectGeneration++
        val activeLocationListener = locationListener
        if (activeLocationListener != null) {
            val manager = getSystemService(LOCATION_SERVICE) as LocationManager
            finishOneTimeLocationRequest(manager, mainHandler, activeLocationListener)
        }
        messaging?.close()
        messaging = null
        speech?.stop()
        speech?.shutdown()
        speech = null
        super.onDestroy()
    }
}
