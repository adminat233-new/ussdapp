package com.ussdapp.mobile

import android.Manifest
import android.app.Activity
import android.os.Bundle
import android.content.Intent
import android.content.pm.PackageManager
import android.graphics.Color
import android.graphics.drawable.GradientDrawable
import android.location.Location
import android.location.LocationListener
import android.location.LocationManager
import android.net.Uri
import android.os.Build
import android.os.Handler
import android.os.Looper
import android.provider.Settings
import android.speech.RecognizerIntent
import android.speech.tts.TextToSpeech
import android.view.Gravity
import android.view.View
import android.widget.Button
import android.widget.CheckBox
import android.widget.EditText
import android.widget.FrameLayout
import android.widget.LinearLayout
import android.widget.ScrollView
import android.widget.TextView
import androidx.core.content.FileProvider
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
    private lateinit var speakRepliesToggle: CheckBox
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
    private lateinit var trackerMapLinks: LinearLayout
    private lateinit var appsStatusView: TextView
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

        window.statusBarColor = Color.rgb(9, 15, 27)
        window.navigationBarColor = Color.rgb(9, 15, 27)

        val appRoot = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            setBackgroundColor(Color.rgb(9, 15, 27))
        }
        val appBar = LinearLayout(this).apply {
            orientation = LinearLayout.HORIZONTAL
            gravity = Gravity.CENTER_VERTICAL
            setPadding(dp(18), dp(14), dp(14), dp(14))
            setBackgroundColor(Color.rgb(16, 25, 41))
        }
        val brand = LinearLayout(this).apply { orientation = LinearLayout.VERTICAL }
        brand.addView(TextView(this).apply {
            text = "USSD Manager"
            textSize = 18f
            setTextColor(Color.rgb(238, 243, 251))
            setTypeface(typeface, android.graphics.Typeface.BOLD)
        })
        brand.addView(TextView(this).apply {
            text = "Communication  ·  Device care"
            textSize = 12f
            setTextColor(Color.rgb(160, 174, 195))
        })
        appBar.addView(brand, LinearLayout.LayoutParams(0, -2, 1f))
        appBar.addView(Button(this).apply {
            text = "Calls"
            isAllCaps = false
            textSize = 12f
            primaryAction()
            contentDescription = "Open calls, video, chat and file transfer"
            setOnClickListener {
                startActivity(Intent(this@MainActivity, CallActivity::class.java))
            }
        })
        appRoot.addView(appBar)

        val content = createPageContent()
        val chatContent = createPageContent()
        val trackerContent = createPageContent()
        addPageHeading(content, "Assistant", "Ask a question, use a local command, or manage your assistant settings.")
        addPageHeading(chatContent, "Secure messages", "Connect to your trusted relay before sending an encrypted message.")
        addPageHeading(trackerContent, "Apps", "Open Laptop Tracker for device management. Its own authentication, pairing, permissions, and privacy controls remain in effect.")

        val agentPanel = addSectionCard(content, "Agent workspace",
            "Ask a question or run a local assistant command. Requests are sent only when you submit them; this assistant cannot control devices.")
        wakeNameInput = EditText(this).apply {
            hint = "Voice wake name"
            setText(agent.wakeName)
            isSingleLine = true
        }
        val wakeNameRow = LinearLayout(this).apply {
            orientation = LinearLayout.HORIZONTAL
            gravity = Gravity.CENTER_VERTICAL
        }
        wakeNameRow.addView(wakeNameInput, LinearLayout.LayoutParams(0, -2, 1f).apply {
            rightMargin = dp(8)
        })
        wakeNameRow.addView(Button(this).apply {
            text = "Save wake name"
            isAllCaps = false
            minWidth = 0
            setPadding(dp(12), dp(8), dp(12), dp(8))
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
        }, LinearLayout.LayoutParams(-2, -2))
        agentPanel.addView(wakeNameRow)

        commandInput = EditText(this).apply {
            hint = "Type /agent help or enter a local command"
            isSingleLine = true
        }
        agentPanel.addView(commandInput)
        val commandActions = LinearLayout(this).apply {
            orientation = LinearLayout.HORIZONTAL
            gravity = Gravity.CENTER_VERTICAL
        }
        commandActions.addView(Button(this).apply {
            text = "Run command"
            isAllCaps = false
            primaryAction()
            setOnClickListener {
                val value = commandInput.text.toString()
                val prompt = agent.aiPromptForText(value)
                if (prompt != null) askAi(prompt) else showReply(agent.handleText(value))
                commandInput.text.clear()
            }
        }, LinearLayout.LayoutParams(0, -2, 1f).apply { rightMargin = dp(8) })
        commandActions.addView(Button(this).apply {
            text = "Speak command"
            isAllCaps = false
            setOnClickListener { requestVoiceInput() }
        }, LinearLayout.LayoutParams(0, -2, 1f))
        agentPanel.addView(commandActions)
        responseView = TextView(this).apply {
            text = "Ready. Try /agent help."
            textSize = 15f
            setTextColor(Color.rgb(229, 236, 247))
            setPadding(0, dp(10), 0, dp(8))
            setTextIsSelectable(true)
            background = GradientDrawable().apply {
                setColor(Color.rgb(10, 17, 29))
                cornerRadius = dp(10).toFloat()
                setStroke(dp(1), Color.rgb(42, 57, 78))
            }
        }
        agentPanel.addView(responseView)
        agentPanel.addView(Button(this).apply {
            text = "Speak response"
            isAllCaps = false
            setOnClickListener { speak(responseView.text.toString()) }
        })
        val speakReplies = CheckBox(this).apply {
            text = "Read AI responses aloud"
            isChecked = preferences.getBoolean("speak_replies", false)
            setTextColor(Color.rgb(160, 174, 195))
            setOnCheckedChangeListener { _, checked ->
                preferences.edit().putBoolean("speak_replies", checked).apply()
            }
        }
        speakRepliesToggle = speakReplies
        agentPanel.addView(speakReplies)
        val providerPanel = addSectionCard(content, "AI provider",
            "Use your own API key. It is stored on this device and sent only when you submit an AI prompt.")
        providerPanel.addView(TextView(this).apply {
            text = "AI model: ${GeminiAssistant.DEFAULT_MODEL}\nPrompts are sent to Google only when you ask. " +
                "A provider API key is required; any free quota is controlled by the provider."
            textSize = 12f
            setTextColor(Color.rgb(160, 174, 195))
            setPadding(0, dp(12), 0, dp(4))
        })
        apiKeyInput = EditText(this).apply {
            hint = "Gemini API key"
            inputType = android.text.InputType.TYPE_CLASS_TEXT or
                android.text.InputType.TYPE_TEXT_VARIATION_PASSWORD
            isSingleLine = true
        }
        providerPanel.addView(apiKeyInput)
        providerPanel.addView(Button(this).apply {
            text = "Save API key securely"
            isAllCaps = false
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
        providerPanel.addView(Button(this).apply {
            text = "Remove saved API key"
            isAllCaps = false
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
        agentPanel.addView(aiPromptInput)
        agentPanel.addView(Button(this).apply {
            text = "Ask AI"
            isAllCaps = false
            primaryAction()
            setOnClickListener {
                askAi(aiPromptInput.text.toString())
                aiPromptInput.text.clear()
            }
        })

        val relayPanel = addSectionCard(chatContent, "Relay connection",
            "Compatible with the Windows ECHATK format. The app contacts your relay only when you tap Connect. TLS certificate and hostname validation stay enabled.")
        relayHostInput = EditText(this).apply {
            hint = "Relay hostname or IP"
            isSingleLine = true
        }
        relayPanel.addView(relayHostInput)
        relayPortInput = EditText(this).apply {
            hint = "Relay TCP port"
            inputType = android.text.InputType.TYPE_CLASS_NUMBER
            isSingleLine = true
        }
        relayPanel.addView(relayPortInput)
        relayNumberInput = EditText(this).apply {
            hint = "Your app number"
            inputType = android.text.InputType.TYPE_CLASS_NUMBER
            isSingleLine = true
        }
        relayPanel.addView(relayNumberInput)
        relayTokenInput = EditText(this).apply {
            hint = "Relay registration token"
            inputType = android.text.InputType.TYPE_CLASS_TEXT or
                android.text.InputType.TYPE_TEXT_VARIATION_PASSWORD
            isSingleLine = true
        }
        relayPanel.addView(relayTokenInput)
        relayPanel.addView(Button(this).apply {
            text = "Connect to relay (TLS)"
            isAllCaps = false
            primaryAction()
            setOnClickListener { connectRelay() }
        })
        recipientInput = EditText(this).apply {
            hint = "Recipient app number"
            inputType = android.text.InputType.TYPE_CLASS_NUMBER
            isSingleLine = true
        }
        relayPanel.addView(recipientInput)
        chatInput = EditText(this).apply {
            hint = "Secure message"
            minLines = 2
            maxLines = 4
        }
        relayPanel.addView(chatInput)
        relayPanel.addView(Button(this).apply {
            text = "Send encrypted message"
            isAllCaps = false
            primaryAction()
            setOnClickListener { sendSecureMessage() }
        })
        relayEventsView = TextView(this).apply {
            text = "Secure chat is disconnected."
            setPadding(0, 8, 0, 12)
            setTextIsSelectable(true)
        }
        relayPanel.addView(relayEventsView)

        val trackerApps = addSectionCard(trackerContent, "Laptop Tracker",
            "The dedicated Laptop Tracker app manages device pairing, account access, permissions, and tracking. This launcher does not add remote shell or hidden device controls.")
        appsStatusView = TextView(this).apply {
            text = "Open Apps to launch Laptop Tracker. If it is not installed, Android will ask you to confirm installation."
            textSize = 13f
            setTextColor(Color.rgb(160, 174, 195))
            setPadding(0, dp(4), 0, dp(12))
        }
        trackerApps.addView(appsStatusView)
        trackerApps.addView(Button(this).apply {
            text = "Open Laptop Tracker"
            isAllCaps = false
            primaryAction()
            setOnClickListener { openLaptopTrackerApp() }
        })
        trackerApps.addView(TextView(this).apply {
            text = "The included installer is handled by Android's package installer and requires your confirmation."
            textSize = 12f
            setTextColor(Color.rgb(160, 174, 195))
            setPadding(0, dp(12), 0, 0)
        })
        val pages = listOf(content, chatContent, trackerContent).map { page ->
            ScrollView(this).apply {
                isFillViewport = true
                setBackgroundColor(Color.rgb(9, 15, 27))
                addView(page)
            }
        }
        val pageHost = FrameLayout(this)
        pages.forEachIndexed { index, page ->
            if (index != (state?.getInt("selected_page", 0) ?: 0)) page.visibility = View.GONE
            pageHost.addView(page, FrameLayout.LayoutParams(
                FrameLayout.LayoutParams.MATCH_PARENT,
                FrameLayout.LayoutParams.MATCH_PARENT
            ))
        }
        appRoot.addView(pageHost, LinearLayout.LayoutParams(
            LinearLayout.LayoutParams.MATCH_PARENT, 0, 1f
        ))

        val navBar = LinearLayout(this).apply {
            orientation = LinearLayout.HORIZONTAL
            gravity = Gravity.CENTER
            setPadding(dp(8), dp(8), dp(8), dp(8))
            setBackgroundColor(Color.rgb(16, 25, 41))
        }
        val navLabels = listOf("⌂\nAssistant", "✉\nMessages", "▦\nApps")
        val navButtons = navLabels.mapIndexed { index, label ->
            val destination = listOf("Assistant", "Messages", "Apps")[index]
            Button(this).apply {
                text = label
                isAllCaps = false
                textSize = 11f
                minHeight = dp(56)
                minimumHeight = dp(56)
                minWidth = 0
                contentDescription = "Show $destination"
                setPadding(dp(4), dp(4), dp(4), dp(4))
            }.also { button ->
                navBar.addView(button, LinearLayout.LayoutParams(0, -2, 1f).apply {
                    leftMargin = dp(4)
                    rightMargin = dp(4)
                })
            }
        }
        appRoot.addView(navBar)
        fun selectPage(index: Int) {
            val selected = index.coerceIn(0, pages.lastIndex)
            val changed = selected != selectedPage
            if (changed) {
                pages[selectedPage].animate().cancel()
                pages[selectedPage].visibility = View.GONE
                pages[selected].apply {
                    alpha = 0f
                    translationY = dp(8).toFloat()
                    visibility = View.VISIBLE
                    animate().alpha(1f).translationY(0f).setDuration(180).start()
                }
            }
            navButtons.forEachIndexed { buttonIndex, button ->
                val active = buttonIndex == selected
                button.setTextColor(if (active) Color.WHITE else Color.rgb(177, 190, 208))
                button.background = roundedSurface(
                    if (active) Color.rgb(49, 91, 206) else Color.rgb(22, 34, 52),
                    dp(12)
                )
                button.isSelected = active
            }
            selectedPage = selected
            if (selected == 2 && changed) openLaptopTrackerApp()
        }
        navButtons.forEachIndexed { index, button -> button.setOnClickListener { selectPage(index) } }
        setContentView(appRoot)
        selectPage(state?.getInt("selected_page", 0) ?: 0)
    }

    override fun onSaveInstanceState(outState: Bundle) {
        outState.putInt("selected_page", selectedPage)
        super.onSaveInstanceState(outState)
    }

    private var selectedPage = 0

    private fun createPageContent(): LinearLayout = LinearLayout(this).apply {
        orientation = LinearLayout.VERTICAL
        setPadding(dp(16), dp(20), dp(16), dp(20))
    }

    private fun addPageHeading(parent: LinearLayout, title: String, description: String) {
        parent.addView(TextView(this).apply {
            text = title
            textSize = 24f
            setTextColor(Color.rgb(238, 243, 251))
            setTypeface(typeface, android.graphics.Typeface.BOLD)
        })
        parent.addView(TextView(this).apply {
            text = description
            textSize = 13f
            setTextColor(Color.rgb(160, 174, 195))
            setPadding(0, dp(4), 0, dp(16))
        })
    }

    private fun roundedSurface(color: Int, radius: Int): GradientDrawable =
        GradientDrawable().apply {
            setColor(color)
            cornerRadius = radius.toFloat()
        }

    private fun Button.primaryAction() {
        background = getDrawable(R.drawable.button_primary)
        setTextColor(Color.WHITE)
        minHeight = dp(48)
        minimumHeight = dp(48)
    }

    private fun openLaptopTrackerApp() {
        try {
            val installed = packageManager.getLaunchIntentForPackage(LAPTOP_TRACKER_PACKAGE)
            if (installed != null) {
                appsStatusView.text = "Laptop Tracker is installed. Opening it now."
                startActivity(installed)
                return
            }

            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O &&
                !packageManager.canRequestPackageInstalls()) {
                appsStatusView.text =
                    "Allow USSD Manager to install apps in Android settings, then return and tap Open Laptop Tracker."
                startActivity(Intent(
                    Settings.ACTION_MANAGE_UNKNOWN_APP_SOURCES,
                    Uri.parse("package:$packageName")
                ))
                return
            }

            val destination = java.io.File(cacheDir, "apps/laptop-tracker.apk")
            destination.parentFile?.let { parent ->
                if (!parent.exists() && !parent.mkdirs()) {
                    throw java.io.IOException("Could not create the temporary installer directory.")
                }
            }
            assets.open(LAPTOP_TRACKER_APK_ASSET).use { input ->
                destination.outputStream().use { output -> input.copyTo(output) }
            }
            val uri = FileProvider.getUriForFile(this, "$packageName.fileprovider", destination)
            val installer = Intent(Intent.ACTION_INSTALL_PACKAGE).apply {
                data = uri
                addFlags(Intent.FLAG_GRANT_READ_URI_PERMISSION)
                putExtra(Intent.EXTRA_RETURN_RESULT, true)
                clipData = android.content.ClipData.newRawUri("Laptop Tracker installer", uri)
            }
            appsStatusView.text =
                "Laptop Tracker is not installed. Confirm installation in Android's package installer."
            startActivity(installer)
        } catch (error: Exception) {
            val message = "Could not open or install Laptop Tracker: ${error.message ?: "unknown error"}"
            if (::appsStatusView.isInitialized) appsStatusView.text = message
        }
    }

    companion object {
        private const val LAPTOP_TRACKER_PACKAGE = "com.find.tracker"
        private const val LAPTOP_TRACKER_APK_ASSET = "laptop-tracker.apk"
    }

    private fun addSectionCard(parent: LinearLayout, title: String, description: String): LinearLayout {
        val card = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            setPadding(dp(18), dp(16), dp(18), dp(14))
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
        }
        card.addView(TextView(this).apply {
            text = title
            textSize = 18f
            setTextColor(Color.rgb(238, 243, 251))
            setTypeface(typeface, android.graphics.Typeface.BOLD)
        })
        card.addView(TextView(this).apply {
            text = description
            textSize = 13f
            setTextColor(Color.rgb(160, 174, 195))
            setPadding(0, dp(5), 0, dp(8))
        })
        parent.addView(card)
        return card
    }

    private fun dp(value: Int): Int =
        (value * resources.displayMetrics.density + 0.5f).toInt()

    private fun addTrackerButton(
        parent: LinearLayout,
        label: String,
        request: (TrackerClient, String, String) -> TrackerReply
    ) {
        val button = Button(this).apply {
            text = label
            isAllCaps = false
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
                if (action == "Refresh status" && reply.ok) {
                    renderTrackerLocations(reply.body)
                }
            }
        }, "ussd-tracker-action").start()
    }

    private fun renderTrackerLocations(body: String) {
        trackerMapLinks.removeAllViews()
        try {
            val devices = JSONObject(body).optJSONArray("devices")
            val points = mutableListOf<Triple<String, Double, Double>>()
            var found = 0
            if (devices != null) {
                for (index in 0 until devices.length()) {
                    val device = devices.optJSONObject(index) ?: continue
                    val location = device.optJSONObject("location") ?: continue
                    val lat = location.optDouble("lat", Double.NaN)
                    val lng = location.optDouble("lng", Double.NaN)
                    if (!lat.isFinite() || !lng.isFinite() || lat !in -90.0..90.0 || lng !in -180.0..180.0) continue
                    val deviceId = device.optString("deviceId", "paired device")
                    val updatedAt = location.optLong("updatedAt", 0L)
                    val status = if (device.optBoolean("online", false)) "online" else "offline"
                    val lost = if (device.optBoolean("isLost", false)) " · marked lost" else ""
                    val timestamp = if (updatedAt > 0L) {
                        " · last report ${java.text.DateFormat.getDateTimeInstance().format(java.util.Date(updatedAt))}"
                    } else ""
                    trackerMapLinks.addView(TextView(this).apply {
                        text = "$deviceId · $status$lost$timestamp\n${"%.6f".format(java.util.Locale.US, lat)}, ${"%.6f".format(java.util.Locale.US, lng)}"
                        setTextColor(Color.rgb(160, 174, 195))
                        setPadding(0, dp(8), 0, dp(4))
                    })
                    points.add(Triple(deviceId, lat, lng))
                    trackerMapLinks.addView(Button(this).apply {
                        text = "Open last reported location in Maps"
                        isAllCaps = false
                        setOnClickListener {
                            val label = Uri.encode(deviceId)
                            val uri = Uri.parse("geo:$lat,$lng?q=$lat,$lng($label)")
                            try {
                                startActivity(Intent(Intent.ACTION_VIEW, uri))
                            } catch (error: android.content.ActivityNotFoundException) {
                                showTrackerResult("No map app is installed.", error.message ?: "")
                            }
                        }
                    })
                    found++
                }
            }
            if (points.size > 1) {
                val currentId = trackerDeviceInput.text.toString().trim()
                val origin = points.firstOrNull { it.first == currentId } ?: points[0]
                val destination = points.firstOrNull { it.first != origin.first }
                    ?: points.getOrNull(1)
                if (destination != null) {
                    val url = "https://www.google.com/maps/dir/?api=1&origin=${origin.second},${origin.third}" +
                        "&destination=${destination.second},${destination.third}"
                    trackerMapLinks.addView(Button(this).apply {
                        text = "Compare this device and a paired device in Maps"
                        isAllCaps = false
                        setOnClickListener {
                            try {
                                startActivity(Intent(Intent.ACTION_VIEW, Uri.parse(url)))
                            } catch (error: android.content.ActivityNotFoundException) {
                                showTrackerResult("No map app or browser is installed.", error.message ?: "")
                            }
                        }
                    }, 0)
                }
            }
            if (found == 0) {
                trackerMapLinks.addView(TextView(this).apply {
                    text = "No paired-device location has been reported. The device must share a location while it is available."
                    setTextColor(Color.rgb(160, 174, 195))
                    setPadding(0, dp(8), 0, dp(4))
                })
            }
        } catch (error: Exception) {
            showTrackerResult("Could not read paired-device location data.", error.message ?: "")
        }
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
        val shouldSpeak = speakResponse ||
            (::speakRepliesToggle.isInitialized && speakRepliesToggle.isChecked)
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
                    onSuccess = { answer -> showReply(AgentReply(answer), shouldSpeak) },
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
