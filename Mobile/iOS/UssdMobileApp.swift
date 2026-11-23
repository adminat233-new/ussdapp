import SwiftUI
import UIKit
import Speech
import AVFoundation
import CoreLocation

@main
struct UssdMobileApp: App {
    var body: some Scene {
        WindowGroup {
            ContentView()
        }
    }
}

struct ContentView: View {
    @State private var selectedTab = 0

    var body: some View {
        // All eight design panels are explicit tabs. iOS moves tabs five and
        // beyond into its automatic More list; each is still declared here.
        TabView(selection: $selectedTab) {
            NavigationStack {
                MobileDialerView()
            }
            .tabItem { Label("Dialer", systemImage: "phone") }
            .tag(0)

            NavigationStack {
                MobileContactsView()
            }
            .tabItem { Label("Contacts", systemImage: "person.crop.circle") }
            .tag(1)

            NavigationStack {
                MobileVideoCallView(selectedTab: $selectedTab)
            }
            .tabItem { Label("Video Call", systemImage: "video") }
            .tag(2)

            NavigationStack {
                MobileMessagingView()
            }
            .tabItem { Label("SMS", systemImage: "message") }
            .tag(3)

            NavigationStack {
                MobileSimManagerView()
            }
            .tabItem { Label("SIM Manager", systemImage: "sim.card") }
            .tag(4)

            NavigationStack {
                MobileUSSDView()
            }
            .tabItem { Label("USSD", systemImage: "asterisk") }
            .tag(5)

            NavigationStack {
                MobileAppsView(selectedTab: $selectedTab)
            }
            .tabItem { Label("Apps", systemImage: "square.grid.2x2") }
            .tag(6)

            NavigationStack {
                MobileAgentView(selectedTab: $selectedTab)
            }
            .tabItem { Label("Agent", systemImage: "sparkles") }
            .tag(7)
        }
    }
}

// MARK: - Video Call panel (wraps the real LiveKit call centre)

private struct MobileVideoCallView: View {
    @Binding var selectedTab: Int

    var body: some View {
        VStack(spacing: 0) {
            VStack(alignment: .leading, spacing: 6) {
                HStack(spacing: 8) {
                    Circle()
                        .fill(Color.green)
                        .frame(width: 9, height: 9)
                    Text("Video Call")
                        .font(.headline)
                    Spacer()
                    Button("Go to Dialer") { selectedTab = 0 }
                        .buttonStyle(.bordered)
                }
                Text("Voice and encrypted LAN/Internet video rooms. No call is active until you start or join one; live media needs a configured CallingServer.")
                    .font(.footnote)
                    .foregroundStyle(.white.opacity(0.85))
            }
            .padding(12)
            .background(Color(red: 0.043, green: 0.059, blue: 0.098))
            .foregroundStyle(.white)

            NativeCallView()
        }
        .navigationTitle("Video Call")
        .navigationBarTitleDisplayMode(.inline)
    }
}

// MARK: - SIM Manager panel

private struct MobileSimManagerView: View {
    @State private var simulatedConnected = false
    @State private var status = "Live SIM telemetry is not available on iOS."

    private let metrics: [(String, String, String)] = [
        ("SIM Status", "Ready (Active)", "Not Inserted"),
        ("Operator", "Telecel Ghana", "—"),
        ("Signal", "-67 dBm (4G LTE)", "—"),
        ("Network Reg", "Registered (Home)", "Unregistered"),
        ("Battery", "94% (AC Powered)", "—"),
        ("Phonebook", "142 SIM entries", "0 entries"),
        ("ICCID", "8923301000048291042", "—"),
        ("IMSI", "620020194827163", "—"),
        ("IMEI", "358942109482710", "—"),
        ("SIM Type", "USIM 4G", "—"),
        ("Carrier", "Telecel GH", "—"),
        ("SIM Slot", "Slot 1 (Primary)", "Slot 1 (Primary)")
    ]

    var body: some View {
        Form {
            Section {
                Text("SIM / MODEM INFORMATION")
                    .font(.headline)
                Text("auto-detected & auto-configured on connect")
                    .font(.caption.weight(.semibold))
                    .foregroundStyle(.blue)
                Text("Real-time hardware identity, carrier registration, and SIM slot diagnostics.")
                    .font(.footnote)
                    .foregroundStyle(.secondary)
            } header: {
                Text("Overview")
            }

            Section {
                Button(simulatedConnected ? "Stop SIM simulation" : "Simulate Connected SIM") {
                    simulatedConnected.toggle()
                    status = simulatedConnected
                        ? "Simulation on: example values only. No modem was connected."
                        : "Simulation off: no live modem is attached to this build."
                }
                Button("Refresh Now") {
                    status = "Telemetry view refreshed locally; no hardware was read."
                }
                Button("Reconfigure Modem") {
                    status = "AT init (ATE0, AT+CMGF=1, AT+CNMI, AT+CLIP) runs on a connected Windows modem, not on iOS."
                }
            } header: {
                Text("Connection")
            } footer: {
                Text(status)
            }

            Section {
                LazyVGrid(columns: [GridItem(.flexible()), GridItem(.flexible())], spacing: 10) {
                    ForEach(metrics, id: \.0) { metric in
                        VStack(alignment: .leading, spacing: 4) {
                            Text(metric.0.uppercased())
                                .font(.caption2.weight(.semibold))
                                .foregroundStyle(.secondary)
                            Text(simulatedConnected ? metric.1 : metric.2)
                                .font(.footnote.monospaced().weight(.semibold))
                                .lineLimit(2)
                                .minimumScaleFactor(0.7)
                        }
                        .frame(maxWidth: .infinity, alignment: .leading)
                        .padding(10)
                        .background(Color(uiColor: .secondarySystemGroupedBackground),
                                    in: RoundedRectangle(cornerRadius: 12))
                    }
                }
            } header: {
                Text("12-metric telemetry")
            } footer: {
                Text("iOS does not expose ICCID, IMSI or IMEI to third-party apps. Values shown while simulation is on are examples from the design, not live readings.")
            }

            Section {
                Label("Auto-configuration", systemImage: "shield.checkered")
                    .font(.subheadline.weight(.semibold))
                Text("On connect the modem is initialized (echo off, text SMS mode, SMS notifications, caller ID) and the SIM is identified (ICCID/IMSI/IMEI/operator). Every 20 s the SIM is re-checked — if the SIM card changes, the modem is re-configured automatically. Incoming SMS are stored and verification codes extracted.")
                    .font(.footnote)
                    .foregroundStyle(.secondary)
            } header: {
                Text("Auto-configuration policy")
            }
        }
        .navigationTitle("SIM Manager")
    }
}

// MARK: - Apps panel

private struct AppModule: Identifiable {
    enum Kind {
        case tracker, codes, apk, ussd, gateway, atLog
    }

    let id = UUID()
    let icon: String
    let title: String
    let detail: String
    let badge: String
    let footer: String
    let kind: Kind
    let connected: Bool
    let bridge: Bool
}

private struct MobileAppsView: View {
    @Binding var selectedTab: Int
    @State private var filter = 0
    @State private var status = ""

    private let modules: [AppModule] = [
        AppModule(icon: "shield.lefthalf.filled", title: "Laptop Tracker",
                  detail: "Local hardware geofencing, device tracking, and AI permission guardrails referenced by the Agent Console.",
                  badge: "Active", footer: "Local Guard v4.0", kind: .tracker,
                  connected: true, bridge: false),
        AppModule(icon: "key.fill", title: "OTP Extractor",
                  detail: "Automatically parses 4–8 digit 2FA verification codes from incoming GSM SMS and routes them to SMS Codes.",
                  badge: "Enabled", footer: "3 codes captured", kind: .codes,
                  connected: true, bridge: false),
        AppModule(icon: "app.badge", title: "Android Companion Bridge (.apk)",
                  detail: "Syncs contacts, VoIP LAN audio/video rooms, and SMS notifications between Windows .exe and Android .apk.",
                  badge: "LAN Ready", footer: "UDP/TCP 700-ID", kind: .apk,
                  connected: true, bridge: true),
        AppModule(icon: "clock.fill", title: "Bulk USSD & Balance Scheduler",
                  detail: "Automates periodic *124# airtime/data checks and carrier bundle renewals via MiFi Web API or AT commands.",
                  badge: "Standby", footer: "Interval: 30m", kind: .ussd,
                  connected: true, bridge: false),
        AppModule(icon: "wifi.router.fill", title: "Router & MiFi Admin Gateway",
                  detail: "Direct HTTP session diagnostics, WAN APN management, and client lease inspection for connected MiFi modems.",
                  badge: "192.168.100.1", footer: "HTTP API Ready", kind: .gateway,
                  connected: false, bridge: true),
        AppModule(icon: "terminal.fill", title: "AT Command & COM Terminal",
                  detail: "Low-level serial console for raw AT+CSQ, AT+CUSD, and AT+CMGF diagnostics with live trace logging.",
                  badge: "COM6 | 115200", footer: "Serial 8N1", kind: .atLog,
                  connected: false, bridge: true)
    ]

    private var filteredModules: [AppModule] {
        switch filter {
        case 1: return modules.filter { $0.connected }
        case 2: return modules.filter { $0.bridge }
        default: return modules
        }
    }

    var body: some View {
        Form {
            Section {
                HStack {
                    VStack(alignment: .leading, spacing: 3) {
                        Text("Companion Modules & Device Bridges")
                            .font(.headline)
                        Text("Integrated C# desktop services, Android LAN bridges, and security utilities.")
                            .font(.footnote)
                            .foregroundStyle(.secondary)
                    }
                    Spacer()
                    Label("6 Services Healthy", systemImage: "checkmark.circle.fill")
                        .font(.caption.weight(.semibold))
                        .foregroundStyle(.green)
                }
                Picker("Filter", selection: $filter) {
                    Text("All Modules").tag(0)
                    Text("Connected").tag(1)
                    Text("Device Bridges").tag(2)
                }
                .pickerStyle(.segmented)
            } header: {
                Text("Overview")
            }

            Section {
                ForEach(filteredModules) { module in
                    if module.kind == .tracker {
                        NavigationLink {
                            DeviceTrackingView()
                        } label: {
                            moduleCard(module)
                        }
                        .buttonStyle(.plain)
                    } else {
                        Button {
                            perform(module)
                        } label: {
                            moduleCard(module)
                        }
                        .buttonStyle(.plain)
                    }
                }
            } header: {
                Text("Modules")
            }

            if !status.isEmpty {
                Section {
                    Text(status)
                        .font(.footnote)
                } header: {
                    Text("Status")
                }
            }
        }
        .navigationTitle("Apps")
    }

    @ViewBuilder
    private func moduleCard(_ module: AppModule) -> some View {
        VStack(alignment: .leading, spacing: 8) {
            HStack {
                Image(systemName: module.icon)
                    .font(.headline)
                    .foregroundStyle(.blue)
                    .frame(width: 38, height: 38)
                    .background(Color.blue.opacity(0.12), in: RoundedRectangle(cornerRadius: 10))
                Spacer()
                Text(module.badge)
                    .font(.caption2.weight(.bold))
                    .foregroundStyle(.green)
            }
            Text(module.title)
                .font(.subheadline.weight(.semibold))
            Text(module.detail)
                .font(.footnote)
                .foregroundStyle(.secondary)
            HStack {
                Text(module.footer)
                    .font(.caption2.monospaced())
                    .foregroundStyle(.secondary)
                Spacer()
                Text(module.kind == .tracker ? "Configure ›" : actionTitle(module) + " ›")
                    .font(.caption.weight(.semibold))
                    .foregroundStyle(.blue)
            }
        }
        .padding(12)
        .background(Color(uiColor: .secondarySystemGroupedBackground),
                    in: RoundedRectangle(cornerRadius: 14))
    }

    private func actionTitle(_ module: AppModule) -> String {
        switch module.kind {
        case .codes: return "View Codes"
        case .apk: return "Preview .apk"
        case .ussd: return "Open USSD"
        case .gateway: return "Ping Gateway"
        case .atLog: return "Open AT Log"
        case .tracker: return "Configure"
        }
    }

    private func perform(_ module: AppModule) {
        switch module.kind {
        case .codes:
            selectedTab = 3
            status = "Opened SMS. Verification codes appear in your messages when received."
        case .apk:
            status = "The Android .apk is produced from the Android project; this iOS build cannot preview it."
        case .ussd:
            selectedTab = 5
            status = "Opened USSD. No balance check was sent automatically."
        case .gateway:
            selectedTab = 5
            status = "Gateway ping needs a configured MiFi HTTP endpoint; none is set here. USSD is open for manual checks."
        case .atLog:
            status = "AT/COM terminals need the Windows desktop app; iOS has no COM ports."
        case .tracker:
            break
        }
    }
}

// MARK: - Agent panel

private struct AgentChatLine: Identifiable {
    let id = UUID()
    let role: String
    let title: String?
    let text: String
}

private struct MobileAgentView: View {
    @Binding var selectedTab: Int
    @StateObject private var assistant = MobileAgent()
    @State private var prompt = ""
    @State private var aiPrompt = ""
    @State private var apiKey = ""
    @State private var readAloud = true
    @State private var showAISettings = false
    @State private var showTracker = false
    @State private var status = ""
    @State private var lines: [AgentChatLine] = [
        AgentChatLine(
            role: "assistant",
            title: "USSD Manager Pro Assistant",
            text: "Hello! I can execute safe local workspace navigation (for example \"Run USSD *124#\", \"Check SIM status\", \"Open SMS codes\") right away, or answer full natural-language queries once enabled in Settings > AI."
        )
    ]

    var body: some View {
        VStack(spacing: 0) {
            VStack(alignment: .leading, spacing: 10) {
                HStack(alignment: .top, spacing: 10) {
                    Image(systemName: "sparkles")
                        .font(.title3)
                        .foregroundStyle(.blue)
                    VStack(alignment: .leading, spacing: 3) {
                        HStack(spacing: 8) {
                            Text("Agent panel")
                                .font(.headline)
                            Text("Local Commands Only")
                                .font(.caption2.weight(.bold))
                                .foregroundStyle(.orange)
                                .padding(.horizontal, 6)
                                .padding(.vertical, 3)
                                .background(Color.orange.opacity(0.12),
                                            in: Capsule())
                        }
                        Text("Your local and AI assistant")
                            .font(.footnote)
                            .foregroundStyle(.secondary)
                    }
                    Spacer()
                }

                Text("Ask the configured AI assistant, use safe local navigation commands, or read a response aloud. Prompts are sent only when you tap Send. Device tracking and permissions stay in Laptop Tracker.")
                    .font(.footnote)
                    .foregroundStyle(.secondary)

                Toggle("Read AI responses aloud", isOn: $readAloud)
                    .font(.footnote)

                HStack(spacing: 8) {
                    Image(systemName: "exclamationmark.triangle.fill")
                        .foregroundStyle(.orange)
                    Text("Configure and enable the AI assistant in Settings > AI first.")
                        .font(.footnote)
                        .foregroundStyle(.orange)
                    Spacer()
                    Button("Open Settings > AI") { showAISettings = true }
                        .buttonStyle(.borderedProminent)
                        .font(.caption)
                }
                .padding(10)
                .background(Color.orange.opacity(0.10),
                            in: RoundedRectangle(cornerRadius: 12))

                Text("Quick commands:")
                    .font(.caption)
                    .foregroundStyle(.secondary)
                LazyVGrid(columns: [GridItem(.adaptive(minimum: 140))], spacing: 6) {
                    ForEach(["Check SIM & modem status", "Run USSD *124#",
                             "Open SMS verification codes", "Go to Laptop Tracker"], id: \.self) { promptText in
                        Button(promptText) { runQuickPrompt(promptText) }
                            .font(.caption)
                            .buttonStyle(.bordered)
                    }
                }
            }
            .padding(12)
            .background(Color(uiColor: .secondarySystemGroupedBackground))

            List {
                ForEach(lines) { line in
                    HStack(alignment: .top, spacing: 10) {
                        Image(systemName: line.role == "user" ? "person.fill" : "sparkles")
                            .foregroundStyle(line.role == "user" ? .secondary : .blue)
                        VStack(alignment: .leading, spacing: 4) {
                            if let title = line.title {
                                Text(title)
                                    .font(.subheadline.weight(.bold))
                            }
                            Text(line.text)
                                .font(.footnote)
                                .textSelection(.enabled)
                        }
                    }
                    .padding(.vertical, 2)
                }
            }
            .listStyle(.plain)

            HStack(spacing: 8) {
                TextField("Ask AI or enter a local command...", text: $prompt)
                    .textFieldStyle(.roundedBorder)
                    .onSubmit(send)
                Button {
                    if readAloud {
                        assistant.speak(assistant.response)
                    } else {
                        status = "Read aloud is off. Turn it on above."
                    }
                } label: {
                    Label("Read aloud", systemImage: "speaker.wave.2")
                        .font(.caption)
                }
                .buttonStyle(.bordered)
                Button("Send", action: send)
                    .buttonStyle(.borderedProminent)
            }
            .padding(10)
            .background(Color(uiColor: .systemGroupedBackground))

            if !status.isEmpty {
                Text(status)
                    .font(.caption)
                    .foregroundStyle(.secondary)
                    .frame(maxWidth: .infinity, alignment: .leading)
                    .padding(.horizontal, 12)
                    .padding(.bottom, 6)
                    .background(Color(uiColor: .systemGroupedBackground))
            }
        }
        .navigationTitle("Agent")
        .navigationBarTitleDisplayMode(.inline)
        .onChange(of: assistant.response) { value in
            guard let index = self.lines.lastIndex(where: { $0.role == "assistant" && $0.title == nil }) else { return }
            self.lines[index] = AgentChatLine(role: "assistant", title: nil, text: value)
        }
        .sheet(isPresented: $showAISettings) {
            NavigationStack {
                Form {
                    Section("Voice wake name") {
                        TextField("Wake name", text: $assistant.wakeName)
                            .textFieldStyle(.roundedBorder)
                            .onChange(of: assistant.wakeName) { value in
                                UserDefaults.standard.set(value, forKey: "assistant.wakeName")
                            }
                    }
                    Section("Gemini API key") {
                        Text("AI model: \(GeminiAssistant.defaultModel)")
                            .font(.footnote)
                        Text("Prompts are sent to Google only when you ask. An API key is required; any free quota is controlled by the provider.")
                            .font(.footnote)
                            .foregroundStyle(.secondary)
                        SecureField("Gemini API key", text: $apiKey)
                            .textFieldStyle(.roundedBorder)
                            .textInputAutocapitalization(.never)
                            .autocorrectionDisabled()
                        HStack {
                            Button("Save API key") {
                                assistant.saveAPIKey(apiKey)
                                apiKey = ""
                            }
                            .buttonStyle(.borderedProminent)
                            Button("Remove key") {
                                assistant.removeAPIKey()
                                apiKey = ""
                            }
                            .buttonStyle(.bordered)
                        }
                    }
                    Section("Ask AI") {
                        TextField("Ask the AI a question", text: $aiPrompt, axis: .vertical)
                            .lineLimit(2...5)
                            .textFieldStyle(.roundedBorder)
                        Button("Ask AI") {
                            assistant.askAI(aiPrompt, speakResponse: readAloud)
                            aiPrompt = ""
                        }
                        .buttonStyle(.borderedProminent)
                        HStack {
                            Button(assistant.isListening ? "Stop listening" : "Listen") {
                                assistant.isListening
                                    ? assistant.stopListening()
                                    : assistant.startListening()
                            }
                            .buttonStyle(.bordered)
                            Button("Speak response") {
                                assistant.speak(assistant.response)
                            }
                            .buttonStyle(.bordered)
                        }
                        Text(assistant.response)
                            .font(.footnote)
                            .textSelection(.enabled)
                    }
                    Section("Safety") {
                        Text("No background listening, relay control, or arbitrary device commands.")
                            .font(.footnote)
                            .foregroundStyle(.secondary)
                    }
                }
                .navigationTitle("Settings > AI")
                .toolbar {
                    ToolbarItem(placement: .navigationBarTrailing) {
                        Button("Done") { showAISettings = false }
                    }
                }
            }
        }
        .sheet(isPresented: $showTracker) {
            NavigationStack {
                DeviceTrackingView()
            }
        }
    }

    private func addAssistant(_ text: String) {
        lines.append(AgentChatLine(role: "assistant", title: nil, text: text))
    }

    private func send() {
        let text = prompt.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !text.isEmpty else { return }
        lines.append(AgentChatLine(role: "user", title: nil, text: text))
        prompt = ""
        if text.lowercased().hasPrefix("/agent") {
            assistant.runTextCommand(text)
            addAssistant(assistant.response)
            if readAloud { assistant.speak(assistant.response) }
        } else {
            assistant.askAI(text, speakResponse: readAloud)
            addAssistant(assistant.response)
        }
    }

    private func runQuickPrompt(_ text: String) {
        lines.append(AgentChatLine(role: "user", title: nil, text: text))
        switch text {
        case "Check SIM & modem status":
            selectedTab = 4
            addAssistant("SIM Manager opened. iOS does not expose ICCID/IMSI or modem telemetry; the panel shows honest status and a labelled simulation.")
        case "Run USSD *124#":
            guard let encoded = "*124#".addingPercentEncoding(withAllowedCharacters: CharacterSet(charactersIn: "0123456789*+")),
                  let url = URL(string: "tel:\(encoded)") else {
                addAssistant("The code could not be prepared. Nothing was opened.")
                return
            }
            UIApplication.shared.open(url, options: [:]) { opened in
                DispatchQueue.main.async {
                    self.addAssistant(opened
                        ? "Opened *124# in the system phone app. It runs only if you confirm it there."
                        : "The system phone app could not open *124#. Nothing was run.")
                }
            }
        case "Open SMS verification codes":
            selectedTab = 3
            addAssistant("Opened SMS. Verification codes appear in messages when received.")
        case "Go to Laptop Tracker":
            showTracker = true
            addAssistant("Opened Laptop Tracker. Pairing and permissions stay in that panel.")
        default:
            addAssistant("Unknown quick command. Nothing was run.")
        }
    }
}



private struct MobileDialerView: View {
    var body: some View {
        Form {
            Section("App number") {
                Text("Dialing Windows 700 app numbers is not available in this mobile build. Mobile calls use LiveKit invitations and require a configured, reachable calling service.")
                    .font(.footnote)
                    .foregroundStyle(.secondary)
            }
            Section("Voice and video") {
                NavigationLink {
                    NativeCallView()
                } label: {
                    Label("Open call center", systemImage: "video")
                }
                Text("Create and share an invitation, or join a friend's invitation. Network reachability and service configuration are required.")
                    .font(.footnote)
                    .foregroundStyle(.secondary)
            }
        }
        .navigationTitle("Dialer")
    }
}

private struct MobileAppContact: Codable, Identifiable {
    var id: String { number }
    let name: String
    let number: String
}

private struct MobileContactsView: View {
    @AppStorage("mobile.contacts") private var savedContacts = "[]"
    @State private var contacts: [MobileAppContact] = []
    @State private var name = ""
    @State private var number = ""
    @State private var status = ""

    var body: some View {
        Form {
            Section("Add app contact") {
                TextField("Name", text: $name)
                    .textContentType(.name)
                TextField("App number", text: $number)
                    .keyboardType(.numberPad)
                Button("Save contact", action: saveContact)
            }
            Section {
                if contacts.isEmpty {
                    Text(status.isEmpty ? "No app contacts saved yet." : status)
                        .font(.footnote)
                        .foregroundStyle(.secondary)
                } else {
                    ForEach(contacts) { contact in
                        HStack {
                            VStack(alignment: .leading, spacing: 3) {
                                Text(contact.name)
                                    .font(.body.weight(.medium))
                                Text(contact.number)
                                    .font(.footnote)
                                    .foregroundStyle(.secondary)
                            }
                            Spacer()
                            Button("Copy") {
                                UIPasteboard.general.string = contact.number
                                status = "Copied \(contact.number)."
                            }
                            .buttonStyle(.bordered)
                        }
                        .swipeActions {
                            Button("Delete", role: .destructive) {
                                contacts.removeAll { $0.id == contact.id }
                                persistContacts()
                            }
                        }
                    }
                }
                if !status.isEmpty && !contacts.isEmpty {
                    Text(status)
                        .font(.footnote)
                        .foregroundStyle(.secondary)
                }
            } header: {
                Text("Saved on this device")
            } footer: {
                Text("These app contacts are stored locally. USSD Manager does not read your iPhone address book.")
            }
        }
        .navigationTitle("Contacts")
        .onAppear(perform: loadContacts)
    }

    private func loadContacts() {
        guard let data = savedContacts.data(using: .utf8) else {
            status = "Saved contacts could not be decoded."
            return
        }
        do {
            contacts = try JSONDecoder().decode([MobileAppContact].self, from: data)
        } catch {
            status = "Saved contacts could not be loaded: \(error.localizedDescription)"
        }
    }

    private func saveContact() {
        let cleanName = name.trimmingCharacters(in: .whitespacesAndNewlines)
        let cleanNumber = number.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !cleanName.isEmpty,
              cleanNumber.range(of: "^[0-9]{4,20}$", options: .regularExpression) != nil else {
            status = "Enter a name and a 4-20 digit app number."
            return
        }
        contacts.removeAll { $0.number == cleanNumber }
        contacts.append(MobileAppContact(name: cleanName, number: cleanNumber))
        persistContacts()
        name = ""
        number = ""
        status = "Contact saved on this device."
    }

    private func persistContacts() {
        do {
            let data = try JSONEncoder().encode(contacts)
            guard let value = String(data: data, encoding: .utf8) else {
                status = "Contacts could not be saved as text."
                return
            }
            savedContacts = value
        } catch {
            status = "Contacts could not be saved: \(error.localizedDescription)"
        }
    }
}

private struct MobileUSSDView: View {
    @State private var code = ""
    @State private var status = "Nothing has been opened."

    var body: some View {
        Form {
            Section {
                TextField("Example: *124#", text: $code)
                    .textInputAutocapitalization(.never)
                    .autocorrectionDisabled()
                Button("Review in phone app", action: openDialer)
                Text(status)
                    .font(.footnote)
                    .foregroundStyle(.secondary)
            } header: {
                Text("Carrier USSD")
            } footer: {
                Text("Carrier, SIM, and iOS support vary. This app only opens the system phone app; check the code there and confirm any action yourself.")
            }
        }
        .navigationTitle("USSD")
    }

    private func openDialer() {
        let cleanCode = code.trimmingCharacters(in: .whitespacesAndNewlines)
        guard cleanCode.range(of: "^\\*[0-9*#]+#$", options: .regularExpression) != nil,
              let encodedCode = cleanCode.addingPercentEncoding(
                withAllowedCharacters: CharacterSet(charactersIn: "0123456789*+")),
              let url = URL(string: "tel:\(encodedCode)") else {
            status = "Enter a code such as *124#. Nothing was opened."
            return
        }
        UIApplication.shared.open(url, options: [:]) { opened in
            status = opened
                ? "Review the code in the system phone app. It runs only if you confirm it there."
                : "The system phone app could not open this code."
        }
    }
}

private struct HomeDestinationCard: View {
    let icon: String
    let title: String
    let detail: String
    let tint: Color

    var body: some View {
        HStack(spacing: 14) {
            Image(systemName: icon)
                .font(.headline)
                .foregroundStyle(tint)
                .frame(width: 42, height: 42)
                .background(tint.opacity(0.12), in: RoundedRectangle(cornerRadius: 12))
            VStack(alignment: .leading, spacing: 3) {
                Text(title)
                    .font(.subheadline.weight(.semibold))
                    .foregroundStyle(.primary)
                Text(detail)
                    .font(.footnote)
                    .foregroundStyle(.secondary)
            }
            Spacer(minLength: 0)
            Image(systemName: "chevron.right")
                .font(.footnote.weight(.semibold))
                .foregroundStyle(.tertiary)
        }
        .padding(12)
        .frame(maxWidth: .infinity, minHeight: 68, alignment: .leading)
        .background(Color(uiColor: .secondarySystemGroupedBackground),
                    in: RoundedRectangle(cornerRadius: 15))
        .contentShape(RoundedRectangle(cornerRadius: 15))
        .accessibilityElement(children: .combine)
    }
}

private struct DeviceTrackingView: View {
    @AppStorage("tracker.server") private var server = "https://laptop-tracker-1.onrender.com"
    @State private var pairCode = ""
    @AppStorage("tracker.deviceId") private var deviceId = ""
    @State private var status = "Not connected."
    @State private var response = ""
    @State private var isBusy = false
    @State private var revokeTargetID = ""
    @State private var showRevokeConfirmation = false
    @StateObject private var locationProvider = OneShotLocationProvider()
    @State private var trackedLocations: [TrackerLocation] = []

    private enum Action: String {
        case generate = "Generate pairing code"
        case verify = "Verify pairing"
        case status = "Refresh status"
        case heartbeat = "Send status-only check-in"
        case lostOn = "Enable lost mode"
        case lostOff = "Disable lost mode"
        case revoke = "Disconnect paired device"
    }

    var body: some View {
        Form {
            Section("Device tracking session") {
                Text("Pair devices you control with authenticated credentials. Refresh status to view their last reported locations. This is not a live feed: each device must share its location while available. Lost mode changes status only. This device shares its location only after you request it and grant When In Use permission.")
                    .font(.footnote)
                    .foregroundColor(.secondary)
                TextField("Tracker service URL (https://...)", text: $server)
                    .textInputAutocapitalization(.never)
                    .autocorrectionDisabled()
                    .keyboardType(.URL)
                TextField("Pairing code", text: $pairCode)
                    .textInputAutocapitalization(.never)
                    .autocorrectionDisabled()
                TextField("Device ID", text: $deviceId)
                    .textInputAutocapitalization(.never)
                    .autocorrectionDisabled()
            }
            Section("Actions") {
                trackerButton(.generate)
                trackerButton(.verify)
                trackerButton(.status)
                trackerButton(.heartbeat)
                Button("Share current location once") { shareCurrentLocationOnce() }
                trackerButton(.lostOn)
                trackerButton(.lostOff)
                TextField("Paired device ID to disconnect", text: $revokeTargetID)
                    .textInputAutocapitalization(.never)
                    .autocorrectionDisabled()
                Button("Disconnect paired device", role: .destructive) {
                    showRevokeConfirmation = true
                }
                .disabled(revokeTargetID.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty)
            }
            Section("Last reported locations") {
                if trackedLocations.isEmpty {
                    Text("No paired-device location loaded. Tap Refresh status; a device must share its location while available.")
                        .font(.footnote)
                        .foregroundColor(.secondary)
                } else {
                    ForEach(trackedLocations) { location in
                        VStack(alignment: .leading, spacing: 5) {
                            Text(location.deviceId + (location.isOnline ? " · online" : " · offline") +
                                 (location.isLost ? " · marked lost" : ""))
                                .font(.subheadline)
                            Text(String(format: "%.6f, %.6f", location.latitude, location.longitude))
                                .font(.footnote)
                                .foregroundColor(.secondary)
                            if let updatedAt = location.updatedAt {
                                Text("Last report " + updatedAt.formatted(date: .abbreviated, time: .shortened))
                                    .font(.caption)
                                    .foregroundColor(.secondary)
                            }
                            if let url = location.mapsURL {
                                Link("Open last reported location in Maps", destination: url)
                            }
                        }
                        .padding(.vertical, 4)
                    }
                }
            }
            Section {
                Text(status)
                    .font(.footnote)
                if !response.isEmpty {
                    Text(response)
                        .font(.footnote)
                        .textSelection(.enabled)
                }
            } header: {
                Text("Tracker response")
            } footer: {
                Text("Use HTTPS. Device credentials are stored in the device Keychain. Share a generated pairing code only with a device you control.")
            }
        }
        .navigationTitle("Device Tracking")
        .disabled(isBusy)
        .confirmationDialog(
            "Disconnect paired device?",
            isPresented: $showRevokeConfirmation,
            titleVisibility: .visible
        ) {
            Button("Disconnect", role: .destructive) { run(.revoke) }
            Button("Cancel", role: .cancel) {}
        } message: {
            Text("This revokes that device's tracker credential for this pairing.")
        }
    }

    private func trackerButton(_ action: Action) -> some View {
        Button(action.rawValue) { run(action) }
    }

    private func run(_ action: Action) {
        let endpoint = server.trimmingCharacters(in: .whitespacesAndNewlines)
        let pair = pairCode.trimmingCharacters(in: .whitespacesAndNewlines)
        let device = deviceId.trimmingCharacters(in: .whitespacesAndNewlines)
        guard let components = URLComponents(string: endpoint),
              components.scheme == "https", components.host != nil,
              TrackerClient(baseUrl: endpoint) != nil else {
            status = "Enter a valid HTTPS tracker URL."
            response = ""
            return
        }
        if action == .verify && pair.isEmpty {
            status = "Enter the pairing code first."
            response = ""
            return
        }
        let needsCredential = action != .generate && action != .verify
        let credentials: TrackerCredentials?
        do {
            credentials = try TrackerCredentialStore().load()
        } catch {
            status = "Could not read the saved device credential."
            response = error.localizedDescription
            return
        }
        if needsCredential && (credentials == nil || credentials?.deviceId != device) {
            status = "Pair this device before requesting authenticated tracker actions."
            response = ""
            return
        }
        if (action == .heartbeat || action == .status || action == .lostOn ||
            action == .lostOff || action == .revoke) && device.isEmpty {
            status = "Enter the device ID first."
            response = ""
            return
        }
        let revokeTarget = revokeTargetID.trimmingCharacters(in: .whitespacesAndNewlines)
        if action == .revoke && revokeTarget.isEmpty {
            status = "Enter the paired device ID to disconnect."
            response = ""
            return
        }
        if action == .revoke && revokeTarget == device {
            status = "Choose the other paired device. This action cannot revoke this device from itself."
            response = ""
            return
        }
        guard let client = TrackerClient(baseUrl: endpoint, token: needsCredential ? credentials?.token : nil) else {
            status = "Could not create a secure tracker connection."
            response = ""
            return
        }

        isBusy = true
        status = "\(action.rawValue) in progress..."
        response = ""
        let completion: (TrackerReply) -> Void = { reply in
            DispatchQueue.main.async {
                isBusy = false
                do {
                    if reply.ok && (action == .generate || action == .verify) {
                        let data = Data(reply.body.utf8)
                        guard let payload = try JSONSerialization.jsonObject(with: data) as? [String: Any],
                              let newDevice = payload["deviceId"] as? String,
                              let token = payload["deviceToken"] as? String else {
                            throw TrackerCredentialError.invalidData
                        }
                        try TrackerCredentialStore().save(deviceId: newDevice, token: token)
                        deviceId = newDevice
                        if action == .generate, let code = payload["pairCode"] as? String {
                            pairCode = code
                        }
                    }
                    if action == .status {
                        trackedLocations = parseTrackerLocations(reply.body)
                    }
                    status = "\(action.rawValue) \(reply.ok ? "completed" : "failed")" +
                        (reply.status > 0 ? " (HTTP \(reply.status))." : ".")
                    response = reply.ok && action == .status && trackedLocations.isEmpty
                        ? "No paired-device location has been reported yet."
                        : trackerDisplayBody(reply.body)
                } catch {
                    status = "\(action.rawValue) failed while securing credentials."
                    response = error.localizedDescription
                }
            }
        }
        switch action {
        case .generate:
            client.generatePair(deviceType: "phone", completion: completion)
        case .verify:
            client.verifyPair(pairCode: pair, completion: completion)
        case .status:
            client.pairInfo(deviceId: device, completion: completion)
        case .heartbeat:
            client.heartbeat(deviceId: device, lat: nil, lng: nil, source: "ussd-app-status",
                             completion: completion)
        case .lostOn:
            client.lostMode(deviceId: device, active: true, completion: completion)
        case .lostOff:
            client.lostMode(deviceId: device, active: false, completion: completion)
        case .revoke:
            client.revokeDevice(deviceId: device, targetDeviceId: revokeTarget, completion: completion)
        }
    }

    private func shareCurrentLocationOnce() {
        let endpoint = server.trimmingCharacters(in: .whitespacesAndNewlines)
        let device = deviceId.trimmingCharacters(in: .whitespacesAndNewlines)
        guard let components = URLComponents(string: endpoint),
              components.scheme == "https", components.host != nil,
              components.user == nil, components.password == nil,
              TrackerClient(baseUrl: endpoint) != nil else {
            status = "Enter a valid HTTPS tracker URL."
            response = ""
            return
        }
        guard !device.isEmpty else {
            status = "Enter the device ID first."
            response = ""
            return
        }
        do {
            guard let credentials = try TrackerCredentialStore().load(),
                  credentials.deviceId == device else {
                status = "Pair this device before sharing a location."
                response = ""
                return
            }
        } catch {
            status = "Could not read the saved device credential."
            response = error.localizedDescription
            return
        }
        isBusy = true
        status = "Requesting one location fix. Nothing is shared until it is sent."
        response = ""
        locationProvider.requestLocation { result in
            isBusy = false
            switch result {
            case .success(let location):
                shareLocation(latitude: location.coordinate.latitude,
                              longitude: location.coordinate.longitude)
            case .failure(let error):
                status = error.localizedDescription
                response = "Nothing was shared."
            }
        }
    }

    private func shareLocation(latitude: Double, longitude: Double) {
        let endpoint = server.trimmingCharacters(in: .whitespacesAndNewlines)
        let device = deviceId.trimmingCharacters(in: .whitespacesAndNewlines)
        guard let components = URLComponents(string: endpoint),
              components.scheme == "https", components.host != nil,
              components.user == nil, components.password == nil else {
            status = "Enter a valid HTTPS tracker URL."
            response = ""
            return
        }
        let saved: TrackerCredentials
        do {
            guard let credentials = try TrackerCredentialStore().load(),
                  credentials.deviceId == device else {
                status = "Pair this device before sharing a location."
                response = ""
                return
            }
            saved = credentials
        } catch {
            status = "Could not read the saved device credential."
            response = error.localizedDescription
            return
        }
        guard let client = TrackerClient(baseUrl: endpoint, token: saved.token) else {
            status = "Could not create a secure tracker connection."
            response = ""
            return
        }
        guard !device.isEmpty else {
            status = "Enter the device ID first."
            response = ""
            return
        }
        isBusy = true
        status = "Sharing the one-time location fix..."
        response = ""
        client.heartbeat(deviceId: device, lat: latitude, lng: longitude,
                         source: "ussd-app-user-approved-location") { reply in
            DispatchQueue.main.async {
                isBusy = false
                status = "Share current location once \(reply.ok ? "completed" : "failed")" +
                    (reply.status > 0 ? " (HTTP \(reply.status))." : ".")
                response = reply.body.count > 6000
                    ? String(reply.body.prefix(6000)) + "\n[response truncated]"
                    : reply.body
            }
        }
    }

    private func parseTrackerLocations(_ body: String) -> [TrackerLocation] {
        guard let data = body.data(using: .utf8),
              let payload = (try? JSONSerialization.jsonObject(with: data)) as? [String: Any],
              let devices = payload["devices"] as? [[String: Any]] else { return [] }
        return devices.compactMap { device in
            guard let deviceId = device["deviceId"] as? String,
                  let location = device["location"] as? [String: Any],
                  let latitude = location["lat"] as? Double,
                  let longitude = location["lng"] as? Double,
                  (-90...90).contains(latitude), (-180...180).contains(longitude) else { return nil }
            let updatedAt = (location["updatedAt"] as? NSNumber)?.doubleValue
            return TrackerLocation(deviceId: deviceId, latitude: latitude, longitude: longitude,
                                   isOnline: device["online"] as? Bool ?? false,
                                   isLost: device["isLost"] as? Bool ?? false,
                                   updatedAt: updatedAt.map { Date(timeIntervalSince1970: $0 / 1000) })
        }
    }

    private func trackerDisplayBody(_ body: String) -> String {
        guard let data = body.data(using: .utf8),
              var payload = (try? JSONSerialization.jsonObject(with: data)) as? [String: Any] else {
            return String(body.prefix(6000))
        }
        guard payload["deviceToken"] != nil else { return String(body.prefix(6000)) }
        payload["deviceToken"] = "[stored securely]"
        guard let sanitized = try? JSONSerialization.data(withJSONObject: payload, options: [.prettyPrinted]),
              let text = String(data: sanitized, encoding: .utf8) else {
            return "Credential response stored securely; details hidden."
        }
        return String(text.prefix(6000))
    }
}

private struct TrackerLocation: Identifiable {
    let deviceId: String
    let latitude: Double
    let longitude: Double
    let isOnline: Bool
    let isLost: Bool
    let updatedAt: Date?

    var id: String { deviceId }
    var mapsURL: URL? {
        var components = URLComponents(string: "https://maps.apple.com/")
        components?.queryItems = [
            URLQueryItem(name: "ll", value: "\(latitude),\(longitude)"),
            URLQueryItem(name: "q", value: deviceId)
        ]
        return components?.url
    }
}

@MainActor
private final class OneShotLocationProvider: NSObject, ObservableObject, CLLocationManagerDelegate {
    private let manager = CLLocationManager()
    private var completion: ((Result<CLLocation, Error>) -> Void)?
    private var timeout: DispatchWorkItem?

    override init() {
        super.init()
        manager.delegate = self
        manager.desiredAccuracy = kCLLocationAccuracyHundredMeters
    }

    func requestLocation(_ completion: @escaping (Result<CLLocation, Error>) -> Void) {
        guard self.completion == nil else {
            completion(.failure(NSError(domain: "UssdLocation", code: 1,
                                        userInfo: [NSLocalizedDescriptionKey: "A location request is already active."])))
            return
        }
        self.completion = completion
        let timeoutWork = DispatchWorkItem { [weak self] in
            self?.finish(.failure(NSError(domain: "UssdLocation", code: 5,
                                          userInfo: [NSLocalizedDescriptionKey: "No location fix arrived within 30 seconds."])))
        }
        timeout = timeoutWork
        DispatchQueue.main.asyncAfter(deadline: .now() + 30, execute: timeoutWork)
        switch manager.authorizationStatus {
        case .authorizedAlways, .authorizedWhenInUse:
            manager.requestLocation()
        case .notDetermined:
            manager.requestWhenInUseAuthorization()
        case .denied, .restricted:
            finish(.failure(NSError(domain: "UssdLocation", code: 2,
                                    userInfo: [NSLocalizedDescriptionKey: "Location permission was denied."])))
        @unknown default:
            finish(.failure(NSError(domain: "UssdLocation", code: 3,
                                    userInfo: [NSLocalizedDescriptionKey: "Location permission status is unknown."])))
        }
    }

    func locationManagerDidChangeAuthorization(_ manager: CLLocationManager) {
        guard completion != nil else { return }
        switch manager.authorizationStatus {
        case .authorizedAlways, .authorizedWhenInUse:
            manager.requestLocation()
        case .denied, .restricted:
            finish(.failure(NSError(domain: "UssdLocation", code: 2,
                                    userInfo: [NSLocalizedDescriptionKey: "Location permission was denied."])))
        case .notDetermined:
            break
        @unknown default:
            finish(.failure(NSError(domain: "UssdLocation", code: 3,
                                    userInfo: [NSLocalizedDescriptionKey: "Location permission status is unknown."])))
        }
    }

    func locationManager(_ manager: CLLocationManager, didUpdateLocations locations: [CLLocation]) {
        guard let location = locations.last else {
            finish(.failure(NSError(domain: "UssdLocation", code: 4,
                                    userInfo: [NSLocalizedDescriptionKey: "No location fix was available."])))
            return
        }
        finish(.success(location))
    }

    func locationManager(_ manager: CLLocationManager, didFailWithError error: Error) {
        finish(.failure(error))
    }

    private func finish(_ result: Result<CLLocation, Error>) {
        let callback = completion
        completion = nil
        timeout?.cancel()
        timeout = nil
        callback?(result)
    }
}
