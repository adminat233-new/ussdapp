import SwiftUI
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
    @StateObject private var assistant = MobileAgent()
    @State private var command = ""
    @State private var apiKey = ""
    @State private var prompt = ""

    var body: some View {
        NavigationStack {
            ScrollView {
                VStack(alignment: .leading, spacing: 18) {
                    VStack(alignment: .leading, spacing: 8) {
                        HStack(spacing: 12) {
                            Image(systemName: "antenna.radiowaves.left.and.right")
                                .font(.title2.weight(.semibold))
                                .foregroundStyle(.white)
                                .frame(width: 48, height: 48)
                                .background(.white.opacity(0.16), in: RoundedRectangle(cornerRadius: 14))
                            VStack(alignment: .leading, spacing: 3) {
                                Text("USSD Manager")
                                    .font(.title2.weight(.bold))
                                Text("Communication, made simple")
                                    .font(.subheadline)
                                    .foregroundStyle(.white.opacity(0.82))
                            }
                        }
                        Text("Your tools, calls and trusted connections in one place.")
                            .font(.footnote)
                            .foregroundStyle(.white.opacity(0.86))
                            .padding(.top, 4)
                    }
                    .foregroundStyle(.white)
                    .padding(20)
                    .frame(maxWidth: .infinity, alignment: .leading)
                    .background(
                        LinearGradient(
                            colors: [Color(red: 0.19, green: 0.35, blue: 0.78),
                                     Color(red: 0.20, green: 0.23, blue: 0.52)],
                            startPoint: .topLeading,
                            endPoint: .bottomTrailing
                        ),
                        in: RoundedRectangle(cornerRadius: 22)
                    )

                    VStack(alignment: .leading, spacing: 10) {
                        Text("Your apps").font(.headline)
                        NavigationLink {
                            NativeCallView()
                        } label: {
                            HomeDestinationCard(
                                icon: "video.fill",
                                title: "Calls & video",
                                detail: "Start or join a voice or video room",
                                tint: .blue
                            )
                        }
                        .buttonStyle(.plain)
                        NavigationLink {
                            MobileMessagingView()
                        } label: {
                            HomeDestinationCard(
                                icon: "lock.fill",
                                title: "Secure messages",
                                detail: "Chat through your trusted relay",
                                tint: .green
                            )
                        }
                        .buttonStyle(.plain)
                        NavigationLink {
                            DeviceTrackingView()
                        } label: {
                            HomeDestinationCard(
                                icon: "laptopcomputer.and.iphone",
                                title: "Device tracking",
                                detail: "Manage paired devices and sharing",
                                tint: .orange
                            )
                        }
                        .buttonStyle(.plain)
                    }

                    VStack(alignment: .leading, spacing: 12) {
                        Label("Assistant", systemImage: "sparkles")
                            .font(.headline)
                        Text("Voice starts only when you tap Listen. The assistant does not execute remote shell commands.")
                            .font(.footnote)
                            .foregroundStyle(.secondary)

                        TextField("Voice wake name", text: $assistant.wakeName)
                            .textFieldStyle(.roundedBorder)
                            .onChange(of: assistant.wakeName) { value in
                                UserDefaults.standard.set(value, forKey: "assistant.wakeName")
                            }

                        TextField("Type /agent help", text: $command)
                            .textFieldStyle(.roundedBorder)
                            .onSubmit { runTypedCommand() }
                        Button("Run assistant command", action: runTypedCommand)
                            .buttonStyle(.borderedProminent)
                            .frame(maxWidth: .infinity, alignment: .leading)

                        Text("AI model: \(GeminiAssistant.defaultModel)")
                            .font(.subheadline.weight(.medium))
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

                        TextField("Ask the AI a question", text: $prompt, axis: .vertical)
                            .lineLimit(2...5)
                            .textFieldStyle(.roundedBorder)
                        Button("Ask AI") {
                            assistant.askAI(prompt)
                            prompt = ""
                        }
                        .buttonStyle(.borderedProminent)

                        HStack {
                            Button(assistant.isListening ? "Stop listening" : "Listen") {
                                assistant.isListening ? assistant.stopListening() : assistant.startListening()
                            }
                            .buttonStyle(.bordered)
                            Button("Speak response") {
                                assistant.speak(assistant.response)
                            }
                            .buttonStyle(.bordered)
                        }
                        Text(assistant.response)
                            .textSelection(.enabled)
                            .frame(maxWidth: .infinity, alignment: .leading)
                            .padding(12)
                            .background(Color(uiColor: .tertiarySystemGroupedBackground),
                                        in: RoundedRectangle(cornerRadius: 12))
                    }
                    .padding(16)
                    .background(Color(uiColor: .secondarySystemGroupedBackground),
                                in: RoundedRectangle(cornerRadius: 18))

                    Text("No background listening, relay control, or arbitrary device commands.")
                        .font(.footnote)
                        .foregroundStyle(.secondary)
                        .frame(maxWidth: .infinity, alignment: .center)
                }
                .padding()
                .frame(maxWidth: 680)
                .frame(maxWidth: .infinity)
            }
            .background(Color(uiColor: .systemGroupedBackground))
            .navigationTitle("Home")
            .navigationBarTitleDisplayMode(.inline)
        }
    }

    private func runTypedCommand() {
        assistant.runTextCommand(command)
        command = ""
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
    @AppStorage("tracker.server") private var server = ""
    @State private var pairCode = ""
    @AppStorage("tracker.deviceId") private var deviceId = ""
    @State private var status = "Not connected."
    @State private var response = ""
    @State private var isBusy = false
    @StateObject private var locationProvider = OneShotLocationProvider()
    @State private var trackedLocations: [TrackerLocation] = []

    private enum Action: String {
        case generate = "Generate pairing code"
        case verify = "Verify pairing"
        case status = "Refresh status"
        case heartbeat = "Send status-only check-in"
        case lostOn = "Enable lost mode"
        case lostOff = "Disable lost mode"
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
        if (action == .heartbeat || action == .status || action == .lostOn || action == .lostOff) && device.isEmpty {
            status = "Enter the device ID first."
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
