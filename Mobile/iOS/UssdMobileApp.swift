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
        NavigationView {
            VStack(alignment: .leading, spacing: 16) {
                Text("USSD Manager").font(.title)
                NavigationLink("Open secure relay chat") {
                    MobileMessagingView()
                }
                NavigationLink("Start voice/video calls") {
                    NativeCallView()
                }
                NavigationLink("Open Device Tracking session") {
                    DeviceTrackingView()
                }
                Text("Local voice assistant")
                    .font(.headline)
                Text("Voice starts only when you tap Listen. Speech recognition is limited to " +
                     "on-device processing when the current language supports it.")
                    .font(.footnote)
                    .foregroundColor(.secondary)

                TextField("Voice wake name", text: $assistant.wakeName)
                    .textFieldStyle(RoundedBorderTextFieldStyle())
                    .onChange(of: assistant.wakeName) { value in
                        UserDefaults.standard.set(value, forKey: "assistant.wakeName")
                    }

                TextField("Type /agent help", text: $command)
                    .textFieldStyle(RoundedBorderTextFieldStyle())
                    .onSubmit { runTypedCommand() }
                Button("Run /agent command", action: runTypedCommand)

                Text("AI model: \(GeminiAssistant.defaultModel)")
                    .font(.subheadline)
                Text("Prompts are sent to Google only when you ask. An API key is required; any free quota is controlled by the provider.")
                    .font(.footnote)
                    .foregroundColor(.secondary)
                SecureField("Gemini API key", text: $apiKey)
                    .textFieldStyle(RoundedBorderTextFieldStyle())
                    .textInputAutocapitalization(.never)
                    .autocorrectionDisabled()
                HStack {
                    Button("Save API key securely") {
                        assistant.saveAPIKey(apiKey)
                        apiKey = ""
                    }
                    Button("Remove API key") {
                        assistant.removeAPIKey()
                        apiKey = ""
                    }
                }

                TextField("Ask the AI a question", text: $prompt, axis: .vertical)
                    .lineLimit(2...5)
                    .textFieldStyle(RoundedBorderTextFieldStyle())
                Button("Ask AI") {
                    assistant.askAI(prompt)
                    prompt = ""
                }

                HStack {
                    Button(assistant.isListening ? "Stop listening" : "Listen") {
                        assistant.isListening ? assistant.stopListening() : assistant.startListening()
                    }
                    Button("Speak response") {
                        assistant.speak(assistant.response)
                    }
                }
                Text(assistant.response)
                    .textSelection(.enabled)
                    .frame(maxWidth: .infinity, alignment: .leading)

                Spacer()
                Text("No background listening, relay control, or arbitrary device commands.")
                    .font(.footnote)
                    .foregroundColor(.secondary)
            }
            .padding()
            .navigationTitle("Home")
        }
    }

    private func runTypedCommand() {
        assistant.runTextCommand(command)
        command = ""
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
                Text("Pair this device with your tracker service using authenticated, one-time credentials. Lost mode is a server-side status only and does not lock or command a device. Location is read only after you tap the one-time location button and grant When In Use permission.")
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
                    status = "\(action.rawValue) \(reply.ok ? "completed" : "failed")" +
                        (reply.status > 0 ? " (HTTP \(reply.status))." : ".")
                    response = trackerDisplayBody(reply.body)
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
