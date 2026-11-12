import CryptoKit
import Foundation
@preconcurrency import LiveKit
import LiveKitComponents
import SwiftUI
import UniformTypeIdentifiers

private let callDataTopic = "ussd.e2e.v1"
private let maxCallFileBytes: Int64 = 50 * 1024 * 1024
private let callFileChunkBytes = 6 * 1024

struct NativeCallView: View {
    @StateObject private var call = NativeCallModel()
    @State private var invitationToJoin = ""
    @State private var messageToSend = ""
    @State private var choosingFile = false

    private let columns = [GridItem(.adaptive(minimum: 150), spacing: 10)]

    var body: some View {
        Form {
            Section("Call setup") {
                TextField("Call service URL (https://...)", text: $call.serviceURL)
                    .textInputAutocapitalization(.never)
                    .autocorrectionDisabled()
                    .keyboardType(.URL)
                TextField("Your display name", text: $call.displayName)
                    .textInputAutocapitalization(.words)
                HStack {
                    Button("Start voice call") {
                        Task { await call.createCall(video: false) }
                    }
                    .disabled(call.isBusy || call.isConnected)
                    Button("Start video call") {
                        Task { await call.createCall(video: true) }
                    }
                    .disabled(call.isBusy || call.isConnected)
                }
                if !call.invitation.isEmpty {
                    ShareLink(item: call.invitation) {
                        Label("Share private invitation", systemImage: "square.and.arrow.up")
                    }
                    Text(call.invitation)
                        .font(.footnote.monospaced())
                        .textSelection(.enabled)
                }
                TextField("Paste a friend's invitation", text: $invitationToJoin)
                    .textInputAutocapitalization(.never)
                    .autocorrectionDisabled()
                Button("Join call") {
                    Task { await call.join(invitation: invitationToJoin, video: false) }
                }
                .disabled(call.isBusy || call.isConnected)
            }

            Section("Call") {
                Text(call.status)
                    .font(.footnote)
                Text("Calls need the deployed CallingServer and LiveKit media service. Windows clients currently use a different calling stack.")
                    .font(.caption)
                    .foregroundStyle(.secondary)
                if call.isConnected {
                    HStack {
                        Button(call.isMuted ? "Unmute" : "Mute") {
                            Task { await call.toggleMicrophone() }
                        }
                        Button(call.isVideoEnabled ? "Turn video off" : "Turn video on") {
                            Task { await call.toggleVideo() }
                        }
                        Button("Leave call", role: .destructive) {
                            Task { await call.leave() }
                        }
                    }
                    LazyVGrid(columns: columns, spacing: 10) {
                        ForEachParticipant { participant in
                            VStack(spacing: 8) {
                                ForEachTrack(filter: .video) { trackReference in
                                    VideoTrackView(trackReference: trackReference)
                                        .frame(minHeight: 140, maxHeight: 220)
                                        .clipShape(RoundedRectangle(cornerRadius: 12))
                                }
                                Text(participant.name ?? participant.identity?.stringValue ?? "Participant")
                                    .font(.caption)
                            }
                            .frame(maxWidth: .infinity, minHeight: 150)
                            .background(Color.secondary.opacity(0.1))
                            .clipShape(RoundedRectangle(cornerRadius: 12))
                        }
                    }
                    .environmentObject(call.room)
                    Text("Audio/video are encrypted in transit by LiveKit, but are not app-level end-to-end encrypted. In-call chat and files use the invitation key.")
                        .font(.caption)
                        .foregroundStyle(.secondary)
                }
            }

            if call.isConnected {
                Section("Encrypted in-call chat") {
                    ForEach(Array(call.chatMessages.enumerated()), id: \.offset) { _, text in
                        Text(text)
                            .textSelection(.enabled)
                    }
                    HStack {
                        TextField("Message", text: $messageToSend, axis: .vertical)
                            .lineLimit(1...4)
                        Button("Send") {
                            let text = messageToSend
                            messageToSend = ""
                            Task { await call.sendChat(text) }
                        }
                        .disabled(messageToSend.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty)
                    }
                    Button("Send encrypted file") { choosingFile = true }
                    .disabled(call.isTransferring)
                    if call.isTransferring {
                        ProgressView("Sending file...")
                    }
                    if let file = call.incomingFileURL {
                        ShareLink(item: file) {
                            Label("Save or share received file: \(file.lastPathComponent)",
                                  systemImage: "square.and.arrow.down")
                        }
                    }
                }
            }
        }
        .navigationTitle("Calls")
        .fileImporter(isPresented: $choosingFile,
                      allowedContentTypes: [.item],
                      allowsMultipleSelection: false) { result in
            switch result {
            case .success(let urls):
                guard let url = urls.first else { return }
                Task { await call.sendFile(url) }
            case .failure(let error):
                call.status = "Could not choose a file: \(error.localizedDescription)"
            }
        }
        .onChange(of: call.serviceURL) { value in
            UserDefaults.standard.set(value, forKey: "call.serviceURL")
        }
        .onChange(of: call.displayName) { value in
            UserDefaults.standard.set(value, forKey: "call.displayName")
        }
        .onDisappear {
            if call.isConnected {
                Task { await call.leave() }
            }
        }
    }
}

@MainActor
private final class NativeCallModel: ObservableObject, RoomDelegate {
    @Published var serviceURL = UserDefaults.standard.string(forKey: "call.serviceURL") ?? ""
    @Published var displayName = UserDefaults.standard.string(forKey: "call.displayName") ?? ""
    @Published var invitation = ""
    @Published var status = "Not in a call."
    @Published var isConnected = false
    @Published var isBusy = false
    @Published var isMuted = false
    @Published var isVideoEnabled = false
    @Published var isTransferring = false
    @Published var chatMessages: [String] = []
    @Published var incomingFileURL: URL?

    let room = Room()
    private var invitationCode = ""
    private var callKey: SymmetricKey?
    private var incomingFileID: String?
    private var incomingFileName = ""
    private var incomingFileExpectedSize: Int64 = 0
    private var incomingFileHandle: FileHandle?
    private var incomingFileURLInternal: URL?
    private var incomingFileBytes: Int64 = 0

    init() {
        room.add(delegate: self)
    }

    func createCall(video: Bool) async {
        guard let base = validatedServiceURL() else { return }
        isBusy = true
        defer { isBusy = false }
        do {
            let response = try await request(base: base, path: "/api/rooms", body: [:])
            guard let code = response["invitationCode"] as? String,
                  code.range(of: "^[a-f0-9]{48}$", options: .regularExpression) != nil else {
                throw CallClientError.invalidResponse
            }
            let key = SymmetricKey(size: .bits256)
            let rawKey = key.withUnsafeBytes { Data($0) }
            invitationCode = code
            callKey = key
            invitation = "\(code):\(rawKey.base64URLEncodedString())"
            try await connect(code: code, video: video, base: base)
        } catch {
            status = "Could not start call: \(error.localizedDescription)"
        }
    }

    func join(invitation suppliedInvitation: String, video: Bool) async {
        guard let base = validatedServiceURL() else { return }
        let parts = suppliedInvitation.trimmingCharacters(in: .whitespacesAndNewlines).split(separator: ":")
        guard parts.count == 2,
              parts[0].range(of: "^[a-f0-9]{48}$", options: .regularExpression) != nil,
              let keyData = Data(base64URLString: String(parts[1])),
              keyData.count == 32 else {
            status = "Paste the complete invitation code, including its private key."
            return
        }
        invitationCode = String(parts[0])
        callKey = SymmetricKey(data: keyData)
        invitation = suppliedInvitation.trimmingCharacters(in: .whitespacesAndNewlines)
        isBusy = true
        defer { isBusy = false }
        do {
            try await connect(code: invitationCode, video: video, base: base)
        } catch {
            status = "Could not join call: \(error.localizedDescription)"
        }
    }

    private func connect(code: String, video: Bool, base: URL) async throws {
        let name = displayName.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !name.isEmpty, name.utf16.count <= 32 else {
            throw CallClientError.invalidDisplayName
        }
        status = "Connecting..."
        let response = try await request(base: base, path: "/api/token",
                                         body: ["invitationCode": code, "displayName": name])
        guard let serverURL = response["serverUrl"] as? String,
              let token = response["token"] as? String else {
            throw CallClientError.invalidResponse
        }
        do {
            try await room.connect(url: serverURL, token: token,
                                   connectOptions: ConnectOptions(enableMicrophone: true))
        } catch {
            await room.disconnect()
            throw error
        }
        isConnected = true
        status = "Connected. Turning video on or off does not end the voice call."
        isMuted = false
        if video {
            do {
                try await room.localParticipant.setCamera(enabled: true)
                isVideoEnabled = true
            } catch {
                status = "Connected with voice. Camera could not be started: \(error.localizedDescription)"
            }
        }
    }

    func toggleMicrophone() async {
        do {
            try await room.localParticipant.setMicrophone(enabled: isMuted)
            isMuted.toggle()
        } catch {
            status = "Could not change microphone state: \(error.localizedDescription)"
        }
    }

    func toggleVideo() async {
        do {
            try await room.localParticipant.setCamera(enabled: !isVideoEnabled)
            isVideoEnabled.toggle()
        } catch {
            status = "Could not change camera state: \(error.localizedDescription)"
        }
    }

    func leave() async {
        await room.disconnect()
        isConnected = false
        isVideoEnabled = false
        isMuted = false
        status = "Call ended."
        closeIncomingFile(removePartial: true)
    }

    func sendChat(_ text: String) async {
        let message = text.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !message.isEmpty else { return }
        do {
            try await publishEncrypted(["kind": "chat", "text": String(message.prefix(2000))])
            chatMessages.append("You: \(String(message.prefix(2000)))")
        } catch {
            status = "Could not send chat: \(error.localizedDescription)"
        }
    }

    func sendFile(_ url: URL) async {
        guard url.startAccessingSecurityScopedResource() else {
            status = "The selected file is not accessible."
            return
        }
        defer { url.stopAccessingSecurityScopedResource() }
        do {
            let attributes = try FileManager.default.attributesOfItem(atPath: url.path)
            guard let size = attributes[.size] as? NSNumber,
                  size.int64Value >= 0, size.int64Value <= maxCallFileBytes else {
                throw CallClientError.fileTooLarge
            }
            isTransferring = true
            defer { isTransferring = false }
            let transferID = UUID().uuidString.lowercased()
            let safeName = String(url.lastPathComponent.filter {
                !$0.isNewline && $0 != "/" && $0 != "\\"
            }.prefix(100))
            try await publishEncrypted(["kind": "file-start", "id": transferID,
                                        "name": safeName, "size": size.int64Value])
            let input = try FileHandle(forReadingFrom: url)
            defer { try? input.close() }
            var sentBytes: Int64 = 0
            while true {
                let chunk = try input.read(upToCount: callFileChunkBytes) ?? Data()
                if chunk.isEmpty { break }
                try await publishEncrypted(["kind": "file-chunk", "id": transferID,
                                           "data": chunk.base64EncodedString()])
                sentBytes += Int64(chunk.count)
            }
            guard sentBytes == size.int64Value else {
                throw CallClientError.fileChanged
            }
            try await publishEncrypted(["kind": "file-end", "id": transferID])
            chatMessages.append("You shared a file: \(safeName)")
            status = "Encrypted file sent: \(safeName)."
        } catch {
            status = "Could not send file: \(error.localizedDescription)"
        }
    }

    func room(_ room: Room,
              participant: RemoteParticipant?,
              didReceiveData data: Data,
              forTopic topic: String,
              encryptionType: EncryptionType) {
        guard topic == callDataTopic else { return }
        Task { @MainActor in
            do {
                try receiveEncrypted(data)
            } catch {
                status = "Rejected invalid or unauthenticated in-call data: \(error.localizedDescription)"
                closeIncomingFile(removePartial: true)
            }
        }
    }

    private func publishEncrypted(_ payload: [String: Any]) async throws {
        guard let callKey else { throw CallClientError.missingInvitationKey }
        let plaintext = try JSONSerialization.data(withJSONObject: payload)
        let nonce = AES.GCM.Nonce()
        let sealed = try AES.GCM.seal(plaintext, using: callKey, nonce: nonce,
                                      authenticating: Data(invitationCode.utf8))
        var ciphertextAndTag = sealed.ciphertext
        ciphertextAndTag.append(sealed.tag)
        let envelope: [String: Any] = [
            "v": 1,
            "iv": Data(nonce).base64EncodedString(),
            "ct": ciphertextAndTag.base64EncodedString()
        ]
        let data = try JSONSerialization.data(withJSONObject: envelope)
        guard data.count < 14000 else { throw CallClientError.packetTooLarge }
        try await room.localParticipant.publish(
            data: data,
            options: DataPublishOptions(topic: callDataTopic, reliable: true)
        )
    }

    private func receiveEncrypted(_ data: Data) throws {
        guard let callKey,
              let envelope = try JSONSerialization.jsonObject(with: data) as? [String: Any],
              envelope["v"] as? Int == 1,
              let ivText = envelope["iv"] as? String,
              let cipherText = envelope["ct"] as? String,
              let iv = Data(base64Encoded: ivText),
              let combined = Data(base64Encoded: cipherText),
              iv.count == 12, combined.count >= 16, combined.count <= 14000 else {
            throw CallClientError.invalidEnvelope
        }
        let nonce = try AES.GCM.Nonce(data: iv)
        let tagStart = combined.count - 16
        let box = try AES.GCM.SealedBox(nonce: nonce,
                                        ciphertext: combined.prefix(tagStart),
                                        tag: combined.suffix(16))
        let clear = try AES.GCM.open(box, using: callKey,
                                     authenticating: Data(invitationCode.utf8))
        guard let payload = try JSONSerialization.jsonObject(with: clear) as? [String: Any],
              let kind = payload["kind"] as? String else {
            throw CallClientError.invalidEnvelope
        }
        switch kind {
        case "chat":
            guard let text = payload["text"] as? String else { throw CallClientError.invalidEnvelope }
            chatMessages.append("Friend: \(String(text.prefix(2000)))")
        case "file-start":
            try beginIncomingFile(payload)
        case "file-chunk":
            try appendIncomingChunk(payload)
        case "file-end":
            try finishIncomingFile(payload)
        default:
            throw CallClientError.invalidEnvelope
        }
    }

    private func beginIncomingFile(_ payload: [String: Any]) throws {
        guard let id = payload["id"] as? String,
              UUID(uuidString: id) != nil,
              let name = payload["name"] as? String,
              let size = payload["size"] as? Int64,
              size >= 0, size <= maxCallFileBytes else {
            throw CallClientError.invalidFileTransfer
        }
        closeIncomingFile(removePartial: true)
        let safeName = String(name.filter { !$0.isNewline && $0 != "/" && $0 != "\\" }.prefix(100))
        let destination = FileManager.default.temporaryDirectory
            .appendingPathComponent("ussd-call-\(UUID().uuidString)-\(safeName)")
        guard FileManager.default.createFile(atPath: destination.path, contents: nil) else {
            throw CallClientError.cannotCreateFile
        }
        incomingFileHandle = try FileHandle(forWritingTo: destination)
        incomingFileURLInternal = destination
        incomingFileID = id
        incomingFileName = safeName
        incomingFileExpectedSize = size
        incomingFileBytes = 0
        chatMessages.append("Receiving encrypted file: \(safeName)")
    }

    private func appendIncomingChunk(_ payload: [String: Any]) throws {
        guard payload["id"] as? String == incomingFileID,
              let encoded = payload["data"] as? String,
              let chunk = Data(base64Encoded: encoded),
              chunk.count <= callFileChunkBytes,
              incomingFileBytes + Int64(chunk.count) <= incomingFileExpectedSize,
              let handle = incomingFileHandle else {
            throw CallClientError.invalidFileTransfer
        }
        try handle.write(contentsOf: chunk)
        incomingFileBytes += Int64(chunk.count)
    }

    private func finishIncomingFile(_ payload: [String: Any]) throws {
        guard payload["id"] as? String == incomingFileID,
              incomingFileBytes == incomingFileExpectedSize,
              let fileURL = incomingFileURLInternal else {
            throw CallClientError.invalidFileTransfer
        }
        try incomingFileHandle?.close()
        incomingFileHandle = nil
        incomingFileID = nil
        incomingFileURLInternal = nil
        incomingFileURL = fileURL
        status = "Encrypted file received: \(incomingFileName). Use the button to save or share it."
    }

    private func closeIncomingFile(removePartial: Bool) {
        try? incomingFileHandle?.close()
        incomingFileHandle = nil
        if removePartial, let url = incomingFileURLInternal {
            try? FileManager.default.removeItem(at: url)
        }
        incomingFileID = nil
        incomingFileURLInternal = nil
        incomingFileBytes = 0
    }

    private func validatedServiceURL() -> URL? {
        let raw = serviceURL.trimmingCharacters(in: .whitespacesAndNewlines)
        guard var components = URLComponents(string: raw),
              components.scheme == "https", components.host != nil,
              components.user == nil, components.password == nil,
              components.query == nil, components.fragment == nil else {
            status = "Enter the HTTPS call service URL."
            return nil
        }
        while components.path.hasSuffix("/") {
            components.path.removeLast()
        }
        guard let url = components.url else {
            status = "Enter a valid HTTPS call service URL."
            return nil
        }
        return url
    }

    private func request(base: URL, path: String, body: [String: Any]) async throws -> [String: Any] {
        let url = URL(string: path, relativeTo: base)?.absoluteURL
        guard let url else { throw CallClientError.invalidServiceURL }
        var request = URLRequest(url: url)
        request.httpMethod = "POST"
        request.timeoutInterval = 15
        request.setValue("application/json", forHTTPHeaderField: "Content-Type")
        request.httpBody = try JSONSerialization.data(withJSONObject: body)
        let (data, response) = try await URLSession.shared.data(for: request)
        guard let http = response as? HTTPURLResponse else { throw CallClientError.invalidResponse }
        guard (200..<300).contains(http.statusCode) else {
            let reason = (try? JSONSerialization.jsonObject(with: data) as? [String: Any])?["error"] as? String
            throw CallClientError.serviceRejected(reason ?? "HTTP \(http.statusCode)")
        }
        guard let json = try JSONSerialization.jsonObject(with: data) as? [String: Any] else {
            throw CallClientError.invalidResponse
        }
        return json
    }
}

private enum CallClientError: LocalizedError {
    case invalidServiceURL
    case invalidDisplayName
    case invalidResponse
    case serviceRejected(String)
    case missingInvitationKey
    case invalidEnvelope
    case invalidFileTransfer
    case cannotCreateFile
    case fileTooLarge
    case fileChanged
    case packetTooLarge

    var errorDescription: String? {
        switch self {
        case .invalidServiceURL: return "The call service URL is invalid."
        case .invalidDisplayName: return "Enter a display name of 1-32 characters."
        case .invalidResponse: return "The call service returned an invalid response."
        case .serviceRejected(let reason): return "The call service rejected the request: \(reason)."
        case .missingInvitationKey: return "The invitation key is missing."
        case .invalidEnvelope: return "The encrypted message format is invalid."
        case .invalidFileTransfer: return "The encrypted file transfer is invalid or incomplete."
        case .cannotCreateFile: return "A temporary file could not be created."
        case .fileTooLarge: return "Files must be 50 MB or smaller."
        case .fileChanged: return "The selected file changed while it was being sent."
        case .packetTooLarge: return "An encrypted message exceeded the transport packet limit."
        }
    }
}

private extension Data {
    func base64URLEncodedString() -> String {
        base64EncodedString()
            .replacingOccurrences(of: "+", with: "-")
            .replacingOccurrences(of: "/", with: "_")
            .replacingOccurrences(of: "=", with: "")
    }

    init?(base64URLString: String) {
        var value = base64URLString
            .replacingOccurrences(of: "-", with: "+")
            .replacingOccurrences(of: "_", with: "/")
        let remainder = value.count % 4
        if remainder != 0 { value += String(repeating: "=", count: 4 - remainder) }
        self.init(base64Encoded: value)
    }
}
