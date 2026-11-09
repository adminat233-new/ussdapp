import SwiftUI
import UIKit

struct MobileMessagingView: View {
    @State private var relayHost = ""
    @State private var relayPort = ""
    @State private var ownNumber = ""
    @State private var relayToken = ""
    @State private var recipient = ""
    @State private var message = ""
    @State private var status = "Not connected."
    @State private var eventLog = ""
    @State private var session: MobileMessagingSession?

    var body: some View {
        Form {
            Section("Relay connection") {
                TextField("Relay hostname or IP", text: $relayHost)
                    .textInputAutocapitalization(.never)
                    .autocorrectionDisabled()
                TextField("Relay TCP port", text: $relayPort)
                    .keyboardType(.numberPad)
                TextField("Your app number", text: $ownNumber)
                    .keyboardType(.numberPad)
                SecureField("Relay registration token", text: $relayToken)
                Button("Connect to relay (TLS)", action: connect)
                Text(status).font(.footnote)
                Text("Relay transport uses TLS with system certificate and hostname validation. Use a DNS name covered by the relay certificate; never bypass certificate warnings.")
                    .font(.footnote)
                    .foregroundColor(.secondary)
            }
            Section("Encrypted in-app chat") {
                TextField("Recipient app number", text: $recipient)
                    .keyboardType(.numberPad)
                TextField("Message", text: $message, axis: .vertical)
                    .lineLimit(2...5)
                Button("Send encrypted message", action: sendMessage)
                Text("Uses signed identity keys and the existing Windows ECHATK envelope. This is in-app chat, not carrier SMS.")
                    .font(.footnote)
                    .foregroundColor(.secondary)
            }
            Section("Connection and message events") {
                Text(eventLog.isEmpty ? "No relay activity." : eventLog)
                    .font(.footnote)
                    .textSelection(.enabled)
            }
        }
        .navigationTitle("Secure chat")
        .onDisappear {
            session?.close()
            session = nil
        }
    }

    private func connect() {
        guard let port = UInt16(relayPort), port > 0,
              !relayHost.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty,
              ownNumber.range(of: "^[0-9]{4,20}$", options: .regularExpression) != nil,
              !relayToken.isEmpty else {
            status = "Enter a relay host, valid TCP port, 4-20 digit app number, and registration token."
            return
        }
        session?.close()
        do {
            let identity = try WindowsSealedMessage(number: ownNumber)
            let client = RelayClient(
                host: relayHost,
                port: port,
                identity: identity,
                machineName: UIDevice.current.name
            )
            let newSession = MobileMessagingSession(relay: client, identity: identity)
            newSession.onEvent = { event in
                DispatchQueue.main.async {
                    eventLog += (eventLog.isEmpty ? "" : "\n") + event
                }
            }
            session = newSession
            status = "Connecting…"
            newSession.connect(token: relayToken) { error in
                DispatchQueue.main.async {
                    status = error.map { "Connection failed: \($0.localizedDescription)" } ?? "Registered and connected."
                }
            }
        } catch {
            status = "Could not create secure identity: \(error.localizedDescription)"
        }
    }

    private func sendMessage() {
        guard let session = session else {
            status = "Connect to a relay before sending a message."
            return
        }
        session.sendChat(to: recipient, text: message)
        message = ""
    }
}
