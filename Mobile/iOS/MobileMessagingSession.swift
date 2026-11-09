import Foundation
import Combine

/// Windows-compatible secure in-app text messaging over existing relay verbs.
/// Payloads use the Windows ECHATK format and are never sent unsealed.
@MainActor
public final class MobileMessagingSession: ObservableObject {
    @Published public private(set) var events: [String] = []
    public var onEvent: ((String) -> Void)?

    private let relay: RelayClient
    private let identity: WindowsSealedMessage
    private var peerKeys: [String: String] = [:]
    private var blockedPeers = Set<String>()
    private var pending: [(String, String)] = []
    private let preferences = UserDefaults.standard

    public init(relay: RelayClient, identity: WindowsSealedMessage) {
        self.relay = relay
        self.identity = identity
        relay.onLine = { [weak self] line in
            Task { @MainActor in self?.receive(line) }
        }
    }

    public func connect(token: String, completion: @escaping (Error?) -> Void) {
        relay.connect { [weak self] result in
            guard let self = self else { return }
            switch result {
            case .failure(let error):
                completion(error)
            case .success:
                self.relay.register(token: token) { registration in
                    DispatchQueue.main.async {
                        switch registration {
                        case .failure(let error):
                            self.relay.close()
                            completion(error)
                        case .success:
                            do {
                                let keyLine = try self.identity.publishKeyLine()
                                self.relay.sendControl(keyLine) { error in
                                    DispatchQueue.main.async {
                                        if let error = error {
                                            self.relay.close()
                                            completion(error)
                                            return
                                        }
                                        self.append("Registered #\(self.identity.number) using Windows-compatible secure mail.")
                                        completion(nil)
                                    }
                                }
                            } catch {
                                self.relay.close()
                                completion(error)
                            }
                        }
                    }
                }
            }
        }
    }

    public func sendChat(to: String, text: String) {
        guard to.range(of: "^[0-9]{4,20}$", options: .regularExpression) != nil,
              !text.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty,
              text.count <= 10000 else {
            append("Enter a valid app number and a message of 1-10000 characters.")
            return
        }
        guard !blockedPeers.contains(to) else {
            append("Messaging #\(to) is blocked because its identity key changed.")
            return
        }
        if let key = peerKeys[to] ?? preferences.string(forKey: peerPreferenceKey(to)) {
            sendSealed(to: to, publicKey: key, text: text)
            return
        }
        guard pending.count < 20 else {
            append("Too many messages are waiting for peer keys.")
            return
        }
        pending.append((to, text))
        relay.sendControl("PKQ|\(to)") { [weak self] error in
            if let error = error {
                Task { @MainActor in
                    self?.pending.removeAll { $0.0 == to && $0.1 == text }
                    self?.append("Could not request the peer key: \(error.localizedDescription)")
                }
            }
        }
        append("Requesting #\(to)'s signed identity key; message remains in memory until it arrives.")
    }

    public func close() { relay.close() }

    private func receive(_ line: String) {
        let fields = line.split(separator: "|", maxSplits: 3, omittingEmptySubsequences: false).map(String.init)
        guard let verb = fields.first else { return }
        switch verb {
        case "PKPUB":
            guard fields.count == 4 else { return }
            let number = fields[1]
            let key = fields[2]
            guard WindowsSealedMessage.verifyPublishedKey(number: number, key: key, signature: fields[3]) else {
                append("Rejected an invalid identity-key proof for #\(number).")
                return
            }
            let prefKey = peerPreferenceKey(number)
            if let old = preferences.string(forKey: prefKey), old != key {
                peerKeys.removeValue(forKey: number)
                blockedPeers.insert(number)
                discardPending(number: number)
                append("SECURITY WARNING: #\(number)'s identity key changed to \(WindowsSealedMessage.fingerprint(of: key)). Messages are blocked.")
                return
            }
            if preferences.string(forKey: prefKey) == nil {
                preferences.set(key, forKey: prefKey)
                append("First-seen key pinned for #\(number): \(WindowsSealedMessage.fingerprint(of: key)). Verify this fingerprint out of band.")
            }
            blockedPeers.remove(number)
            peerKeys[number] = key
            flushPending(number: number, key: key)
        case "PKNONE":
            let number = fields.dropFirst().first ?? "?"
            discardPending(number: number)
            append("Relay has no published identity key for #\(number); queued messages were not sent.")
        case "MSG":
            if fields.count >= 4 { receiveMessage(from: fields[2], wire: fields[3]) }
        case "ERR", "CLIENT_ERROR":
            append("Relay: \(line)")
        case "UNDELIVERABLE":
            append("Message could not be delivered: \(line)")
        default:
            break
        }
    }

    private func receiveMessage(from: String, wire: String) {
        guard !blockedPeers.contains(from) else {
            append("Rejected message from #\(from) because its identity key changed.")
            return
        }
        guard wire.hasPrefix("ECHATK|") else {
            append("Rejected unsealed or unsupported message content from #\(from).")
            return
        }
        guard let key = peerKeys[from] ?? preferences.string(forKey: peerPreferenceKey(from)) else {
            relay.sendControl("PKQ|\(from)", completion: nil)
            append("Message from #\(from) held until its signed identity key arrives.")
            return
        }
        do {
            guard let opened = try identity.open(
                wire: wire,
                expectedFrom: from,
                expectedTo: identity.number,
                senderPublicKey: key
            ) else {
                append("Rejected an unauthenticated or misaddressed message from #\(from).")
                return
            }
            append("CHAT|#\(from)|\(opened.text)")
            relay.sendMessage(to: from, line: "CHATACK|", completion: nil)
        } catch {
            append("Could not open message from #\(from): \(error.localizedDescription)")
        }
    }

    private func sendSealed(to: String, publicKey: String, text: String) {
        do {
            let wire = try identity.seal(to: to, recipientPublicKey: publicKey, chatText: text)
            relay.sendMessage(to: to, line: wire) { [weak self] error in
                if let error = error {
                    Task { @MainActor in self?.append("Message send failed: \(error.localizedDescription)") }
                } else {
                    Task { @MainActor in self?.append("CHAT|You| \(text)") }
                }
            }
        } catch {
            append("Could not seal message: \(error.localizedDescription)")
        }
    }

    private func flushPending(number: String, key: String) {
        let ready = pending.filter { $0.0 == number }
        pending.removeAll { $0.0 == number }
        for (_, text) in ready {
            sendSealed(to: number, publicKey: key, text: text)
        }
    }

    private func discardPending(number: String) {
        pending.removeAll { $0.0 == number }
    }

    private func peerPreferenceKey(_ number: String) -> String { "mobile.trustedPeer.\(number)" }

    private func append(_ value: String) {
        events.append(value)
        if events.count > 200 { events.removeFirst(events.count - 200) }
        onEvent?(value)
    }
}
