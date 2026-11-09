import Foundation

public struct ChatMessage {
    public let to: String
    public let payload: String
}

public final class OfflineQueue {
    private var pending: [ChatMessage] = []
    private let url: URL

    public init(url: URL) { self.url = url }
    public func enqueue(_ message: ChatMessage) { pending.append(message); persist() }
    public func drain(_ send: (ChatMessage) throws -> Void) throws {
        while !pending.isEmpty {
            let item = pending.removeFirst()
            do { try send(item) }
            catch { pending.insert(item, at: 0); persist(); throw error }
        }
        persist()
    }
    private func persist() {
        let text = pending.map { "\($0.to)\t\($0.payload)" }.joined(separator: "\n")
        try? text.data(using: .utf8)?.write(to: url, options: .atomic)
    }
}

public protocol CallEngine {
    func startVoice(peer: String)
    func startVideo(peer: String)
    func stop()
}

public protocol GroupCallEngine {
    func join(room: String)
    func leave(room: String)
    func setMuted(_ muted: Bool)
}

public protocol EncryptedFileTransfer {
    func offer(peer: String, file: URL)
    func accept(id: String, destination: URL)
    func cancel(id: String)
}

public protocol NotificationGateway {
    func show(title: String, body: String)
}
