import Foundation
import Network

public enum RelayClientError: Error {
    case notConnected
    case invalidField
    case invalidMessage
    case relayClosed
    case relayError(String)
}

/// Newline-framed relay transport. Callers must provide an identity backed by
/// the iOS Keychain/Secure Enclave and must perform UI permission requests
/// before constructing a client for a user-facing feature.
public final class RelayClient {
    private let connection: NWConnection
    private let identity: RelayIdentity
    private let machineName: String
    private var buffer = Data()
    private var connected = false
    public var onLine: ((String) -> Void)?
    private var receiving = false
    private let stateLock = NSLock()
    private var connectCompleted = false

    public init(host: String, port: UInt16, identity: RelayIdentity, machineName: String) {
        self.connection = NWConnection(
            host: NWEndpoint.Host(host),
            port: NWEndpoint.Port(rawValue: port)!,
            using: .tls
        )
        self.identity = identity
        self.machineName = machineName
    }

    public func connect(timeout: TimeInterval = 5,
                        completion: @escaping (Result<Void, Error>) -> Void) {
        let queue = DispatchQueue(label: "com.ussdapp.relay")
        connection.stateUpdateHandler = { [weak self] state in
            switch state {
            case .ready:
                self?.finishConnect(.success(()), completion: completion)
            case .failed(let error):
                self?.finishConnect(.failure(error), completion: completion)
            case .cancelled:
                self?.finishConnect(.failure(RelayClientError.notConnected), completion: completion)
            default:
                break
            }
        }
        connection.start(queue: queue)
        queue.asyncAfter(deadline: .now() + timeout) { [weak self] in
            guard let self = self else { return }
            self.finishConnect(.failure(RelayClientError.notConnected), completion: completion)
            self.stateLock.lock()
            let shouldCancel = !self.connected
            self.stateLock.unlock()
            guard shouldCancel else { return }
            self.connection.cancel()
        }
    }

    public func register(token: String, completion: @escaping (Result<String, Error>) -> Void) {
        do {
            let proof = try identity.signOwnsClaim()
            guard !proof.isEmpty else { throw RelayClientError.invalidMessage }
            let numberField = try field(identity.number)
            let tokenField = try field(token)
            let machineNameField = try field(machineName)
            let publicKeyField = try field(identity.publicKey)
            let proofField = try field(proof)
            let line = "REG|\(numberField)|\(tokenField)|" +
                "\(machineNameField)|\(publicKeyField)|\(proofField)"
            send(line, expectResponse: true) { result in
                switch result {
                case .success(let line):
                    if line.hasPrefix("ERR|") {
                        completion(.failure(RelayClientError.relayError(line)))
                    } else {
                        self.startReceiving()
                        completion(.success(line))
                    }
                case .failure(let error):
                    completion(.failure(error))
                }
            }
        } catch {
            completion(.failure(error))
        }
    }

    public func keepAlive(completion: ((Error?) -> Void)? = nil) {
        send("KA|", expectResponse: false) { result in
            if case .failure(let error) = result { completion?(error) }
            else { completion?(nil) }
        }
    }

    public func sendMessage(to: String, line: String,
                            completion: ((Error?) -> Void)? = nil) {
        guard line.hasPrefix("ECHAT|") || line.hasPrefix("KEYX|") ||
                line.hasPrefix("ECHATK|") || line.hasPrefix("KEYXOK|") ||
                line.hasPrefix("CALL|") || line == "CHATACK|" else {
            completion?(RelayClientError.invalidMessage)
            return
        }
        do {
            let target = try field(to)
            let sender = try field(identity.number)
            send("MSG|\(target)|\(sender)|\(line)", expectResponse: false) { result in
                if case .failure(let error) = result { completion?(error) }
                else { completion?(nil) }
            }
        } catch {
            completion?(error)
        }
    }

    public func sendControl(_ line: String, completion: ((Error?) -> Void)? = nil) {
        guard line.hasPrefix("PUBK|") || line.hasPrefix("PKQ|") else {
            completion?(RelayClientError.invalidMessage)
            return
        }
        send(line, expectResponse: false) { result in
            if case .failure(let error) = result { completion?(error) }
            else { completion?(nil) }
        }
    }

    public func startReceiving() {
        guard connected && !receiving else { return }
        receiving = true
        receiveNext()
    }

    public func close() {
        if connected { send("QUIT|", expectResponse: false) { _ in } }
        connection.cancel()
        connected = false
        receiving = false
    }

    private func receiveNext() {
        guard connected && receiving else { return }
        connection.receive(minimumIncompleteLength: 1, maximumLength: 65536) {
            [weak self] data, _, isComplete, error in
            guard let self = self else { return }
            if let error = error {
                self.receiving = false
                self.onLine?("CLIENT_ERROR|\(error.localizedDescription)")
                return
            }
            if let data = data { self.buffer.append(data) }
            while let newline = self.buffer.firstIndex(of: 10) {
                let lineData = self.buffer.subdata(in: self.buffer.startIndex..<newline)
                self.buffer.removeSubrange(self.buffer.startIndex...newline)
                self.onLine?(String(decoding: lineData, as: UTF8.self))
            }
            if isComplete {
                self.receiving = false
                self.onLine?("CLIENT_ERROR|relay closed the connection")
            } else {
                self.receiveNext()
            }
        }
    }

    private func send(_ line: String, expectResponse: Bool,
                      completion: @escaping (Result<String, Error>) -> Void) {
        guard connected else {
            completion(.failure(RelayClientError.notConnected))
            return
        }
        guard !line.contains("\n") && !line.contains("\r") else {
            completion(.failure(RelayClientError.invalidField))
            return
        }
        let payload = Data((line + "\n").utf8)
        connection.send(content: payload, completion: .contentProcessed { [weak self] error in
            if let error = error {
                completion(.failure(error))
                return
            }
            if expectResponse {
                self?.receiveLine(completion: completion)
            } else {
                completion(.success(""))
            }
        })
    }

    private func receiveLine(completion: @escaping (Result<String, Error>) -> Void) {
        connection.receive(minimumIncompleteLength: 1, maximumLength: 65536) {
            [weak self] data, _, isComplete, error in
            if let error = error {
                completion(.failure(error))
                return
            }
            if let data = data { self?.buffer.append(data) }
            if let self = self, let newline = self.buffer.firstIndex(of: 10) {
                let lineData = self.buffer.subdata(in: self.buffer.startIndex..<newline)
                self.buffer.removeSubrange(self.buffer.startIndex...newline)
                completion(.success(String(decoding: lineData, as: UTF8.self)))
            } else if isComplete {
                completion(.failure(RelayClientError.relayClosed))
            } else {
                self?.receiveLine(completion: completion)
            }
        }
    }

    private func field(_ value: String) throws -> String {
        guard !value.contains("|") && !value.contains("\n") && !value.contains("\r") else {
            throw RelayClientError.invalidField
        }
        return value
    }

    private func finishConnect(_ result: Result<Void, Error>,
                               completion: @escaping (Result<Void, Error>) -> Void) {
        stateLock.lock()
        guard !connectCompleted else {
            stateLock.unlock()
            return
        }
        connectCompleted = true
        if case .success = result { connected = true }
        stateLock.unlock()
        completion(result)
    }
}
