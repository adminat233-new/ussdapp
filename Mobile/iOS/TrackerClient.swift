import Foundation
import Security

public struct TrackerReply {
    public let ok: Bool
    public let status: Int
    public let body: String
}

public struct TrackerCredentials {
    public let deviceId: String
    public let token: String
}

public enum TrackerCredentialError: Error {
    case keychain(OSStatus)
    case invalidData
}

public final class TrackerCredentialStore {
    private let service = Bundle.main.bundleIdentifier ?? "com.ussdapp.mobile"
    private let account = "tracker-device-credentials"

    public init() {}

    public func save(deviceId: String, token: String) throws {
        guard !deviceId.isEmpty, !token.isEmpty else { throw TrackerCredentialError.invalidData }
        let data = try JSONSerialization.data(withJSONObject: [
            "deviceId": deviceId,
            "token": token
        ])
        let query = keychainQuery()
        let status = SecItemCopyMatching(query as CFDictionary, nil)
        if status == errSecSuccess {
            let updateStatus = SecItemUpdate(
                query as CFDictionary,
                [kSecValueData as String: data] as CFDictionary
            )
            guard updateStatus == errSecSuccess else { throw TrackerCredentialError.keychain(updateStatus) }
        } else if status == errSecItemNotFound {
            var addQuery = query
            addQuery[kSecValueData as String] = data
            addQuery[kSecAttrAccessible as String] = kSecAttrAccessibleWhenUnlockedThisDeviceOnly
            let addStatus = SecItemAdd(addQuery as CFDictionary, nil)
            guard addStatus == errSecSuccess else { throw TrackerCredentialError.keychain(addStatus) }
        } else {
            throw TrackerCredentialError.keychain(status)
        }
    }

    public func load() throws -> TrackerCredentials? {
        var query = keychainQuery()
        query[kSecReturnData as String] = true
        query[kSecMatchLimit as String] = kSecMatchLimitOne
        var result: CFTypeRef?
        let status = SecItemCopyMatching(query as CFDictionary, &result)
        if status == errSecItemNotFound { return nil }
        guard status == errSecSuccess, let data = result as? Data,
              let value = try JSONSerialization.jsonObject(with: data) as? [String: String],
              let deviceId = value["deviceId"], let token = value["token"],
              !deviceId.isEmpty, !token.isEmpty else {
            throw TrackerCredentialError.invalidData
        }
        return TrackerCredentials(deviceId: deviceId, token: token)
    }

    public func clear() throws {
        let status = SecItemDelete(keychainQuery() as CFDictionary)
        guard status == errSecSuccess || status == errSecItemNotFound else {
            throw TrackerCredentialError.keychain(status)
        }
    }

    private func keychainQuery() -> [String: Any] {
        [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: account
        ]
    }
}

/// Consent-only bridge to laptop-tracker HTTP endpoints.
public final class TrackerClient {
    private let base: URL
    private let redirectBlocker: TrackerRedirectBlocker
    private let session: URLSession
    private let token: String?
    public init?(baseUrl: String, token: String? = nil) {
        guard let u = URL(string: baseUrl),
              u.scheme == "https", u.host != nil, u.user == nil, u.password == nil else { return nil }
        base = u
        self.token = token
        let blocker = TrackerRedirectBlocker()
        redirectBlocker = blocker
        session = URLSession(configuration: .ephemeral, delegate: blocker, delegateQueue: nil)
    }

    public func generatePair(deviceType: String, completion: @escaping (TrackerReply) -> Void) {
        post(path: "/api/v2/pair/generate", body: ["deviceType": deviceType], completion: completion)
    }
    public func verifyPair(pairCode: String, completion: @escaping (TrackerReply) -> Void) {
        post(path: "/api/v2/pair/verify", body: ["pairCode": pairCode, "deviceType": "phone"], completion: completion)
    }
    public func pairInfo(deviceId: String, completion: @escaping (TrackerReply) -> Void) {
        guard let encodedId = deviceId.addingPercentEncoding(withAllowedCharacters: .urlQueryAllowed) else {
            completion(TrackerReply(ok: false, status: 0, body: "invalid-device-id"))
            return
        }
        get(path: "/api/v2/pair-info?deviceId=\(encodedId)", completion: completion)
    }
    public func heartbeat(deviceId: String, lat: Double?, lng: Double?, source: String,
                          completion: @escaping (TrackerReply) -> Void) {
        var body: [String: Any] = ["deviceId": deviceId, "location": NSNull()]
        if let lat = lat, let lng = lng {
            body["location"] = ["lat": lat, "lng": lng, "source": source]
        }
        post(path: "/api/v2/heartbeat", body: body, completion: completion)
    }
    public func lostMode(deviceId: String, active: Bool, completion: @escaping (TrackerReply) -> Void) {
        post(path: "/api/v2/lost-mode", body: ["deviceId": deviceId, "active": active], completion: completion)
    }
    public func revokeDevice(deviceId: String, targetDeviceId: String,
                             completion: @escaping (TrackerReply) -> Void) {
        post(path: "/api/v2/revoke-device",
             body: ["deviceId": deviceId, "targetDeviceId": targetDeviceId],
             completion: completion)
    }

    private func get(path: String, completion: @escaping (TrackerReply) -> Void) {
        guard let url = URL(string: path, relativeTo: base) else {
            completion(TrackerReply(ok: false, status: 0, body: "invalid-url"))
            return
        }
        var req = URLRequest(url: url)
        req.httpMethod = "GET"
        req.timeoutInterval = 10
        if let token = token { req.setValue("Bearer \(token)", forHTTPHeaderField: "Authorization") }
        send(req, completion: completion)
    }

    private func post(path: String, body: Any, completion: @escaping (TrackerReply) -> Void) {
        guard let url = URL(string: path, relativeTo: base) else {
            completion(TrackerReply(ok: false, status: 0, body: "invalid-url"))
            return
        }
        var req = URLRequest(url: url)
        req.httpMethod = "POST"
        req.setValue("application/json", forHTTPHeaderField: "Content-Type")
        req.setValue("application/json", forHTTPHeaderField: "Accept")
        req.timeoutInterval = 10
        do {
            req.httpBody = try JSONSerialization.data(withJSONObject: body, options: [])
        } catch {
            completion(TrackerReply(ok: false, status: 0, body: error.localizedDescription))
            return
        }
        if let token = token { req.setValue("Bearer \(token)", forHTTPHeaderField: "Authorization") }
        send(req, completion: completion)
    }

    private func send(_ req: URLRequest, completion: @escaping (TrackerReply) -> Void) {
        session.dataTask(with: req) { data, res, error in
            let status = (res as? HTTPURLResponse)?.statusCode ?? 0
            let body = data.map { String(decoding: $0, as: UTF8.self) }
                ?? error?.localizedDescription
                ?? ""
            let ok = (200...299).contains(status) &&
                body.range(of: "\"success\":true", options: .caseInsensitive) != nil
            completion(TrackerReply(ok: ok, status: status, body: body))
        }.resume()
    }
}

private final class TrackerRedirectBlocker: NSObject, URLSessionTaskDelegate {
    func urlSession(_ session: URLSession, task: URLSessionTask,
                    willPerformHTTPRedirection response: HTTPURLResponse,
                    newRequest request: URLRequest,
                    completionHandler: @escaping (URLRequest?) -> Void) {
        completionHandler(nil)
    }
}
