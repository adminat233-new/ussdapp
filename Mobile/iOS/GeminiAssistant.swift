import Foundation
import Security

public enum GeminiAssistantError: LocalizedError {
    case invalidKey
    case missingKey
    case invalidPrompt
    case keychain(OSStatus)
    case invalidResponse
    case providerStatus(Int)
    case responseTooLarge

    public var errorDescription: String? {
        switch self {
        case .invalidKey: return "API key length is invalid."
        case .missingKey: return "Add your Gemini API key in AI settings first."
        case .invalidPrompt: return "Prompt must contain 1 to 10000 characters."
        case .keychain(let status): return "Secure key storage failed (status \(status))."
        case .invalidResponse: return "AI provider returned an invalid or empty response."
        case .providerStatus(let status):
            return "AI provider returned HTTP \(status). Check the key, model access, and quota."
        case .responseTooLarge: return "AI provider response exceeded the 1 MiB limit."
        }
    }
}

public final class GeminiAssistant {
    public static let defaultModel = "gemini-2.5-flash"

    private let service = "com.ussdapp.mobile.gemini"
    private let account = "api-key"
    private let redirectBlocker = GeminiRedirectBlocker()
    private lazy var session = URLSession(
        configuration: .ephemeral,
        delegate: redirectBlocker,
        delegateQueue: nil
    )

    public init() {}

    public func hasAPIKey() -> Bool {
        SecItemCopyMatching(keychainQuery(returnData: false) as CFDictionary, nil) == errSecSuccess
    }

    public func saveAPIKey(_ value: String) throws {
        let key = value.trimmingCharacters(in: .whitespacesAndNewlines)
        guard (20...512).contains(key.count) else { throw GeminiAssistantError.invalidKey }
        let data = Data(key.utf8)
        let query = keychainQuery(returnData: false)
        let status = SecItemCopyMatching(query as CFDictionary, nil)
        if status == errSecSuccess {
            let updateStatus = SecItemUpdate(
                query as CFDictionary,
                [kSecValueData as String: data] as CFDictionary
            )
            guard updateStatus == errSecSuccess else { throw GeminiAssistantError.keychain(updateStatus) }
        } else if status == errSecItemNotFound {
            var addQuery = query
            addQuery[kSecValueData as String] = data
            addQuery[kSecAttrAccessible as String] = kSecAttrAccessibleWhenUnlockedThisDeviceOnly
            let addStatus = SecItemAdd(addQuery as CFDictionary, nil)
            guard addStatus == errSecSuccess else { throw GeminiAssistantError.keychain(addStatus) }
        } else {
            throw GeminiAssistantError.keychain(status)
        }
    }

    public func removeAPIKey() throws {
        let status = SecItemDelete(keychainQuery(returnData: false) as CFDictionary)
        guard status == errSecSuccess || status == errSecItemNotFound else {
            throw GeminiAssistantError.keychain(status)
        }
    }

    public func ask(_ prompt: String, completion: @escaping (Result<String, Error>) -> Void) {
        let userPrompt = prompt.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !userPrompt.isEmpty && userPrompt.count <= 10000 else {
            completion(.failure(GeminiAssistantError.invalidPrompt))
            return
        }

        do {
            let apiKey = try readAPIKey()
            guard let url = URL(string:
                "https://generativelanguage.googleapis.com/v1beta/models/" +
                "\(Self.defaultModel):generateContent"
            ), url.scheme == "https", url.host == "generativelanguage.googleapis.com" else {
                completion(.failure(GeminiAssistantError.invalidResponse))
                return
            }
            var request = URLRequest(url: url, timeoutInterval: 45)
            request.httpMethod = "POST"
            request.setValue("application/json; charset=utf-8", forHTTPHeaderField: "Content-Type")
            request.setValue("application/json", forHTTPHeaderField: "Accept")
            request.setValue(apiKey, forHTTPHeaderField: "x-goog-api-key")
            request.httpBody = try JSONSerialization.data(withJSONObject: [
                "contents": [[
                    "parts": [["text": userPrompt]]
                ]],
                "generationConfig": ["maxOutputTokens": 1024]
            ])

            session.dataTask(with: request) { data, response, error in
                if let error = error {
                    completion(.failure(error))
                    return
                }
                guard let http = response as? HTTPURLResponse else {
                    completion(.failure(GeminiAssistantError.invalidResponse))
                    return
                }
                guard let data = data else {
                    completion(.failure(GeminiAssistantError.invalidResponse))
                    return
                }
                guard data.count <= 1024 * 1024 else {
                    completion(.failure(GeminiAssistantError.responseTooLarge))
                    return
                }
                guard (200...299).contains(http.statusCode) else {
                    completion(.failure(GeminiAssistantError.providerStatus(http.statusCode)))
                    return
                }
                do {
                    let json = try JSONSerialization.jsonObject(with: data) as? [String: Any]
                    let candidates = json?["candidates"] as? [[String: Any]]
                    let content = candidates?.first?["content"] as? [String: Any]
                    let parts = content?["parts"] as? [[String: Any]]
                    let text = (parts?.first?["text"] as? String)?
                        .trimmingCharacters(in: .whitespacesAndNewlines)
                    guard let text = text, !text.isEmpty else {
                        completion(.failure(GeminiAssistantError.invalidResponse))
                        return
                    }
                    completion(.success(text))
                } catch {
                    completion(.failure(GeminiAssistantError.invalidResponse))
                }
            }.resume()
        } catch {
            completion(.failure(error))
        }
    }

    private final class GeminiRedirectBlocker: NSObject, URLSessionTaskDelegate {
        func urlSession(
            _ session: URLSession,
            task: URLSessionTask,
            willPerformHTTPRedirection response: HTTPURLResponse,
            newRequest request: URLRequest,
            completionHandler: @escaping (URLRequest?) -> Void
        ) {
            completionHandler(nil)
        }
    }

    private func readAPIKey() throws -> String {
        var query = keychainQuery(returnData: true)
        query[kSecMatchLimit as String] = kSecMatchLimitOne
        var result: CFTypeRef?
        let status = SecItemCopyMatching(query as CFDictionary, &result)
        guard status != errSecItemNotFound else { throw GeminiAssistantError.missingKey }
        guard status == errSecSuccess, let data = result as? Data,
              let value = String(data: data, encoding: .utf8), !value.isEmpty else {
            throw GeminiAssistantError.keychain(status)
        }
        return value
    }

    private func keychainQuery(returnData: Bool) -> [String: Any] {
        var query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: account
        ]
        if returnData { query[kSecReturnData as String] = true }
        return query
    }
}
