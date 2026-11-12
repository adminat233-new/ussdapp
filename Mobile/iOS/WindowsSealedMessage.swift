import CommonCrypto
import Foundation
import Security

public enum WindowsSealedMessageError: LocalizedError {
    case invalidKey
    case keychain(OSStatus)
    case crypto

    public var errorDescription: String? {
        switch self {
        case .invalidKey: return "Invalid Windows-compatible RSA public key."
        case .keychain(let status): return "Secure identity key operation failed (\(status))."
        case .crypto: return "Could not seal or authenticate the message."
        }
    }
}

public final class WindowsSealedMessage: RelayIdentity {
    private static let verb = "ECHATK"
    private static let identityTagPrefix = Data("com.ussdapp.mobile.identity.rsa2048.".utf8)

    public struct Opened {
        public let from: String
        public let to: String
        public let text: String
    }

    public let number: String
    private let privateKey: SecKey
    public let publicKey: String

    public init(number: String) throws {
        guard number.range(of: "^[0-9]{4,20}$", options: .regularExpression) != nil else {
            throw WindowsSealedMessageError.invalidKey
        }
        self.number = number
        privateKey = try Self.loadOrCreateIdentity(number: number)
        guard let publicKeyObject = SecKeyCopyPublicKey(privateKey),
              let data = SecKeyCopyExternalRepresentation(publicKeyObject, nil) as Data?,
              let components = Self.parseRSAComponents(data) else {
            throw WindowsSealedMessageError.invalidKey
        }
        let xml = "<RSAKeyValue><Modulus>\(components.modulus.base64EncodedString())</Modulus>" +
            "<Exponent>\(components.exponent.base64EncodedString())</Exponent></RSAKeyValue>"
        publicKey = Data(xml.utf8).base64EncodedString()
    }

    public func signOwnsClaim() throws -> String {
        try sign("OWNS|\(number)")
    }

    public func publishKeyLine() throws -> String {
        let signature = try sign("PUBK|\(number)")
        return "PUBK|\(number)|\(publicKey)|\(signature)"
    }

    public func seal(to: String, recipientPublicKey: String, chatText: String) throws -> String {
        guard !chatText.isEmpty, chatText.count <= 10000,
              recipientPublicKey.utf8.count <= 8192,
              to.range(of: "^[0-9]{4,20}$", options: .regularExpression) != nil else {
            throw WindowsSealedMessageError.crypto
        }
        let ticks = Int64(Date().timeIntervalSince1970 * 10_000_000) + 621_355_968_000_000_000
        let body = Data("\(number)|\(to)|\(ticks)|CHAT|\(chatText)".utf8)
        var key = Data(count: 48)
        var iv = Data(count: 16)
        guard key.withUnsafeMutableBytes({ SecRandomCopyBytes(kSecRandomDefault, 48, $0.baseAddress!) }) == errSecSuccess,
              iv.withUnsafeMutableBytes({ SecRandomCopyBytes(kSecRandomDefault, 16, $0.baseAddress!) }) == errSecSuccess else {
            throw WindowsSealedMessageError.crypto
        }
        let aesKey = key.prefix(16)
        let macKey = key.suffix(32)
        let ciphertext = try Self.aesCTR(key: Data(aesKey), iv: iv, data: body)
        let tag = Self.hmac(key: Data(macKey), data: iv + ciphertext).prefix(16)
        let recipientKey = try Self.publicRSAKey(xmlBase64: recipientPublicKey)
        guard SecKeyIsAlgorithmSupported(recipientKey, .encrypt, .rsaEncryptionOAEPSHA1),
              let wrappedKey = SecKeyCreateEncryptedData(
                recipientKey,
                .rsaEncryptionOAEPSHA1,
                key as CFData,
                nil
              ) as Data? else {
            throw WindowsSealedMessageError.crypto
        }
        let box = (wrappedKey + iv + tag + ciphertext).base64EncodedString()
        let signature = try sign("\(Self.verb)|\(box)")
        return "\(Self.verb)|\(box)|\(signature)"
    }

    public func open(
        wire: String,
        expectedFrom: String,
        expectedTo: String,
        senderPublicKey: String
    ) throws -> Opened? {
        guard wire.utf8.count <= 65536,
              senderPublicKey.utf8.count <= 8192,
              expectedFrom.range(of: "^[0-9]{4,20}$", options: .regularExpression) != nil,
              expectedTo.range(of: "^[0-9]{4,20}$", options: .regularExpression) != nil else { return nil }
        let fields = wire.split(separator: "|", maxSplits: 2, omittingEmptySubsequences: false)
        guard fields.count == 3, fields[0] == Self.verb,
              let box = Data(base64Encoded: String(fields[1])),
              let signature = Data(base64Encoded: String(fields[2])) else { return nil }
        let senderKey = try Self.publicRSAKey(xmlBase64: senderPublicKey)
        let signedText = Data("\(Self.verb)|\(fields[1])".utf8)
        guard SecKeyIsAlgorithmSupported(senderKey, .verify, .rsaSignatureMessagePKCS1v15SHA256),
              SecKeyVerifySignature(
                senderKey,
                .rsaSignatureMessagePKCS1v15SHA256,
                signedText as CFData,
                signature as CFData,
                nil
              ) else { return nil }

        let ownModulusBytes = (SecKeyCopyAttributes(privateKey) as? [String: Any])?[kSecAttrKeySizeInBits as String] as? Int ?? 2048
        let wrappedBytes = ownModulusBytes / 8
        guard box.count >= wrappedBytes + 33,
              SecKeyIsAlgorithmSupported(privateKey, .decrypt, .rsaEncryptionOAEPSHA1),
              let key = SecKeyCreateDecryptedData(
                privateKey,
                .rsaEncryptionOAEPSHA1,
                box.prefix(wrappedBytes) as CFData,
                nil
              ) as Data?, key.count == 48 else { return nil }
        let iv = box.subdata(in: wrappedBytes..<(wrappedBytes + 16))
        let tag = box.subdata(in: (wrappedBytes + 16)..<(wrappedBytes + 32))
        let ciphertext = box.subdata(in: (wrappedBytes + 32)..<box.count)
        let expectedTag = Self.hmac(key: key.subdata(in: 16..<48), data: iv + ciphertext).prefix(16)
        guard Data(tag) == Data(expectedTag) else { return nil }
        let plain = try Self.aesCTR(key: key.prefix(16), iv: iv, data: ciphertext)
        let body = String(decoding: plain, as: UTF8.self)
            .split(separator: "|", maxSplits: 3, omittingEmptySubsequences: false)
        guard body.count == 4, body[0] == expectedFrom, body[1] == expectedTo,
              body[3].hasPrefix("CHAT|") else { return nil }
        return Opened(from: String(body[0]), to: String(body[1]), text: String(body[3].dropFirst(5)))
    }

    public static func verifyPublishedKey(number: String, key: String, signature: String) -> Bool {
        do {
            guard number.range(of: "^[0-9]{4,20}$", options: .regularExpression) != nil,
                  key.utf8.count <= 8192, signature.utf8.count <= 2048 else { return false }
            let publicKey = try publicRSAKey(xmlBase64: key)
            guard let sig = Data(base64Encoded: signature) else { return false }
            return SecKeyVerifySignature(
                publicKey,
                .rsaSignatureMessagePKCS1v15SHA256,
                Data("PUBK|\(number)".utf8) as CFData,
                sig as CFData,
                nil
            )
        } catch {
            return false
        }
    }

    public static func fingerprint(of key: String) -> String {
        guard key.utf8.count <= 8192 else { return "" }
        let data = Data(key.utf8)
        var digest = [UInt8](repeating: 0, count: Int(CC_SHA256_DIGEST_LENGTH))
        data.withUnsafeBytes {
            CC_SHA256($0.baseAddress, CC_LONG(data.count), &digest)
        }
        let hex = digest.prefix(8).map { String(format: "%02X", Int($0)) }.joined()
        return stride(from: 0, to: hex.count, by: 4).map { start in
            let begin = hex.index(hex.startIndex, offsetBy: start)
            let end = hex.index(begin, offsetBy: 4)
            return String(hex[begin..<end])
        }.joined(separator: "-")
    }

    private func sign(_ value: String) throws -> String {
        guard SecKeyIsAlgorithmSupported(privateKey, .sign, .rsaSignatureMessagePKCS1v15SHA256),
              let signature = SecKeyCreateSignature(
                privateKey,
                .rsaSignatureMessagePKCS1v15SHA256,
                Data(value.utf8) as CFData,
                nil
              ) as Data? else {
            throw WindowsSealedMessageError.crypto
        }
        return signature.base64EncodedString()
    }

    private static func loadOrCreateIdentity(number: String) throws -> SecKey {
        var digest = [UInt8](repeating: 0, count: Int(CC_SHA256_DIGEST_LENGTH))
        let numberBytes = Data(number.utf8)
        numberBytes.withUnsafeBytes {
            CC_SHA256($0.baseAddress, CC_LONG(numberBytes.count), &digest)
        }
        let tag = identityTagPrefix + Data(digest.prefix(12).map { String(format: "%02x", $0) }.joined().utf8)
        var query: [String: Any] = [
            kSecClass as String: kSecClassKey,
            kSecAttrApplicationTag as String: tag,
            kSecAttrKeyType as String: kSecAttrKeyTypeRSA,
            kSecReturnRef as String: true
        ]
        var result: CFTypeRef?
        let status = SecItemCopyMatching(query as CFDictionary, &result)
        if status == errSecSuccess, let key = result as! SecKey? { return key }
        guard status == errSecItemNotFound else { throw WindowsSealedMessageError.keychain(status) }

        let access = SecAccessControlCreateWithFlags(
            nil,
            kSecAttrAccessibleWhenUnlockedThisDeviceOnly,
            [],
            nil
        )
        guard let access = access else { throw WindowsSealedMessageError.crypto }
        let attributes: [String: Any] = [
            kSecAttrKeyType as String: kSecAttrKeyTypeRSA,
            kSecAttrKeySizeInBits as String: 2048,
            kSecPrivateKeyAttrs as String: [
                kSecAttrIsPermanent as String: true,
                kSecAttrApplicationTag as String: tag,
                kSecAttrAccessControl as String: access
            ]
        ]
        guard let privateKey = SecKeyCreateRandomKey(attributes as CFDictionary, nil) else {
            throw WindowsSealedMessageError.crypto
        }
        query.removeValue(forKey: kSecReturnRef as String)
        return privateKey
    }

    private static func publicRSAKey(xmlBase64: String) throws -> SecKey {
        guard let xmlData = Data(base64Encoded: xmlBase64),
              let xml = String(data: xmlData, encoding: .utf8),
              let modulus = xmlComponent("Modulus", in: xml),
              let exponent = xmlComponent("Exponent", in: xml),
              let der = rsaPublicDER(modulus: modulus, exponent: exponent) else {
            throw WindowsSealedMessageError.invalidKey
        }
        let attributes: [String: Any] = [
            kSecAttrKeyType as String: kSecAttrKeyTypeRSA,
            kSecAttrKeyClass as String: kSecAttrKeyClassPublic,
            kSecAttrKeySizeInBits as String: modulus.count * 8
        ]
        guard let key = SecKeyCreateWithData(der as CFData, attributes as CFDictionary, nil) else {
            throw WindowsSealedMessageError.invalidKey
        }
        return key
    }

    private static func xmlComponent(_ name: String, in xml: String) -> Data? {
        guard let start = xml.range(of: "<\(name)>"),
              let end = xml.range(of: "</\(name)>", range: start.upperBound..<xml.endIndex) else { return nil }
        return Data(base64Encoded: String(xml[start.upperBound..<end.lowerBound]))
    }

    private static func parseRSAComponents(_ der: Data) -> (modulus: Data, exponent: Data)? {
        var bytes = [UInt8](der)
        guard bytes.count > 8, bytes.removeFirst() == 0x30, readDERLength(&bytes) != nil,
              bytes.removeFirst() == 0x02, let nLength = readDERLength(&bytes),
              bytes.count >= nLength else { return nil }
        let modulus = Data(bytes.prefix(nLength).drop(while: { $0 == 0 }))
        bytes.removeFirst(nLength)
        guard bytes.removeFirst() == 0x02, let eLength = readDERLength(&bytes),
              bytes.count >= eLength else { return nil }
        let exponent = Data(bytes.prefix(eLength).drop(while: { $0 == 0 }))
        return modulus.isEmpty || exponent.isEmpty ? nil : (modulus, exponent)
    }

    private static func readDERLength(_ bytes: inout [UInt8]) -> Int? {
        guard !bytes.isEmpty else { return nil }
        let first = Int(bytes.removeFirst())
        if first < 0x80 { return first }
        let count = first & 0x7f
        guard count > 0 && count <= 4 && bytes.count >= count else { return nil }
        var length = 0
        for _ in 0..<count { length = (length << 8) | Int(bytes.removeFirst()) }
        return length
    }

    private static func rsaPublicDER(modulus: Data, exponent: Data) -> Data? {
        func integer(_ value: Data) -> Data {
            var bytes = [UInt8](value)
            while bytes.count > 1 && bytes[0] == 0 { bytes.removeFirst() }
            if bytes[0] & 0x80 != 0 { bytes.insert(0, at: 0) }
            return Data([0x02]) + derLength(bytes.count) + Data(bytes)
        }
        let body = integer(modulus) + integer(exponent)
        return Data([0x30]) + derLength(body.count) + body
    }

    private static func derLength(_ length: Int) -> Data {
        if length < 0x80 { return Data([UInt8(length)]) }
        var value = length
        var bytes: [UInt8] = []
        while value > 0 {
            bytes.insert(UInt8(value & 0xff), at: 0)
            value >>= 8
        }
        return Data([0x80 | UInt8(bytes.count)] + bytes)
    }

    private static func aesCTR(key: Data, iv: Data, data: Data) throws -> Data {
        var cryptor: CCCryptorRef?
        let create = CCCryptorCreateWithMode(
            CCOperation(kCCEncrypt),
            CCMode(kCCModeCTR),
            CCAlgorithm(kCCAlgorithmAES),
            CCPadding(ccNoPadding),
            (iv as NSData).bytes,
            (key as NSData).bytes,
            key.count,
            nil,
            0,
            0,
            CCModeOptions(kCCModeOptionCTR_BE),
            &cryptor
        )
        guard create == kCCSuccess, let cryptor = cryptor else { throw WindowsSealedMessageError.crypto }
        defer { CCCryptorRelease(cryptor) }
        var output = Data(count: data.count)
        let outputCapacity = output.count
        var moved = 0
        let status = output.withUnsafeMutableBytes { out in
            data.withUnsafeBytes { input in
                CCCryptorUpdate(cryptor, input.baseAddress, data.count, out.baseAddress, outputCapacity, &moved)
            }
        }
        guard status == kCCSuccess else { throw WindowsSealedMessageError.crypto }
        output.count = moved
        return output
    }

    private static func hmac(key: Data, data: Data) -> Data {
        var output = Data(count: Int(CC_SHA256_DIGEST_LENGTH))
        output.withUnsafeMutableBytes { out in
            key.withUnsafeBytes { keyBytes in
                data.withUnsafeBytes { dataBytes in
                    CCHmac(
                        CCHmacAlgorithm(kCCHmacAlgSHA256),
                        keyBytes.baseAddress,
                        key.count,
                        dataBytes.baseAddress,
                        data.count,
                        out.baseAddress
                    )
                }
            }
        }
        return output
    }
}
