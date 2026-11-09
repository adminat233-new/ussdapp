import Foundation

public protocol RelayIdentity {
    var number: String { get }
    var publicKey: String { get }
    func signOwnsClaim() throws -> String
}
