#if os(iOS)
import CryptoKit
import Foundation

/// Ephemeral holder key backed by the iPhone Secure Enclave.
///
/// Persistent key storage and user-presence policy are intentionally left to
/// the containing wallet app, which can retain `dataRepresentation` in the
/// Keychain and restore it with CryptoKit.
public struct SecureEnclaveHolderKey: HolderSigningKey {
    private let key: SecureEnclave.P256.Signing.PrivateKey

    public init() throws {
        guard SecureEnclave.isAvailable else {
            throw TLSNotaryMobileError.signingFailure("The Secure Enclave is unavailable.")
        }
        key = try SecureEnclave.P256.Signing.PrivateKey()
    }

    public var publicKeyX963: Data { key.publicKey.x963Representation }
    public var did: String { SoftwareHolderKey.didJwk(publicKey: publicKeyX963) }

    public func sign(_ data: Data) throws -> Data {
        try key.signature(for: data).derRepresentation
    }
}
#endif
