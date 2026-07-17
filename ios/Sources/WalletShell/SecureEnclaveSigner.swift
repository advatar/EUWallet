import Foundation
import Security

/// Implements the Rust core's `Signer` foreign trait. The private key is created inside
/// the Secure Enclave and is non-exportable; signing requires biometric/device auth via
/// the key's access control (plan Section 8).
public protocol Signer {
    func sign(keyRef: String, payload: Data) throws -> Data
}

public enum SignerError: Error { case keyUnavailable, signFailed(String) }

public final class SecureEnclaveSigner: Signer {
    public init() {}

    public func sign(keyRef: String, payload: Data) throws -> Data {
        guard let key = try loadOrCreateKey(tag: keyRef) else { throw SignerError.keyUnavailable }
        var error: Unmanaged<CFError>?
        guard let sig = SecKeyCreateSignature(
            key, .ecdsaSignatureMessageX962SHA256, payload as CFData, &error
        ) else {
            throw SignerError.signFailed(String(describing: error?.takeRetainedValue()))
        }
        return sig as Data
    }

    private func loadOrCreateKey(tag: String) throws -> SecKey? {
        let tagData = Data(tag.utf8)
        // Try to load an existing key first.
        let query: [String: Any] = [
            kSecClass as String: kSecClassKey,
            kSecAttrApplicationTag as String: tagData,
            kSecAttrKeyType as String: kSecAttrKeyTypeECSECPrimeRandom,
            kSecReturnRef as String: true,
        ]
        var item: CFTypeRef?
        if SecItemCopyMatching(query as CFDictionary, &item) == errSecSuccess {
            return (item as! SecKey)
        }
        // Otherwise create one bound to the Secure Enclave with biometric access control.
        // (On macOS without a Secure Enclave this falls back per platform; iOS enforces it.)
        guard let access = SecAccessControlCreateWithFlags(
            nil, kSecAttrAccessibleWhenUnlockedThisDeviceOnly,
            [.privateKeyUsage, .biometryCurrentSet], nil
        ) else { return nil }

        var attrs: [String: Any] = [
            kSecAttrKeyType as String: kSecAttrKeyTypeECSECPrimeRandom,
            kSecAttrKeySizeInBits as String: 256,
            kSecPrivateKeyAttrs as String: [
                kSecAttrIsPermanent as String: true,
                kSecAttrApplicationTag as String: tagData,
                kSecAttrAccessControl as String: access,
            ],
        ]
        #if os(iOS)
        attrs[kSecAttrTokenID as String] = kSecAttrTokenIDSecureEnclave
        #endif
        var createError: Unmanaged<CFError>?
        return SecKeyCreateRandomKey(attrs as CFDictionary, &createError)
    }
}
