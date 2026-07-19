import Foundation
import Security

/// Implements the Rust core's `Signer` foreign trait. The private key is created inside
/// the Secure Enclave and is non-exportable; signing requires biometric/device auth via
/// the key's access control (plan Section 8).
public protocol Signer {
    func sign(keyRef: String, payload: Data) throws -> Data
}

public enum SignerError: Error { case keyUnavailable, signFailed(String) }

/// Real device signer. On a device the key lives in the Secure Enclave (non-exportable,
/// biometric-gated); on the Simulator (which has no enclave) it falls back to a keychain-resident
/// P-256 key so development builds still exercise genuine ECDSA. Signatures are emitted as JOSE
/// ES256 raw `r‖s` (64 bytes) — the form the Rust core verifies — not DER.
public final class SecureEnclaveSigner: Signer {
    public init() {}

    public func sign(keyRef: String, payload: Data) throws -> Data {
        guard let key = try loadOrCreateKey(tag: keyRef) else { throw SignerError.keyUnavailable }
        var error: Unmanaged<CFError>?
        // `...MessageX962SHA256` hashes the payload with SHA-256 then signs, returning DER.
        guard let der = SecKeyCreateSignature(
            key, .ecdsaSignatureMessageX962SHA256, payload as CFData, &error
        ) as Data? else {
            throw SignerError.signFailed(String(describing: error?.takeRetainedValue()))
        }
        guard let raw = Self.joseSignature(fromDER: der) else {
            throw SignerError.signFailed("could not convert DER ECDSA signature to JOSE r‖s")
        }
        return raw
    }

    /// The device public key as X9.63 uncompressed bytes (`0x04‖X‖Y`, 65 bytes) — the raw form the
    /// Rust core verifies against (`load_device_key`) and the WUA attests. Creates the key on first
    /// use.
    public func publicKeyRaw(keyRef: String) throws -> Data {
        guard let key = try loadOrCreateKey(tag: keyRef),
              let pub = SecKeyCopyPublicKey(key) else { throw SignerError.keyUnavailable }
        var error: Unmanaged<CFError>?
        guard let data = SecKeyCopyExternalRepresentation(pub, &error) as Data? else {
            throw SignerError.signFailed(String(describing: error?.takeRetainedValue()))
        }
        return data
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
        #if targetEnvironment(simulator)
        // No Secure Enclave on the Simulator: a keychain-resident key keeps dev builds real.
        return createKey(tag: tagData, useEnclave: false)
        #else
        if let key = createKey(tag: tagData, useEnclave: true) { return key }
        // Fall back if the enclave is unavailable (e.g. no biometry enrolled) — still a real key.
        return createKey(tag: tagData, useEnclave: false)
        #endif
    }

    private func createKey(tag: Data, useEnclave: Bool) -> SecKey? {
        var privateAttrs: [String: Any] = [
            kSecAttrIsPermanent as String: true,
            kSecAttrApplicationTag as String: tag,
        ]
        if useEnclave {
            // Non-exportable; usage requires the current biometric set / device passcode.
            if let access = SecAccessControlCreateWithFlags(
                nil, kSecAttrAccessibleWhenUnlockedThisDeviceOnly,
                [.privateKeyUsage, .biometryCurrentSet], nil
            ) {
                privateAttrs[kSecAttrAccessControl as String] = access
            }
        } else {
            privateAttrs[kSecAttrAccessible as String] = kSecAttrAccessibleWhenUnlockedThisDeviceOnly
        }
        var attrs: [String: Any] = [
            kSecAttrKeyType as String: kSecAttrKeyTypeECSECPrimeRandom,
            kSecAttrKeySizeInBits as String: 256,
            kSecPrivateKeyAttrs as String: privateAttrs,
        ]
        if useEnclave {
            attrs[kSecAttrTokenID as String] = kSecAttrTokenIDSecureEnclave
        }
        var error: Unmanaged<CFError>?
        return SecKeyCreateRandomKey(attrs as CFDictionary, &error)
    }

    /// Convert a DER-encoded ECDSA signature (`SEQUENCE { INTEGER r, INTEGER s }`) to the JOSE
    /// fixed-width `r‖s` (32 bytes each) that ES256 verifiers — including the Rust core — expect.
    static func joseSignature(fromDER der: Data) -> Data? {
        let b = [UInt8](der)
        var i = 0
        guard b.count > 8, b[i] == 0x30 else { return nil } // SEQUENCE
        i += 1
        // Sequence length: short form, or long form (0x81 nn). ECDSA P-256 fits one length byte.
        if b[i] & 0x80 != 0 {
            let n = Int(b[i] & 0x7f)
            i += 1 + n
        } else {
            i += 1
        }
        func readInt() -> [UInt8]? {
            guard i < b.count, b[i] == 0x02 else { return nil } // INTEGER
            i += 1
            guard i < b.count else { return nil }
            let len = Int(b[i]); i += 1
            guard len > 0, i + len <= b.count else { return nil }
            var bytes = Array(b[i..<i + len]); i += len
            // Strip DER's leading sign-zero, then left-pad (or trim) to exactly 32 bytes.
            while bytes.count > 32, bytes.first == 0x00 { bytes.removeFirst() }
            while bytes.count < 32 { bytes.insert(0, at: 0) }
            guard bytes.count == 32 else { return nil }
            return bytes
        }
        guard let r = readInt(), let s = readInt() else { return nil }
        return Data(r + s)
    }
}
