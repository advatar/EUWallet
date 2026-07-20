import Foundation
import Security

/// Implements the Rust core's `Signer` foreign trait. The private key is created inside
/// the Secure Enclave and is non-exportable; signing requires biometric/device auth via
/// the key's access control (plan Section 8).
public protocol Signer {
    func sign(keyRef: String, payload: Data) throws -> Data
}

public enum SignerError: Error, Equatable {
    case keyUnavailable
    case keyLookupFailed(OSStatus)
    case accessControlCreationFailed(String)
    case keyCreationFailed(String)
    case hardwarePolicyViolation(String)
    case signFailed(String)
}

extension SignerError: LocalizedError {
    public var errorDescription: String? {
        switch self {
        case .keyUnavailable: return "Signing key is unavailable"
        case .keyLookupFailed(let status): return "Signing-key lookup failed (OSStatus \(status))"
        case .accessControlCreationFailed(let reason):
            return "Could not create the approved signing-key access control: \(reason)"
        case .keyCreationFailed(let reason): return "Signing-key creation failed: \(reason)"
        case .hardwarePolicyViolation(let reason):
            return "Signing key does not satisfy the hardware policy: \(reason)"
        case .signFailed(let reason): return "Signing failed: \(reason)"
        }
    }
}

/// Real device signer. On a device the key lives in the Secure Enclave (non-exportable,
/// biometric-gated); on the Simulator (which has no enclave) it falls back to a keychain-resident
/// P-256 key so development builds still exercise genuine ECDSA. Signatures are emitted as JOSE
/// ES256 raw `r‖s` (64 bytes) — the form the Rust core verifies — not DER.
public final class SecureEnclaveSigner: Signer {
    public init() {}

    public func sign(keyRef: String, payload: Data) throws -> Data {
        let key = try loadOrCreateKey(tag: keyRef)
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
        let key = try loadOrCreateKey(tag: keyRef)
        guard let pub = SecKeyCopyPublicKey(key) else { throw SignerError.keyUnavailable }
        var error: Unmanaged<CFError>?
        guard let data = SecKeyCopyExternalRepresentation(pub, &error) as Data? else {
            throw SignerError.signFailed(String(describing: error?.takeRetainedValue()))
        }
        return data
    }

    private func loadOrCreateKey(tag: String) throws -> SecKey {
        let tagData = Data(tag.utf8)

        #if targetEnvironment(simulator)
        // Simulator software keys are an explicit development-only policy. This branch is absent
        // from physical-device builds, so it can never become a runtime fallback there.
        if let key = try lookupKey(query: Self.simulatorLookupQuery(tag: tagData)) {
            return key
        }
        return try createSimulatorKey(tag: tagData)
        #else
        let accessControl = try Self.approvedHardwareAccessControl()
        // Matching on both the Secure Enclave token and the exact access-control object prevents an
        // older or software-backed key with the same tag from being accepted.
        if let key = try lookupKey(
            query: Self.hardwareLookupQuery(tag: tagData, accessControl: accessControl)
        ) {
            try Self.verifyHardwarePolicy(key, accessControlMatched: true)
            return key
        }
        let key = try createHardwareKey(tag: tagData, accessControl: accessControl)
        try Self.verifyHardwarePolicy(key, accessControlMatched: true)
        return key
        #endif
    }

    private func lookupKey(query: [String: Any]) throws -> SecKey? {
        var item: CFTypeRef?
        let status = SecItemCopyMatching(query as CFDictionary, &item)
        if status == errSecItemNotFound { return nil }
        guard status == errSecSuccess else { throw SignerError.keyLookupFailed(status) }
        guard let item, CFGetTypeID(item) == SecKeyGetTypeID() else {
            throw SignerError.keyUnavailable
        }
        return (item as! SecKey)
    }

    private static func baseLookupQuery(tag: Data) -> [String: Any] {
        [
            kSecClass as String: kSecClassKey,
            kSecAttrApplicationTag as String: tag,
            kSecAttrKeyType as String: kSecAttrKeyTypeECSECPrimeRandom,
            kSecAttrKeySizeInBits as String: 256,
            kSecAttrKeyClass as String: kSecAttrKeyClassPrivate,
            kSecReturnRef as String: true,
            kSecMatchLimit as String: kSecMatchLimitOne,
        ]
    }

    private static func simulatorLookupQuery(tag: Data) -> [String: Any] {
        baseLookupQuery(tag: tag)
    }

    private static func hardwareLookupQuery(
        tag: Data, accessControl: SecAccessControl
    ) -> [String: Any] {
        var query = baseLookupQuery(tag: tag)
        query[kSecAttrTokenID as String] = kSecAttrTokenIDSecureEnclave
        query[kSecAttrAccessControl as String] = accessControl
        return query
    }

    private static func approvedHardwareAccessControl() throws -> SecAccessControl {
        var error: Unmanaged<CFError>?
        guard let access = SecAccessControlCreateWithFlags(
            nil,
            kSecAttrAccessibleWhenUnlockedThisDeviceOnly,
            [.privateKeyUsage, .biometryCurrentSet],
            &error
        ) else {
            throw SignerError.accessControlCreationFailed(takeErrorDescription(&error))
        }
        return access
    }

    private func createHardwareKey(tag: Data, accessControl: SecAccessControl) throws -> SecKey {
        let privateAttrs: [String: Any] = [
            kSecAttrIsPermanent as String: true,
            kSecAttrApplicationTag as String: tag,
            kSecAttrAccessControl as String: accessControl,
        ]
        let attrs: [String: Any] = [
            kSecAttrKeyType as String: kSecAttrKeyTypeECSECPrimeRandom,
            kSecAttrKeySizeInBits as String: 256,
            kSecAttrTokenID as String: kSecAttrTokenIDSecureEnclave,
            kSecPrivateKeyAttrs as String: privateAttrs,
        ]
        var error: Unmanaged<CFError>?
        guard let key = SecKeyCreateRandomKey(attrs as CFDictionary, &error) else {
            throw SignerError.keyCreationFailed(Self.takeErrorDescription(&error))
        }
        return key
    }

    private func createSimulatorKey(tag: Data) throws -> SecKey {
        let privateAttrs: [String: Any] = [
            kSecAttrIsPermanent as String: true,
            kSecAttrApplicationTag as String: tag,
            kSecAttrAccessible as String: kSecAttrAccessibleWhenUnlockedThisDeviceOnly,
        ]
        let attrs: [String: Any] = [
            kSecAttrKeyType as String: kSecAttrKeyTypeECSECPrimeRandom,
            kSecAttrKeySizeInBits as String: 256,
            kSecPrivateKeyAttrs as String: privateAttrs,
        ]
        var error: Unmanaged<CFError>?
        guard let key = SecKeyCreateRandomKey(attrs as CFDictionary, &error) else {
            throw SignerError.keyCreationFailed(Self.takeErrorDescription(&error))
        }
        return key
    }

    private static func verifyHardwarePolicy(
        _ key: SecKey, accessControlMatched: Bool
    ) throws {
        guard let raw = SecKeyCopyAttributes(key) as? [String: Any] else {
            throw SignerError.hardwarePolicyViolation("key attributes unavailable")
        }
        if let violation = hardwarePolicyViolation(
            attributes: raw,
            accessControlMatched: accessControlMatched
        ) {
            throw SignerError.hardwarePolicyViolation(violation)
        }
    }

    /// Kept internal for policy-focused unit tests. Access-control equality is established by the
    /// lookup query (or by supplying the same object at creation); intrinsic key attributes then
    /// prove the Secure Enclave, private P-256 and signing-only portions of the policy.
    static func hardwarePolicyViolation(
        attributes: [String: Any], accessControlMatched: Bool
    ) -> String? {
        guard accessControlMatched else { return "approved access control was not matched" }
        guard attributes[kSecAttrTokenID as String] as? String
                == kSecAttrTokenIDSecureEnclave as String else {
            return "key is not backed by the Secure Enclave"
        }
        guard attributes[kSecAttrKeyType as String] as? String
                == kSecAttrKeyTypeECSECPrimeRandom as String else {
            return "key is not an elliptic-curve key"
        }
        guard (attributes[kSecAttrKeySizeInBits as String] as? NSNumber)?.intValue == 256 else {
            return "key is not P-256"
        }
        guard attributes[kSecAttrKeyClass as String] as? String
                == kSecAttrKeyClassPrivate as String else {
            return "key is not private"
        }
        guard (attributes[kSecAttrCanSign as String] as? NSNumber)?.boolValue == true else {
            return "key is not authorized for signing"
        }
        if (attributes[kSecAttrIsExtractable as String] as? NSNumber)?.boolValue == true {
            return "key is extractable"
        }
        return nil
    }

    private static func takeErrorDescription(_ error: inout Unmanaged<CFError>?) -> String {
        guard let error else { return "Security framework returned no detail" }
        return String(describing: error.takeRetainedValue())
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
