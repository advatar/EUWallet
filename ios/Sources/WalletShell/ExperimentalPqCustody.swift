import CryptoKit
import Foundation
import LocalAuthentication
import Security

/// This is experimental software custody: Apple Secure Enclave does not execute ML-DSA or
/// ML-KEM. The P-256 component remains enclave-native; PQ seeds are generated and AES-GCM wrapped
/// inside Rust before crossing FFI.
public struct ExperimentalPqWrappedMaterial: Equatable {
    public let nonce: Data
    public let encryptedPrivateKey: Data
    public let mlDsa65PublicKey: Data
    public let mlKem768PublicKey: Data

    public init(
        nonce: Data,
        encryptedPrivateKey: Data,
        mlDsa65PublicKey: Data,
        mlKem768PublicKey: Data
    ) {
        self.nonce = nonce
        self.encryptedPrivateKey = encryptedPrivateKey
        self.mlDsa65PublicKey = mlDsa65PublicKey
        self.mlKem768PublicKey = mlKem768PublicKey
    }
}

public struct ExperimentalHybridRecoveryEnvelope: Equatable {
    public let senderIdentity: String
    public let recipientIdentity: String
    public let keyGeneration: UInt64
    public let classicalEphemeralPublicKey: Data
    public let mlKem768Ciphertext: Data
    public let transcriptHash: Data
    public let nonce: Data
    public let ciphertext: Data
}

/// Implemented by the generated UniFFI adapter. The supplied key must be cleared by both sides.
public protocol ExperimentalPqGenerating: AnyObject {
    func generateWrappedMaterial(wrappingKey: inout Data) throws
        -> ExperimentalPqWrappedMaterial
    func signWrappedMaterial(
        wrappingKey: inout Data,
        nonce: Data,
        encryptedPrivateKey: Data,
        payload: Data
    ) throws -> Data
    func openWrappedRecovery(
        wrappingKey: inout Data,
        custodyNonce: Data,
        encryptedPrivateKey: Data,
        recipientClassicalPublicKey: Data,
        recipientMlKem768PublicKey: Data,
        classicalSharedSecret: inout Data,
        context: Data,
        envelope: ExperimentalHybridRecoveryEnvelope
    ) throws -> Data
    func sealRecovery(
        senderIdentity: String,
        recipientIdentity: String,
        keyGeneration: UInt64,
        recipientClassicalPublicKey: Data,
        recipientMlKem768PublicKey: Data,
        context: Data,
        plaintext: Data
    ) throws -> ExperimentalHybridRecoveryEnvelope
}

public protocol HybridClassicalKeyProviding: Signer, AnyObject {
    func publicKeyRaw(keyRef: String) throws -> Data
    func keyAgreement(keyRef: String, peerPublicKey: Data) throws -> Data
}

extension SecureEnclaveSigner: HybridClassicalKeyProviding {}

public struct ExperimentalHybridRecoveryRecipient: Equatable {
    public let logicalKeyID: String
    public let keyGeneration: UInt64
    public let classicalPublicKey: Data
    public let mlKem768PublicKey: Data

    public init(
        logicalKeyID: String,
        keyGeneration: UInt64,
        classicalPublicKey: Data,
        mlKem768PublicKey: Data
    ) {
        self.logicalKeyID = logicalKeyID
        self.keyGeneration = keyGeneration
        self.classicalPublicKey = classicalPublicKey
        self.mlKem768PublicKey = mlKem768PublicKey
    }
}

public enum ExperimentalPqProfile: String, Codable, Equatable {
    case hybridP256MlDsa65MlKem768V1 = "euwallet-hybrid-pq-v1"
}

/// Secret-free logical reference binding both components to one monotonically anchored generation.
public struct HybridKeyGeneration: Codable, Equatable, CustomDebugStringConvertible {
    public let logicalKeyID: String
    public let generation: UInt64
    public let profile: ExperimentalPqProfile
    public let classicalKeyReference: String
    public let wrappedPqReference: String
    public let classicalPublicKeyHash: Data
    public let mlDsa65PublicKeyHash: Data
    public let mlKem768PublicKeyHash: Data

    public var debugDescription: String {
        "HybridKeyGeneration(id: \(logicalKeyID), generation: \(generation), profile: \(profile.rawValue))"
    }
}

public struct ExperimentalPqCustodyRecord: Codable, Equatable, CustomDebugStringConvertible {
    public let reference: HybridKeyGeneration
    public let nonce: Data
    public let encryptedPrivateKey: Data
    public let mlDsa65PublicKey: Data
    public let mlKem768PublicKey: Data

    public var debugDescription: String {
        "ExperimentalPqCustodyRecord(reference: \(reference.debugDescription), ciphertext: [REDACTED])"
    }
}

public struct ExperimentalHybridSignature: Equatable {
    public let classicalSignature: Data
    public let postQuantumSignature: Data
}

public protocol ExperimentalHybridSigning: AnyObject {
    func sign(
        logicalKeyID: String,
        profile: ExperimentalHybridSignatureProfile,
        purpose: ExperimentalHybridSignPurpose,
        payload: Data,
        prompt: String
    ) throws -> ExperimentalHybridSignature
}

public struct ExperimentalPqGenerationAnchor: Codable, Equatable {
    public let logicalKeyID: String
    public let generation: UInt64
    public let recordHash: Data
}

public protocol ExperimentalPqWrappingKeyStoring: AnyObject {
    func create(reference: String, prompt: String) throws -> Data
    func load(reference: String, prompt: String) throws -> Data
    func delete(reference: String) throws
}

public protocol ExperimentalPqRecordStoring: AnyObject {
    func load(logicalKeyID: String) throws -> ExperimentalPqCustodyRecord?
    func commit(_ record: ExperimentalPqCustodyRecord) throws
    func delete(logicalKeyID: String) throws
}

public protocol ExperimentalPqGenerationAnchoring: AnyObject {
    func load(logicalKeyID: String) throws -> ExperimentalPqGenerationAnchor?
    func replace(
        expected: ExperimentalPqGenerationAnchor?,
        with next: ExperimentalPqGenerationAnchor
    ) throws
}

public enum ExperimentalPqCustodyError: Error, Equatable {
    case invalidIdentifier
    case generationOverflow
    case missingGeneration
    case missingWrappingKey
    case mixedGeneration
    case rollbackDetected
    case malformedMaterial
    case persistenceFailure
    case keychainFailure(OSStatus)
    case biometricPolicyUnavailable
}

extension ExperimentalPqCustodyError: LocalizedError {
    public var errorDescription: String? {
        switch self {
        case .invalidIdentifier: return "Invalid hybrid-key identifier"
        case .generationOverflow: return "Hybrid-key generation exhausted"
        case .missingGeneration: return "Hybrid key is unavailable"
        case .missingWrappingKey: return "Post-quantum wrapping key is unavailable"
        case .mixedGeneration: return "Hybrid key components belong to different generations"
        case .rollbackDetected: return "Hybrid key rollback was detected"
        case .malformedMaterial: return "Post-quantum key material is malformed"
        case .persistenceFailure: return "Post-quantum custody persistence failed"
        case .keychainFailure(let status): return "Post-quantum Keychain operation failed (\(status))"
        case .biometricPolicyUnavailable: return "Biometric-gated custody is unavailable"
        }
    }
}

/// Coordinates one logical rotation across Secure Enclave P-256 and Rust-generated PQ components.
public final class ExperimentalHybridKeyCustody: ExperimentalHybridSigning {
    private let signer: any HybridClassicalKeyProviding
    private let backend: any ExperimentalPqGenerating
    private let wrappingKeys: any ExperimentalPqWrappingKeyStoring
    private let records: any ExperimentalPqRecordStoring
    private let anchors: any ExperimentalPqGenerationAnchoring

    public init(
        signer: any HybridClassicalKeyProviding,
        backend: any ExperimentalPqGenerating,
        wrappingKeys: any ExperimentalPqWrappingKeyStoring,
        records: any ExperimentalPqRecordStoring,
        anchors: any ExperimentalPqGenerationAnchoring
    ) {
        self.signer = signer
        self.backend = backend
        self.wrappingKeys = wrappingKeys
        self.records = records
        self.anchors = anchors
    }

    /// Rotate both components. The old generation remains authoritative until record and anchor
    /// commits succeed; a partial candidate is never returned as a usable logical reference.
    public func rotate(logicalKeyID: String, prompt: String) throws -> HybridKeyGeneration {
        guard Self.validIdentifier(logicalKeyID) else {
            throw ExperimentalPqCustodyError.invalidIdentifier
        }
        let priorRecord = try records.load(logicalKeyID: logicalKeyID)
        let priorAnchor = try anchors.load(logicalKeyID: logicalKeyID)
        try Self.validate(record: priorRecord, anchor: priorAnchor)
        let successor = (priorAnchor?.generation ?? 0).addingReportingOverflow(1)
        guard !successor.overflow else { throw ExperimentalPqCustodyError.generationOverflow }

        let generation = successor.partialValue
        let classicalReference = "\(logicalKeyID).hybrid.\(generation).p256"
        let wrappedReference = "\(logicalKeyID).hybrid.\(generation).pq-wrap"
        let classicalPublic = try signer.publicKeyRaw(keyRef: classicalReference)
        var wrappingKey = try wrappingKeys.create(reference: wrappedReference, prompt: prompt)
        defer { wrappingKey.clearSensitiveBytes() }

        do {
            let material = try backend.generateWrappedMaterial(wrappingKey: &wrappingKey)
            try Self.validate(material: material)
            let reference = HybridKeyGeneration(
                logicalKeyID: logicalKeyID,
                generation: generation,
                profile: .hybridP256MlDsa65MlKem768V1,
                classicalKeyReference: classicalReference,
                wrappedPqReference: wrappedReference,
                classicalPublicKeyHash: Self.sha256(classicalPublic),
                mlDsa65PublicKeyHash: Self.sha256(material.mlDsa65PublicKey),
                mlKem768PublicKeyHash: Self.sha256(material.mlKem768PublicKey))
            let record = ExperimentalPqCustodyRecord(
                reference: reference,
                nonce: material.nonce,
                encryptedPrivateKey: material.encryptedPrivateKey,
                mlDsa65PublicKey: material.mlDsa65PublicKey,
                mlKem768PublicKey: material.mlKem768PublicKey)
            let anchor = ExperimentalPqGenerationAnchor(
                logicalKeyID: logicalKeyID,
                generation: generation,
                recordHash: try Self.recordHash(record))
            try records.commit(record)
            do {
                try anchors.replace(expected: priorAnchor, with: anchor)
            } catch {
                // The unanchored candidate is unusable and must not replace the prior generation.
                if let priorRecord { try? records.commit(priorRecord) }
                else { try? records.delete(logicalKeyID: logicalKeyID) }
                throw error
            }
            if let old = priorRecord?.reference.wrappedPqReference,
               old != wrappedReference {
                try? wrappingKeys.delete(reference: old)
            }
            return reference
        } catch {
            try? wrappingKeys.delete(reference: wrappedReference)
            throw error
        }
    }

    /// Authenticate a generation and scope the unlocked wrapping key to exactly one operation.
    /// The key is zeroized immediately after `operation` returns or throws.
    public func withUnlockedGeneration<T>(
        reference: HybridKeyGeneration,
        prompt: String,
        operation: (ExperimentalPqCustodyRecord, inout Data) throws -> T
    ) throws -> T {
        guard let record = try records.load(logicalKeyID: reference.logicalKeyID),
              let anchor = try anchors.load(logicalKeyID: reference.logicalKeyID)
        else { throw ExperimentalPqCustodyError.missingGeneration }
        try Self.validate(record: record, anchor: anchor)
        guard record.reference == reference else {
            throw ExperimentalPqCustodyError.mixedGeneration
        }
        let classicalPublic = try signer.publicKeyRaw(
            keyRef: reference.classicalKeyReference)
        guard Self.sha256(classicalPublic) == reference.classicalPublicKeyHash else {
            throw ExperimentalPqCustodyError.mixedGeneration
        }
        var wrappingKey: Data
        do {
            wrappingKey = try wrappingKeys.load(
                reference: reference.wrappedPqReference,
                prompt: prompt)
        } catch ExperimentalPqCustodyError.missingWrappingKey {
            throw ExperimentalPqCustodyError.missingWrappingKey
        }
        guard wrappingKey.count == 32 else {
            wrappingKey.clearSensitiveBytes()
            throw ExperimentalPqCustodyError.malformedMaterial
        }
        defer { wrappingKey.clearSensitiveBytes() }
        return try operation(record, &wrappingKey)
    }

    /// Produce both components after one custody unlock. A component error throws before the
    /// caller receives any result, so no partial signature can cross the effect boundary.
    public func sign(
        reference: HybridKeyGeneration,
        payload: Data,
        prompt: String
    ) throws -> ExperimentalHybridSignature {
        try withUnlockedGeneration(reference: reference, prompt: prompt) { record, wrappingKey in
            let classical = try signer.sign(
                keyRef: reference.classicalKeyReference,
                payload: payload)
            let postQuantum = try backend.signWrappedMaterial(
                wrappingKey: &wrappingKey,
                nonce: record.nonce,
                encryptedPrivateKey: record.encryptedPrivateKey,
                payload: payload)
            guard classical.count == 64, postQuantum.count == 3_309 else {
                throw ExperimentalPqCustodyError.malformedMaterial
            }
            return ExperimentalHybridSignature(
                classicalSignature: classical,
                postQuantumSignature: postQuantum)
        }
    }

    public func sign(
        logicalKeyID: String,
        profile: ExperimentalHybridSignatureProfile,
        purpose: ExperimentalHybridSignPurpose,
        payload: Data,
        prompt: String
    ) throws -> ExperimentalHybridSignature {
        guard profile == .es256MlDsa65V1,
              let reference = try records.load(logicalKeyID: logicalKeyID)?.reference
        else { throw ExperimentalPqCustodyError.missingGeneration }
        // Purpose is already committed into the core-constructed payload; retaining the closed
        // discriminator here prevents a generic signing entry point from entering this path.
        _ = purpose
        return try sign(reference: reference, payload: payload, prompt: prompt)
    }

    /// Open one recovery artifact only after a single biometric custody unlock, Secure Enclave
    /// P-256 ECDH, wrapped ML-KEM decapsulation, transcript authentication and AEAD verification.
    public func openRecovery(
        logicalKeyID: String,
        context: Data,
        envelope: ExperimentalHybridRecoveryEnvelope,
        prompt: String
    ) throws -> Data {
        guard let reference = try records.load(logicalKeyID: logicalKeyID)?.reference,
              envelope.recipientIdentity == reference.logicalKeyID,
              envelope.keyGeneration == reference.generation
        else { throw ExperimentalPqCustodyError.mixedGeneration }
        return try withUnlockedGeneration(reference: reference, prompt: prompt) {
            record, wrappingKey in
            var classicalSecret = try signer.keyAgreement(
                keyRef: reference.classicalKeyReference,
                peerPublicKey: envelope.classicalEphemeralPublicKey)
            defer { classicalSecret.clearSensitiveBytes() }
            let classicalPublic = try signer.publicKeyRaw(
                keyRef: reference.classicalKeyReference)
            return try backend.openWrappedRecovery(
                wrappingKey: &wrappingKey,
                custodyNonce: record.nonce,
                encryptedPrivateKey: record.encryptedPrivateKey,
                recipientClassicalPublicKey: classicalPublic,
                recipientMlKem768PublicKey: record.mlKem768PublicKey,
                classicalSharedSecret: &classicalSecret,
                context: context,
                envelope: envelope)
        }
    }

    static func validate(
        record: ExperimentalPqCustodyRecord?,
        anchor: ExperimentalPqGenerationAnchor?
    ) throws {
        guard (record == nil) == (anchor == nil) else {
            throw ExperimentalPqCustodyError.rollbackDetected
        }
        guard let record, let anchor else { return }
        guard record.reference.logicalKeyID == anchor.logicalKeyID,
              record.reference.generation == anchor.generation,
              try recordHash(record) == anchor.recordHash
        else { throw ExperimentalPqCustodyError.rollbackDetected }
        guard record.reference.mlDsa65PublicKeyHash == sha256(record.mlDsa65PublicKey),
              record.reference.mlKem768PublicKeyHash == sha256(record.mlKem768PublicKey)
        else { throw ExperimentalPqCustodyError.mixedGeneration }
    }

    private static func validate(material: ExperimentalPqWrappedMaterial) throws {
        guard material.nonce.count == 12,
              material.encryptedPrivateKey.count == 20 + 32 + 64 + 16,
              material.mlDsa65PublicKey.count == 1_952,
              material.mlKem768PublicKey.count == 1_184
        else { throw ExperimentalPqCustodyError.malformedMaterial }
    }

    private static func recordHash(_ record: ExperimentalPqCustodyRecord) throws -> Data {
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.sortedKeys, .withoutEscapingSlashes]
        return sha256(try encoder.encode(record))
    }

    private static func sha256(_ data: Data) -> Data { Data(SHA256.hash(data: data)) }

    private static func validIdentifier(_ value: String) -> Bool {
        !value.isEmpty && value.count <= 128 && value.unicodeScalars.allSatisfy {
            CharacterSet.alphanumerics.union(CharacterSet(charactersIn: "._-")).contains($0)
        }
    }
}

/// End-to-end bridge between the real durable Core checkpoint and the experimental hybrid
/// recovery cryptography. Checkpoint generation and the caller's bounded session context are
/// committed into the authenticated KEM transcript and AEAD associated data.
public final class ExperimentalHybridCheckpointRecovery {
    private static let contextDomain = Data("EUWALLET-HYBRID-CHECKPOINT-RECOVERY-V1".utf8)
    private static let maximumSessionContextBytes = 4_096

    private let engine: any DurableWalletEngineDriving
    private let backend: any ExperimentalPqGenerating
    private let custody: ExperimentalHybridKeyCustody

    public init(
        engine: any DurableWalletEngineDriving,
        backend: any ExperimentalPqGenerating,
        custody: ExperimentalHybridKeyCustody
    ) {
        self.engine = engine
        self.backend = backend
        self.custody = custody
    }

    public func sealCheckpoint(
        checkpointGeneration: UInt64,
        senderIdentity: String,
        recipient: ExperimentalHybridRecoveryRecipient,
        sessionContext: Data
    ) throws -> ExperimentalHybridRecoveryEnvelope {
        let context = try Self.context(
            checkpointGeneration: checkpointGeneration,
            sessionContext: sessionContext)
        let checkpoint = try engine.makeDurableCheckpoint(generation: checkpointGeneration)
        guard checkpoint.generation == checkpointGeneration, !checkpoint.bytes.isEmpty else {
            throw ExperimentalPqCustodyError.malformedMaterial
        }
        return try backend.sealRecovery(
            senderIdentity: senderIdentity,
            recipientIdentity: recipient.logicalKeyID,
            keyGeneration: recipient.keyGeneration,
            recipientClassicalPublicKey: recipient.classicalPublicKey,
            recipientMlKem768PublicKey: recipient.mlKem768PublicKey,
            context: context,
            plaintext: checkpoint.bytes)
    }

    public func restoreCheckpoint(
        checkpointGeneration: UInt64,
        logicalKeyID: String,
        sessionContext: Data,
        envelope: ExperimentalHybridRecoveryEnvelope,
        prompt: String
    ) throws {
        let context = try Self.context(
            checkpointGeneration: checkpointGeneration,
            sessionContext: sessionContext)
        let checkpoint = try custody.openRecovery(
            logicalKeyID: logicalKeyID,
            context: context,
            envelope: envelope,
            prompt: prompt)
        guard !checkpoint.isEmpty,
              checkpoint.count <= DurableLifecycleCoordinator.maximumCheckpointBytes
        else { throw ExperimentalPqCustodyError.malformedMaterial }
        try engine.restoreDurableCheckpointRecord(
            CoreDurableCheckpoint(generation: checkpointGeneration, bytes: checkpoint))
    }

    private static func context(
        checkpointGeneration: UInt64,
        sessionContext: Data
    ) throws -> Data {
        guard checkpointGeneration > 0,
              !sessionContext.isEmpty,
              sessionContext.count <= maximumSessionContextBytes
        else { throw ExperimentalPqCustodyError.malformedMaterial }
        var output = contextDomain
        var generation = checkpointGeneration.bigEndian
        Swift.withUnsafeBytes(of: &generation) { output.append(contentsOf: $0) }
        var length = UInt32(sessionContext.count).bigEndian
        Swift.withUnsafeBytes(of: &length) { output.append(contentsOf: $0) }
        output.append(sessionContext)
        return output
    }
}

extension Data {
    mutating func clearSensitiveBytes() {
        withUnsafeMutableBytes { raw in
            guard let base = raw.baseAddress else { return }
            memset_s(base, raw.count, 0, raw.count)
        }
        removeAll(keepingCapacity: false)
    }
}

/// Biometric-gated, non-migrating AES-256 wrapping keys. No API exports all keys or their values.
public final class AppleExperimentalPqWrappingKeyStore: ExperimentalPqWrappingKeyStoring {
    private let service: String

    public init(service: String) { self.service = service }

    public func create(reference: String, prompt _: String) throws -> Data {
        var key = Data(count: 32)
        let status = key.withUnsafeMutableBytes { raw in
            SecRandomCopyBytes(kSecRandomDefault, raw.count, raw.baseAddress!)
        }
        guard status == errSecSuccess else {
            key.clearSensitiveBytes()
            throw ExperimentalPqCustodyError.keychainFailure(status)
        }
        var error: Unmanaged<CFError>?
        guard let access = SecAccessControlCreateWithFlags(
            nil,
            kSecAttrAccessibleWhenUnlockedThisDeviceOnly,
            [.biometryCurrentSet],
            &error)
        else {
            key.clearSensitiveBytes()
            throw ExperimentalPqCustodyError.biometricPolicyUnavailable
        }
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: reference,
            kSecAttrAccessControl as String: access,
            kSecAttrSynchronizable as String: false,
            kSecUseDataProtectionKeychain as String: true,
            kSecValueData as String: key,
        ]
        let add = SecItemAdd(query as CFDictionary, nil)
        guard add == errSecSuccess else {
            key.clearSensitiveBytes()
            throw ExperimentalPqCustodyError.keychainFailure(add)
        }
        return key
    }

    public func load(reference: String, prompt: String) throws -> Data {
        let context = LAContext()
        context.localizedReason = prompt
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: reference,
            kSecAttrSynchronizable as String: false,
            kSecUseDataProtectionKeychain as String: true,
            kSecReturnData as String: true,
            kSecMatchLimit as String: kSecMatchLimitOne,
            kSecUseAuthenticationContext as String: context,
        ]
        var item: CFTypeRef?
        let status = SecItemCopyMatching(query as CFDictionary, &item)
        if status == errSecItemNotFound { throw ExperimentalPqCustodyError.missingWrappingKey }
        guard status == errSecSuccess, let key = item as? Data else {
            throw ExperimentalPqCustodyError.keychainFailure(status)
        }
        return key
    }

    public func delete(reference: String) throws {
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: reference,
            kSecUseDataProtectionKeychain as String: true,
        ]
        let status = SecItemDelete(query as CFDictionary)
        guard status == errSecSuccess || status == errSecItemNotFound else {
            throw ExperimentalPqCustodyError.keychainFailure(status)
        }
    }
}

/// Ciphertext-only application storage. Files use complete protection, atomic replacement and are
/// explicitly excluded from device backups. No plaintext PQ key is accepted by this API.
public final class AppleExperimentalPqRecordStore: ExperimentalPqRecordStoring {
    private let root: URL
    private let fileManager: FileManager

    public init(
        applicationSupportRoot: URL? = nil,
        fileManager: FileManager = .default
    ) throws {
        self.fileManager = fileManager
        let base = try applicationSupportRoot ?? fileManager.url(
            for: .applicationSupportDirectory,
            in: .userDomainMask,
            appropriateFor: nil,
            create: true)
        root = base.appendingPathComponent("ExperimentalPqCustody", isDirectory: true)
        #if os(iOS)
            let attributes: [FileAttributeKey: Any] = [
                .protectionKey: FileProtectionType.complete
            ]
        #else
            let attributes: [FileAttributeKey: Any] = [:]
        #endif
        try fileManager.createDirectory(
            at: root,
            withIntermediateDirectories: true,
            attributes: attributes)
        #if os(iOS)
        var values = URLResourceValues()
        values.isExcludedFromBackup = true
        var mutableRoot = root
        try mutableRoot.setResourceValues(values)
        #endif
    }

    public func load(logicalKeyID: String) throws -> ExperimentalPqCustodyRecord? {
        let url = recordURL(logicalKeyID)
        guard fileManager.fileExists(atPath: url.path) else { return nil }
        do {
            let bytes = try Data(contentsOf: url, options: [.mappedIfSafe])
            return try JSONDecoder().decode(ExperimentalPqCustodyRecord.self, from: bytes)
        } catch {
            throw ExperimentalPqCustodyError.persistenceFailure
        }
    }

    public func commit(_ record: ExperimentalPqCustodyRecord) throws {
        do {
            let encoder = JSONEncoder()
            encoder.outputFormatting = [.sortedKeys, .withoutEscapingSlashes]
            let bytes = try encoder.encode(record)
            let url = recordURL(record.reference.logicalKeyID)
            #if os(iOS)
                let options: Data.WritingOptions = [.atomic, .completeFileProtection]
            #else
                let options: Data.WritingOptions = [.atomic]
            #endif
            try bytes.write(to: url, options: options)
            #if os(iOS)
            var values = URLResourceValues()
            values.isExcludedFromBackup = true
            var mutableURL = url
            try mutableURL.setResourceValues(values)
            #endif
        } catch {
            throw ExperimentalPqCustodyError.persistenceFailure
        }
    }

    public func delete(logicalKeyID: String) throws {
        let url = recordURL(logicalKeyID)
        guard fileManager.fileExists(atPath: url.path) else { return }
        do { try fileManager.removeItem(at: url) }
        catch { throw ExperimentalPqCustodyError.persistenceFailure }
    }

    private func recordURL(_ logicalKeyID: String) -> URL {
        let name = SHA256.hash(data: Data(logicalKeyID.utf8))
            .map { String(format: "%02x", $0) }.joined()
        return root.appendingPathComponent("\(name).pq-custody", isDirectory: false)
    }
}

/// Secret-free rollback anchor in non-migrating Keychain storage. A process lock makes the
/// expected-generation replacement a local compare-and-swap rather than a blind overwrite.
public final class AppleExperimentalPqGenerationAnchorStore: ExperimentalPqGenerationAnchoring {
    private let service: String
    private let lock = NSLock()

    public init(service: String) { self.service = service }

    public func load(logicalKeyID: String) throws -> ExperimentalPqGenerationAnchor? {
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: logicalKeyID,
            kSecAttrSynchronizable as String: false,
            kSecUseDataProtectionKeychain as String: true,
            kSecReturnData as String: true,
            kSecMatchLimit as String: kSecMatchLimitOne,
        ]
        var item: CFTypeRef?
        let status = SecItemCopyMatching(query as CFDictionary, &item)
        if status == errSecItemNotFound { return nil }
        guard status == errSecSuccess, let data = item as? Data,
              let anchor = try? JSONDecoder().decode(
                ExperimentalPqGenerationAnchor.self,
                from: data)
        else { throw ExperimentalPqCustodyError.keychainFailure(status) }
        return anchor
    }

    public func replace(
        expected: ExperimentalPqGenerationAnchor?,
        with next: ExperimentalPqGenerationAnchor
    ) throws {
        lock.lock()
        defer { lock.unlock() }
        guard try load(logicalKeyID: next.logicalKeyID) == expected else {
            throw ExperimentalPqCustodyError.rollbackDetected
        }
        let data: Data
        do { data = try JSONEncoder().encode(next) }
        catch { throw ExperimentalPqCustodyError.persistenceFailure }

        if expected == nil {
            let add: [String: Any] = [
                kSecClass as String: kSecClassGenericPassword,
                kSecAttrService as String: service,
                kSecAttrAccount as String: next.logicalKeyID,
                kSecAttrAccessible as String: kSecAttrAccessibleWhenUnlockedThisDeviceOnly,
                kSecAttrSynchronizable as String: false,
                kSecUseDataProtectionKeychain as String: true,
                kSecValueData as String: data,
            ]
            let status = SecItemAdd(add as CFDictionary, nil)
            guard status == errSecSuccess else {
                throw ExperimentalPqCustodyError.keychainFailure(status)
            }
        } else {
            let query: [String: Any] = [
                kSecClass as String: kSecClassGenericPassword,
                kSecAttrService as String: service,
                kSecAttrAccount as String: next.logicalKeyID,
                kSecUseDataProtectionKeychain as String: true,
            ]
            let status = SecItemUpdate(
                query as CFDictionary,
                [kSecValueData as String: data] as CFDictionary)
            guard status == errSecSuccess else {
                throw ExperimentalPqCustodyError.keychainFailure(status)
            }
        }
    }
}
