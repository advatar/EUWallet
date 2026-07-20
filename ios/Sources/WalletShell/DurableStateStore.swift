import CryptoKit
import Foundation

/// Authenticated caller-controlled binding for one durable wallet-state namespace.
///
/// The binding should contain stable, non-secret installation context such as the device-key
/// identifier and wallet profile identifier. It is authenticated as AEAD associated data and is
/// also committed into the Keychain anchor; it is never stored as plaintext in a slot file.
public struct DurableStateContext: Equatable, Sendable {
    public static let currentSchemaVersion: UInt32 = 1
    public static let maximumBindingBytes = 4 * 1024

    public let schemaVersion: UInt32
    public let binding: Data

    public init(
        schemaVersion: UInt32 = DurableStateContext.currentSchemaVersion,
        binding: Data
    ) throws {
        guard schemaVersion == Self.currentSchemaVersion else {
            throw DurableStateStoreError.unsupportedSchemaVersion(schemaVersion)
        }
        guard !binding.isEmpty, binding.count <= Self.maximumBindingBytes else {
            throw DurableStateStoreError.invalidContextLength(binding.count)
        }
        self.schemaVersion = schemaVersion
        self.binding = binding
    }
}

public struct DurableStateRecord: Equatable, Sendable {
    public let generation: UInt64
    public let plaintext: Data

    public init(generation: UInt64, plaintext: Data) {
        self.generation = generation
        self.plaintext = plaintext
    }
}

public enum DurableStateLoadResult: Equatable, Sendable {
    /// No committed durable state exists. Its compare-and-swap generation is zero.
    case empty
    case record(DurableStateRecord)
}

/// Narrow persistence boundary. Serializing or restoring the Rust Core is intentionally outside
/// this API: callers supply one already-bounded canonical plaintext checkpoint.
public protocol DurableStateStore: AnyObject {
    func load(context: DurableStateContext) throws -> DurableStateLoadResult

    @discardableResult
    func commit(
        expectedGeneration: UInt64,
        nextGeneration: UInt64,
        plaintext: Data,
        context: DurableStateContext
    ) throws -> DurableStateRecord
}

public enum DurableStateSlot: UInt8, Equatable, Sendable {
    case a = 0
    case b = 1

    fileprivate var opposite: DurableStateSlot { self == .a ? .b : .a }
}

/// Explicit crash-injection boundaries retained as public values so storage assurance tests can
/// identify the exact failed durability step without parsing strings.
public enum DurableStateFaultPoint: String, CaseIterable, Equatable, Sendable {
    case afterKeyCreation
    case beforeGenesisAnchor
    case afterGenesisAnchor
    case beforeTemporaryCreate
    case afterTemporaryCreate
    case afterTemporaryWrite
    case afterTemporarySync
    case afterRename
    case afterDirectorySync
    case beforeAnchorUpdate
    case afterAnchorUpdate
}

public enum DurableStateStoreError: Error, Equatable, Sendable {
    case invalidApplicationIdentifier
    case invalidContextLength(Int)
    case unsupportedSchemaVersion(UInt32)
    case plaintextTooLarge(actual: Int, maximum: Int)
    case envelopeTooLarge(actual: Int, maximum: Int)
    case invalidGenerationTransition(expected: UInt64, next: UInt64)
    case generationConflict(expected: UInt64, actual: UInt64)
    case missingInstallationKey
    case corruptInstallationKey
    case missingAnchor
    case corruptAnchor
    case unsupportedAnchorVersion(UInt16)
    case unsupportedEnvelopeVersion(UInt16)
    case schemaMismatch(expected: UInt32, actual: UInt32)
    case applicationIdentityMismatch
    case contextMismatch
    case invalidGenesisAnchor
    case missingAnchoredSlot(DurableStateSlot)
    case anchorDigestMismatch
    case slotMismatch(expected: DurableStateSlot, actual: DurableStateSlot)
    case generationMismatch(expected: UInt64, actual: UInt64)
    case corruptEnvelope
    case authenticationFailed
    case encryptionFailed
    case anchorAlreadyExists
    case secureMetadataFailure(operation: String, status: Int32)
    case storageFailure(operation: String, code: Int32)
    case storagePolicyFailure(String)
    case interruptedWrite(DurableStateFaultPoint)
}

extension DurableStateStoreError: LocalizedError {
    public var errorDescription: String? {
        switch self {
        case .invalidApplicationIdentifier:
            return "The application identity is absent or invalid"
        case .invalidContextLength(let count):
            return "The durable-state context length is invalid (\(count) bytes)"
        case .unsupportedSchemaVersion(let version):
            return "Durable-state schema version \(version) is not supported"
        case .plaintextTooLarge(let actual, let maximum):
            return "Durable-state plaintext is \(actual) bytes; maximum is \(maximum)"
        case .envelopeTooLarge(let actual, let maximum):
            return "Durable-state envelope is \(actual) bytes; maximum is \(maximum)"
        case .invalidGenerationTransition(let expected, let next):
            return "Invalid durable-state generation transition \(expected) -> \(next)"
        case .generationConflict(let expected, let actual):
            return "Durable-state CAS expected generation \(expected), found \(actual)"
        case .missingInstallationKey:
            return "Durable state exists but its installation key is missing"
        case .corruptInstallationKey:
            return "The durable-state installation key is malformed"
        case .missingAnchor:
            return "Durable slot state exists but its Keychain anchor is missing"
        case .corruptAnchor:
            return "The durable-state Keychain anchor is malformed"
        case .unsupportedAnchorVersion(let version):
            return "Durable-state anchor version \(version) is not supported"
        case .unsupportedEnvelopeVersion(let version):
            return "Durable-state envelope version \(version) is not supported"
        case .schemaMismatch(let expected, let actual):
            return "Durable-state schema mismatch: expected \(expected), found \(actual)"
        case .applicationIdentityMismatch:
            return "Durable state belongs to a different application identity"
        case .contextMismatch:
            return "Durable state belongs to a different caller context"
        case .invalidGenesisAnchor:
            return "The generation-zero durable-state anchor is invalid"
        case .missingAnchoredSlot(let slot):
            return "The anchored durable-state slot \(slot) is missing"
        case .anchorDigestMismatch:
            return "The anchored durable-state envelope digest does not match"
        case .slotMismatch(let expected, let actual):
            return "Durable-state slot mismatch: expected \(expected), found \(actual)"
        case .generationMismatch(let expected, let actual):
            return "Durable-state generation mismatch: expected \(expected), found \(actual)"
        case .corruptEnvelope:
            return "The durable-state envelope is malformed"
        case .authenticationFailed:
            return "Durable-state authentication failed"
        case .encryptionFailed:
            return "Durable-state encryption failed"
        case .anchorAlreadyExists:
            return "A durable-state anchor already exists"
        case .secureMetadataFailure(let operation, let status):
            return "Secure metadata operation \(operation) failed (OSStatus \(status))"
        case .storageFailure(let operation, let code):
            return "Durable-state filesystem operation \(operation) failed (errno \(code))"
        case .storagePolicyFailure(let reason):
            return "Durable-state file policy failed: \(reason)"
        case .interruptedWrite(let point):
            return "Injected durable-state interruption at \(point.rawValue)"
        }
    }
}

protocol DurableSecureMetadataStore: AnyObject {
    func readInstallationKey() throws -> Data?
    func createInstallationKey() throws -> Data
    func readAnchor() throws -> Data?
    func createAnchor(_ value: Data) throws
    func replaceAnchor(_ value: Data) throws
}

protocol DurableStateFaultInjecting: AnyObject {
    func hit(_ point: DurableStateFaultPoint) throws
}

protocol DurableStateFileSystem: AnyObject {
    func acquireExclusiveLock() throws
    func releaseExclusiveLock()
    func hasAnySlot() throws -> Bool
    func read(slot: DurableStateSlot, maximumBytes: Int) throws -> Data?
    func writeDurably(
        _ data: Data,
        to slot: DurableStateSlot,
        faultInjector: (any DurableStateFaultInjecting)?
    ) throws
}

private struct DurableAnchor: Equatable {
    static let genesisSlot: UInt8 = 0xff

    let schemaVersion: UInt32
    let generation: UInt64
    let slotRaw: UInt8
    let applicationDigest: Data
    let contextDigest: Data
    let envelopeDigest: Data

    var slot: DurableStateSlot? { DurableStateSlot(rawValue: slotRaw) }

    static func genesis(
        schemaVersion: UInt32,
        applicationDigest: Data,
        contextDigest: Data
    ) -> DurableAnchor {
        DurableAnchor(
            schemaVersion: schemaVersion,
            generation: 0,
            slotRaw: genesisSlot,
            applicationDigest: applicationDigest,
            contextDigest: contextDigest,
            envelopeDigest: Data(repeating: 0, count: 32))
    }
}

private enum DurableAnchorCodec {
    static let formatVersion: UInt16 = 1
    static let encodedLength = 8 + 2 + 4 + 8 + 1 + 32 + 32 + 32
    private static let magic = Array("EUWANCHR".utf8)

    static func encode(_ anchor: DurableAnchor) -> Data {
        var data = Data(magic)
        data.appendBigEndian(formatVersion)
        data.appendBigEndian(anchor.schemaVersion)
        data.appendBigEndian(anchor.generation)
        data.append(anchor.slotRaw)
        data.append(anchor.applicationDigest)
        data.append(anchor.contextDigest)
        data.append(anchor.envelopeDigest)
        return data
    }

    static func decode(_ data: Data) throws -> DurableAnchor {
        guard data.count == encodedLength else { throw DurableStateStoreError.corruptAnchor }
        var reader = StrictByteReader(data)
        guard try reader.readBytes(count: magic.count) == magic else {
            throw DurableStateStoreError.corruptAnchor
        }
        let version = try reader.readUInt16()
        guard version == formatVersion else {
            throw DurableStateStoreError.unsupportedAnchorVersion(version)
        }
        let schemaVersion = try reader.readUInt32()
        let generation = try reader.readUInt64()
        let slotRaw = try reader.readUInt8()
        let applicationDigest = Data(try reader.readBytes(count: 32))
        let contextDigest = Data(try reader.readBytes(count: 32))
        let envelopeDigest = Data(try reader.readBytes(count: 32))
        guard reader.isAtEnd else { throw DurableStateStoreError.corruptAnchor }
        guard slotRaw == DurableAnchor.genesisSlot || DurableStateSlot(rawValue: slotRaw) != nil
        else {
            throw DurableStateStoreError.corruptAnchor
        }
        return DurableAnchor(
            schemaVersion: schemaVersion,
            generation: generation,
            slotRaw: slotRaw,
            applicationDigest: applicationDigest,
            contextDigest: contextDigest,
            envelopeDigest: envelopeDigest)
    }
}

private struct DurableEnvelope {
    let schemaVersion: UInt32
    let generation: UInt64
    let slot: DurableStateSlot
    let nonce: Data
    let ciphertext: Data
    let tag: Data
}

private enum DurableEnvelopeCodec {
    static let formatVersion: UInt16 = 1
    static let nonceLength = 12
    static let tagLength = 16
    static let fixedOverhead = 8 + 2 + 4 + 8 + 1 + 1 + 4 + nonceLength + tagLength
    private static let magic = Array("EUWSTATE".utf8)

    static func encode(_ envelope: DurableEnvelope) -> Data {
        var data = Data(magic)
        data.appendBigEndian(formatVersion)
        data.appendBigEndian(envelope.schemaVersion)
        data.appendBigEndian(envelope.generation)
        data.append(envelope.slot.rawValue)
        data.append(UInt8(nonceLength))
        data.appendBigEndian(UInt32(envelope.ciphertext.count))
        data.append(envelope.nonce)
        data.append(envelope.ciphertext)
        data.append(envelope.tag)
        return data
    }

    static func decode(_ data: Data, maximumPlaintextBytes: Int) throws -> DurableEnvelope {
        let maximumEnvelopeBytes = maximumPlaintextBytes + fixedOverhead
        guard data.count <= maximumEnvelopeBytes else {
            throw DurableStateStoreError.envelopeTooLarge(
                actual: data.count, maximum: maximumEnvelopeBytes)
        }
        var reader = StrictByteReader(data)
        guard try reader.readBytes(count: magic.count) == magic else {
            throw DurableStateStoreError.corruptEnvelope
        }
        let version = try reader.readUInt16()
        guard version == formatVersion else {
            throw DurableStateStoreError.unsupportedEnvelopeVersion(version)
        }
        let schemaVersion = try reader.readUInt32()
        let generation = try reader.readUInt64()
        let rawSlot = try reader.readUInt8()
        guard let slot = DurableStateSlot(rawValue: rawSlot) else {
            throw DurableStateStoreError.corruptEnvelope
        }
        guard try reader.readUInt8() == UInt8(nonceLength) else {
            throw DurableStateStoreError.corruptEnvelope
        }
        let ciphertextLength32 = try reader.readUInt32()
        guard ciphertextLength32 <= UInt32(maximumPlaintextBytes) else {
            throw DurableStateStoreError.envelopeTooLarge(
                actual: Int(ciphertextLength32), maximum: maximumPlaintextBytes)
        }
        let ciphertextLength = Int(ciphertextLength32)
        let remainingLength = nonceLength.addingReportingOverflow(ciphertextLength)
        guard !remainingLength.overflow else { throw DurableStateStoreError.corruptEnvelope }
        let expectedRemaining = remainingLength.partialValue.addingReportingOverflow(tagLength)
        guard !expectedRemaining.overflow, reader.remainingCount == expectedRemaining.partialValue
        else {
            throw DurableStateStoreError.corruptEnvelope
        }
        let nonce = Data(try reader.readBytes(count: nonceLength))
        let ciphertext = Data(try reader.readBytes(count: ciphertextLength))
        let tag = Data(try reader.readBytes(count: tagLength))
        guard reader.isAtEnd else { throw DurableStateStoreError.corruptEnvelope }
        return DurableEnvelope(
            schemaVersion: schemaVersion,
            generation: generation,
            slot: slot,
            nonce: nonce,
            ciphertext: ciphertext,
            tag: tag)
    }
}

/// Apple production implementation of the encrypted durable-state primitive.
///
/// A random installation key and a generation/digest anchor live in ThisDeviceOnly Keychain
/// items. Ciphertext lives in two protected, backup-excluded Application Support slots. Commits
/// make the inactive slot durable before atomically replacing the anchor, and reads follow only
/// the anchor-selected generation: there is no fallback to an older valid slot.
///
/// This detects corrupt or stale local files while the Keychain anchor is intact. It does **not**
/// claim certified rollback resistance if an attacker can roll back the full application/device
/// state together with Keychain. A provider monotonic receipt or evaluated platform mechanism is
/// still required for that assurance claim.
public final class AppleDurableStateStore: DurableStateStore {
    static let maximumEnvelopeBytes = 32 * 1024 * 1024
    /// Shared Core/iOS/Android plaintext ceiling. Android's authenticated slot envelope has the
    /// largest fixed overhead (120 bytes), so using its limit here keeps the lifecycle contract
    /// identical on both platforms and leaves 64 bytes of additional headroom in Apple's envelope.
    public static let maximumPlaintextBytes = 33_554_312

    private let applicationIdentifier: String
    private let metadata: any DurableSecureMetadataStore
    private let fileSystem: any DurableStateFileSystem
    private let faultInjector: (any DurableStateFaultInjecting)?

    public convenience init() throws {
        guard let applicationIdentifier = Bundle.main.bundleIdentifier else {
            throw DurableStateStoreError.invalidApplicationIdentifier
        }
        let metadata = AppleKeychainDurableMetadataStore(
            service: "\(applicationIdentifier).euwallet.durable-state.v1")
        let fileSystem = try AppleDurableStateFileSystem.production(
            applicationIdentifier: applicationIdentifier)
        try self.init(
            applicationIdentifier: applicationIdentifier,
            metadata: metadata,
            fileSystem: fileSystem,
            faultInjector: nil)
    }

    init(
        applicationIdentifier: String,
        metadata: any DurableSecureMetadataStore,
        fileSystem: any DurableStateFileSystem,
        faultInjector: (any DurableStateFaultInjecting)? = nil
    ) throws {
        guard Self.isValidApplicationIdentifier(applicationIdentifier) else {
            throw DurableStateStoreError.invalidApplicationIdentifier
        }
        self.applicationIdentifier = applicationIdentifier
        self.metadata = metadata
        self.fileSystem = fileSystem
        self.faultInjector = faultInjector
    }

    public func load(context: DurableStateContext) throws -> DurableStateLoadResult {
        try fileSystem.acquireExclusiveLock()
        defer { fileSystem.releaseExclusiveLock() }
        switch try validatedState(context: context) {
        case .unanchoredEmpty, .anchoredEmpty:
            return .empty
        case .record(_, _, let record):
            return .record(record)
        }
    }

    @discardableResult
    public func commit(
        expectedGeneration: UInt64,
        nextGeneration: UInt64,
        plaintext: Data,
        context: DurableStateContext
    ) throws -> DurableStateRecord {
        guard plaintext.count <= Self.maximumPlaintextBytes else {
            throw DurableStateStoreError.plaintextTooLarge(
                actual: plaintext.count, maximum: Self.maximumPlaintextBytes)
        }
        guard expectedGeneration != UInt64.max, nextGeneration == expectedGeneration + 1 else {
            throw DurableStateStoreError.invalidGenerationTransition(
                expected: expectedGeneration, next: nextGeneration)
        }

        try fileSystem.acquireExclusiveLock()
        defer { fileSystem.releaseExclusiveLock() }

        var state = try validatedState(context: context)
        let actualGeneration = state.generation
        guard expectedGeneration == actualGeneration else {
            throw DurableStateStoreError.generationConflict(
                expected: expectedGeneration, actual: actualGeneration)
        }

        if case .unanchoredEmpty(let existingKey) = state {
            let key: Data
            if let existingKey {
                key = existingKey
            } else {
                key = try validatedKey(metadata.createInstallationKey())
                try faultInjector?.hit(.afterKeyCreation)
            }
            try faultInjector?.hit(.beforeGenesisAnchor)
            let genesis = DurableAnchor.genesis(
                schemaVersion: context.schemaVersion,
                applicationDigest: Self.digest(Data(applicationIdentifier.utf8)),
                contextDigest: Self.digest(context.binding))
            try metadata.createAnchor(DurableAnchorCodec.encode(genesis))
            try faultInjector?.hit(.afterGenesisAnchor)
            state = .anchoredEmpty(key, genesis)
        }

        guard let key = state.key else {
            throw DurableStateStoreError.missingInstallationKey
        }
        let targetSlot = state.activeSlot?.opposite ?? .a
        let aad = try associatedData(
            context: context, generation: nextGeneration, slot: targetSlot)
        let symmetricKey = SymmetricKey(data: key)
        let sealed: AES.GCM.SealedBox
        do {
            sealed = try AES.GCM.seal(plaintext, using: symmetricKey, authenticating: aad)
        } catch {
            throw DurableStateStoreError.encryptionFailed
        }
        let envelope = DurableEnvelope(
            schemaVersion: context.schemaVersion,
            generation: nextGeneration,
            slot: targetSlot,
            nonce: sealed.nonce.withUnsafeBytes { Data($0) },
            ciphertext: sealed.ciphertext,
            tag: sealed.tag)
        let encodedEnvelope = DurableEnvelopeCodec.encode(envelope)
        guard encodedEnvelope.count <= Self.maximumEnvelopeBytes else {
            throw DurableStateStoreError.envelopeTooLarge(
                actual: encodedEnvelope.count, maximum: Self.maximumEnvelopeBytes)
        }

        try fileSystem.writeDurably(
            encodedEnvelope, to: targetSlot, faultInjector: faultInjector)

        let nextAnchor = DurableAnchor(
            schemaVersion: context.schemaVersion,
            generation: nextGeneration,
            slotRaw: targetSlot.rawValue,
            applicationDigest: Self.digest(Data(applicationIdentifier.utf8)),
            contextDigest: Self.digest(context.binding),
            envelopeDigest: Self.digest(encodedEnvelope))
        try faultInjector?.hit(.beforeAnchorUpdate)
        // This is an in-place Keychain update. The implementation never deletes the old anchor.
        try metadata.replaceAnchor(DurableAnchorCodec.encode(nextAnchor))
        try faultInjector?.hit(.afterAnchorUpdate)
        return DurableStateRecord(generation: nextGeneration, plaintext: plaintext)
    }

    private enum ValidatedState {
        case unanchoredEmpty(Data?)
        case anchoredEmpty(Data, DurableAnchor)
        case record(Data, DurableAnchor, DurableStateRecord)

        var generation: UInt64 {
            switch self {
            case .unanchoredEmpty, .anchoredEmpty: return 0
            case .record(_, let anchor, _): return anchor.generation
            }
        }

        var key: Data? {
            switch self {
            case .unanchoredEmpty(let key): return key
            case .anchoredEmpty(let key, _), .record(let key, _, _): return key
            }
        }

        var activeSlot: DurableStateSlot? {
            switch self {
            case .unanchoredEmpty, .anchoredEmpty: return nil
            case .record(_, let anchor, _): return anchor.slot
            }
        }
    }

    private func validatedState(context: DurableStateContext) throws -> ValidatedState {
        let anchorData = try metadata.readAnchor()
        let keyData = try metadata.readInstallationKey()
        let anySlot = try fileSystem.hasAnySlot()

        guard let anchorData else {
            if anySlot {
                guard let keyData else {
                    throw DurableStateStoreError.missingInstallationKey
                }
                _ = try validatedKey(keyData)
                throw DurableStateStoreError.missingAnchor
            }
            if let keyData { return .unanchoredEmpty(try validatedKey(keyData)) }
            return .unanchoredEmpty(nil)
        }

        guard let keyData else { throw DurableStateStoreError.missingInstallationKey }
        let key = try validatedKey(keyData)
        let anchor = try DurableAnchorCodec.decode(anchorData)
        guard anchor.schemaVersion <= DurableStateContext.currentSchemaVersion else {
            throw DurableStateStoreError.unsupportedSchemaVersion(anchor.schemaVersion)
        }
        guard anchor.schemaVersion == context.schemaVersion else {
            throw DurableStateStoreError.schemaMismatch(
                expected: context.schemaVersion, actual: anchor.schemaVersion)
        }
        guard
            Self.constantTimeEqual(
                anchor.applicationDigest,
                Self.digest(Data(applicationIdentifier.utf8))
            )
        else {
            throw DurableStateStoreError.applicationIdentityMismatch
        }
        guard Self.constantTimeEqual(anchor.contextDigest, Self.digest(context.binding)) else {
            throw DurableStateStoreError.contextMismatch
        }

        if anchor.generation == 0 {
            guard anchor.slotRaw == DurableAnchor.genesisSlot,
                anchor.envelopeDigest == Data(repeating: 0, count: 32)
            else {
                throw DurableStateStoreError.invalidGenesisAnchor
            }
            // A slot may be crash debris from a first commit interrupted before anchor update.
            return .anchoredEmpty(key, anchor)
        }
        guard let slot = anchor.slot else { throw DurableStateStoreError.corruptAnchor }
        guard
            let encodedEnvelope = try fileSystem.read(
                slot: slot, maximumBytes: Self.maximumEnvelopeBytes)
        else {
            throw DurableStateStoreError.missingAnchoredSlot(slot)
        }
        guard
            Self.constantTimeEqual(
                anchor.envelopeDigest,
                Self.digest(encodedEnvelope)
            )
        else {
            throw DurableStateStoreError.anchorDigestMismatch
        }
        let envelope = try DurableEnvelopeCodec.decode(
            encodedEnvelope, maximumPlaintextBytes: Self.maximumPlaintextBytes)
        guard envelope.schemaVersion <= DurableStateContext.currentSchemaVersion else {
            throw DurableStateStoreError.unsupportedSchemaVersion(envelope.schemaVersion)
        }
        guard envelope.schemaVersion == context.schemaVersion else {
            throw DurableStateStoreError.schemaMismatch(
                expected: context.schemaVersion, actual: envelope.schemaVersion)
        }
        guard envelope.slot == slot else {
            throw DurableStateStoreError.slotMismatch(expected: slot, actual: envelope.slot)
        }
        guard envelope.generation == anchor.generation else {
            throw DurableStateStoreError.generationMismatch(
                expected: anchor.generation, actual: envelope.generation)
        }
        let nonce: AES.GCM.Nonce
        let sealedBox: AES.GCM.SealedBox
        do {
            nonce = try AES.GCM.Nonce(data: envelope.nonce)
            sealedBox = try AES.GCM.SealedBox(
                nonce: nonce, ciphertext: envelope.ciphertext, tag: envelope.tag)
        } catch {
            throw DurableStateStoreError.corruptEnvelope
        }
        let plaintext: Data
        do {
            plaintext = try AES.GCM.open(
                sealedBox,
                using: SymmetricKey(data: key),
                authenticating: associatedData(
                    context: context, generation: anchor.generation, slot: slot))
        } catch {
            throw DurableStateStoreError.authenticationFailed
        }
        guard plaintext.count <= Self.maximumPlaintextBytes else {
            throw DurableStateStoreError.plaintextTooLarge(
                actual: plaintext.count, maximum: Self.maximumPlaintextBytes)
        }
        return .record(
            key,
            anchor,
            DurableStateRecord(generation: anchor.generation, plaintext: plaintext))
    }

    private func associatedData(
        context: DurableStateContext,
        generation: UInt64,
        slot: DurableStateSlot
    ) throws -> Data {
        let application = Data(applicationIdentifier.utf8)
        guard application.count <= Int(UInt16.max) else {
            throw DurableStateStoreError.invalidApplicationIdentifier
        }
        var data = Data("EUW-AAD1".utf8)
        data.appendBigEndian(DurableEnvelopeCodec.formatVersion)
        data.appendBigEndian(context.schemaVersion)
        data.appendBigEndian(UInt16(application.count))
        data.append(application)
        data.appendBigEndian(UInt32(context.binding.count))
        data.append(context.binding)
        data.appendBigEndian(generation)
        data.append(slot.rawValue)
        return data
    }

    private func validatedKey(_ key: Data) throws -> Data {
        guard key.count == 32 else { throw DurableStateStoreError.corruptInstallationKey }
        return key
    }

    private static func digest(_ data: Data) -> Data {
        Data(SHA256.hash(data: data))
    }

    private static func constantTimeEqual(_ lhs: Data, _ rhs: Data) -> Bool {
        guard lhs.count == rhs.count else { return false }
        var difference: UInt8 = 0
        for (left, right) in zip(lhs, rhs) { difference |= left ^ right }
        return difference == 0
    }

    private static func isValidApplicationIdentifier(_ value: String) -> Bool {
        let bytes = Array(value.utf8)
        guard !bytes.isEmpty, bytes.count <= 255, value != ".", value != ".." else {
            return false
        }
        return bytes.allSatisfy {
            (0x30...0x39).contains($0) || (0x41...0x5a).contains($0)
                || (0x61...0x7a).contains($0) || $0 == 0x2d || $0 == 0x2e
        }
    }
}

private struct StrictByteReader {
    private let bytes: [UInt8]
    private(set) var offset = 0

    init(_ data: Data) { bytes = Array(data) }

    var remainingCount: Int { bytes.count - offset }
    var isAtEnd: Bool { offset == bytes.count }

    mutating func readUInt8() throws -> UInt8 {
        let value = try readBytes(count: 1)
        return value[0]
    }

    mutating func readUInt16() throws -> UInt16 {
        let value = try readBytes(count: 2)
        return value.reduce(0) { ($0 << 8) | UInt16($1) }
    }

    mutating func readUInt32() throws -> UInt32 {
        let value = try readBytes(count: 4)
        return value.reduce(0) { ($0 << 8) | UInt32($1) }
    }

    mutating func readUInt64() throws -> UInt64 {
        let value = try readBytes(count: 8)
        return value.reduce(0) { ($0 << 8) | UInt64($1) }
    }

    mutating func readBytes(count: Int) throws -> [UInt8] {
        guard count >= 0 else { throw DurableStateStoreError.corruptEnvelope }
        let end = offset.addingReportingOverflow(count)
        guard !end.overflow, end.partialValue <= bytes.count else {
            throw DurableStateStoreError.corruptEnvelope
        }
        defer { offset = end.partialValue }
        return Array(bytes[offset..<end.partialValue])
    }
}

extension Data {
    fileprivate mutating func appendBigEndian<T: FixedWidthInteger>(_ value: T) {
        var bigEndian = value.bigEndian
        Swift.withUnsafeBytes(of: &bigEndian) { append(contentsOf: $0) }
    }
}
