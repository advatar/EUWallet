import Foundation
import Security
import XCTest
@testable import WalletShell

private enum PqExpectedFailure: Error { case failure }

private final class PqTestSigner: HybridClassicalKeyProviding {
    private(set) var references: [String] = []
    private var publicKeys: [String: Data] = [:]
    var signError: Error?

    func publicKeyRaw(keyRef: String) throws -> Data {
        references.append(keyRef)
        if let existing = publicKeys[keyRef] { return existing }
        let value = Data([0x04] + [UInt8](repeating: UInt8(publicKeys.count + 1), count: 64))
        publicKeys[keyRef] = value
        return value
    }

    func sign(keyRef _: String, payload _: Data) throws -> Data {
        if let signError { throw signError }
        return Data(repeating: 0x51, count: 64)
    }

    func keyAgreement(keyRef _: String, peerPublicKey _: Data) throws -> Data {
        Data(repeating: 0x71, count: 32)
    }

    func replacePublicKey(for reference: String, with value: Data) {
        publicKeys[reference] = value
    }
}

private final class PqTestBackend: ExperimentalPqGenerating {
    var malformed = false
    var signError: Error?
    private(set) var observedKeyLengths: [Int] = []
    private(set) var signCalls = 0

    func generateWrappedMaterial(
        wrappingKey: inout Data
    ) throws -> ExperimentalPqWrappedMaterial {
        observedKeyLengths.append(wrappingKey.count)
        return ExperimentalPqWrappedMaterial(
            nonce: Data(repeating: 0x10, count: malformed ? 11 : 12),
            encryptedPrivateKey: Data(repeating: 0x20, count: 132),
            mlDsa65PublicKey: Data(repeating: 0x30, count: 1_952),
            mlKem768PublicKey: Data(repeating: 0x40, count: 1_184))
    }

    func signWrappedMaterial(
        wrappingKey _: inout Data,
        nonce _: Data,
        encryptedPrivateKey _: Data,
        payload _: Data
    ) throws -> Data {
        signCalls += 1
        if let signError { throw signError }
        return Data(repeating: 0x61, count: 3_309)
    }

    func openWrappedRecovery(
        wrappingKey _: inout Data,
        custodyNonce _: Data,
        encryptedPrivateKey _: Data,
        recipientClassicalPublicKey _: Data,
        recipientMlKem768PublicKey _: Data,
        classicalSharedSecret _: inout Data,
        context _: Data,
        envelope _: ExperimentalHybridRecoveryEnvelope
    ) throws -> Data {
        Data("recovered".utf8)
    }
}

private final class PqTestWrappingKeys: ExperimentalPqWrappingKeyStoring {
    var values: [String: Data] = [:]
    var loadError: Error?
    private(set) var deleted: [String] = []

    func create(reference: String, prompt _: String) throws -> Data {
        let value = Data(repeating: UInt8(values.count + 1), count: 32)
        values[reference] = value
        return value
    }

    func load(reference: String, prompt _: String) throws -> Data {
        if let loadError { throw loadError }
        guard let value = values[reference] else {
            throw ExperimentalPqCustodyError.missingWrappingKey
        }
        return value
    }

    func delete(reference: String) throws {
        deleted.append(reference)
        values.removeValue(forKey: reference)
    }
}

private final class PqTestRecords: ExperimentalPqRecordStoring {
    var values: [String: ExperimentalPqCustodyRecord] = [:]

    func load(logicalKeyID: String) throws -> ExperimentalPqCustodyRecord? {
        values[logicalKeyID]
    }

    func commit(_ record: ExperimentalPqCustodyRecord) throws {
        values[record.reference.logicalKeyID] = record
    }

    func delete(logicalKeyID: String) throws { values.removeValue(forKey: logicalKeyID) }
}

private final class PqTestAnchors: ExperimentalPqGenerationAnchoring {
    var values: [String: ExperimentalPqGenerationAnchor] = [:]
    var failNextReplace = false

    func load(logicalKeyID: String) throws -> ExperimentalPqGenerationAnchor? {
        values[logicalKeyID]
    }

    func replace(
        expected: ExperimentalPqGenerationAnchor?,
        with next: ExperimentalPqGenerationAnchor
    ) throws {
        if failNextReplace {
            failNextReplace = false
            throw ExperimentalPqCustodyError.persistenceFailure
        }
        guard values[next.logicalKeyID] == expected else {
            throw ExperimentalPqCustodyError.rollbackDetected
        }
        values[next.logicalKeyID] = next
    }
}

final class ExperimentalPqCustodyTests: XCTestCase {
    private var signer: PqTestSigner!
    private var backend: PqTestBackend!
    private var keys: PqTestWrappingKeys!
    private var records: PqTestRecords!
    private var anchors: PqTestAnchors!
    private var custody: ExperimentalHybridKeyCustody!

    override func setUp() {
        signer = PqTestSigner()
        backend = PqTestBackend()
        keys = PqTestWrappingKeys()
        records = PqTestRecords()
        anchors = PqTestAnchors()
        custody = ExperimentalHybridKeyCustody(
            signer: signer,
            backend: backend,
            wrappingKeys: keys,
            records: records,
            anchors: anchors)
    }

    func testCreatesOneBoundGenerationAndLoadsOnlyItsWrappingKey() throws {
        let reference = try custody.rotate(logicalKeyID: "wallet-key", prompt: "Create")
        XCTAssertEqual(reference.generation, 1)
        XCTAssertEqual(reference.classicalKeyReference, "wallet-key.hybrid.1.p256")
        XCTAssertEqual(reference.wrappedPqReference, "wallet-key.hybrid.1.pq-wrap")
        XCTAssertEqual(backend.observedKeyLengths, [32])
        try custody.withUnlockedGeneration(reference: reference, prompt: "Use") { record, key in
            XCTAssertEqual(record.reference, reference)
            XCTAssertEqual(key.count, 32)
        }
        XCTAssertEqual(signer.references, [
            reference.classicalKeyReference,
            reference.classicalKeyReference,
        ])
    }

    func testRotationAlwaysRotatesBothComponentsAndRetiresOldWrappingKey() throws {
        let first = try custody.rotate(logicalKeyID: "wallet-key", prompt: "Create")
        let second = try custody.rotate(logicalKeyID: "wallet-key", prompt: "Rotate")
        XCTAssertEqual(second.generation, 2)
        XCTAssertNotEqual(first.classicalKeyReference, second.classicalKeyReference)
        XCTAssertNotEqual(first.wrappedPqReference, second.wrappedPqReference)
        XCTAssertEqual(keys.deleted, [first.wrappedPqReference])
        XCTAssertThrowsError(try custody.withUnlockedGeneration(reference: first, prompt: "Use") { _, _ in }) {
            XCTAssertEqual($0 as? ExperimentalPqCustodyError, .mixedGeneration)
        }
    }

    func testMixedGenerationAndRolledBackRecordAreRejected() throws {
        let first = try custody.rotate(logicalKeyID: "wallet-key", prompt: "Create")
        let firstRecord = records.values["wallet-key"]!
        _ = try custody.rotate(logicalKeyID: "wallet-key", prompt: "Rotate")
        records.values["wallet-key"] = firstRecord

        XCTAssertThrowsError(try custody.withUnlockedGeneration(reference: first, prompt: "Use") { _, _ in }) {
            XCTAssertEqual($0 as? ExperimentalPqCustodyError, .rollbackDetected)
        }
    }

    func testFailedAnchorCommitRestoresPriorGenerationAndDeletesCandidateKey() throws {
        let first = try custody.rotate(logicalKeyID: "wallet-key", prompt: "Create")
        anchors.failNextReplace = true
        XCTAssertThrowsError(try custody.rotate(logicalKeyID: "wallet-key", prompt: "Rotate")) {
            XCTAssertEqual($0 as? ExperimentalPqCustodyError, .persistenceFailure)
        }
        XCTAssertEqual(records.values["wallet-key"]?.reference, first)
        XCTAssertEqual(keys.deleted.last, "wallet-key.hybrid.2.pq-wrap")
        try custody.withUnlockedGeneration(reference: first, prompt: "Use") { _, key in
            XCTAssertEqual(key.count, 32)
        }
    }

    func testMissingKeyBiometricCancellationAndLockedDeviceFailClosed() throws {
        let reference = try custody.rotate(logicalKeyID: "wallet-key", prompt: "Create")
        keys.values.removeValue(forKey: reference.wrappedPqReference)
        XCTAssertThrowsError(try custody.withUnlockedGeneration(reference: reference, prompt: "Use") { _, _ in }) {
            XCTAssertEqual($0 as? ExperimentalPqCustodyError, .missingWrappingKey)
        }

        keys.loadError = ExperimentalPqCustodyError.keychainFailure(errSecUserCanceled)
        XCTAssertThrowsError(try custody.withUnlockedGeneration(reference: reference, prompt: "Use") { _, _ in }) {
            XCTAssertEqual(
                $0 as? ExperimentalPqCustodyError,
                .keychainFailure(errSecUserCanceled))
        }
        keys.loadError = ExperimentalPqCustodyError.keychainFailure(errSecInteractionNotAllowed)
        XCTAssertThrowsError(try custody.withUnlockedGeneration(reference: reference, prompt: "Use") { _, _ in }) {
            XCTAssertEqual(
                $0 as? ExperimentalPqCustodyError,
                .keychainFailure(errSecInteractionNotAllowed))
        }
    }

    func testChangedClassicalKeyForSameReferenceIsRejected() throws {
        let reference = try custody.rotate(logicalKeyID: "wallet-key", prompt: "Create")
        signer.replacePublicKey(for: reference.classicalKeyReference, with: Data(repeating: 9, count: 65))

        XCTAssertThrowsError(
            try custody.withUnlockedGeneration(reference: reference, prompt: "Use") { _, _ in }
        ) {
            XCTAssertEqual($0 as? ExperimentalPqCustodyError, .mixedGeneration)
        }
    }

    func testHybridSignReturnsBothComponentsOrNoResult() throws {
        let reference = try custody.rotate(logicalKeyID: "wallet-key", prompt: "Create")
        let signature = try custody.sign(
            reference: reference,
            payload: Data([1, 2, 3]),
            prompt: "Sign")
        XCTAssertEqual(signature.classicalSignature.count, 64)
        XCTAssertEqual(signature.postQuantumSignature.count, 3_309)
        XCTAssertEqual(backend.signCalls, 1)

        backend.signError = PqExpectedFailure.failure
        XCTAssertThrowsError(try custody.sign(
            reference: reference,
            payload: Data([4]),
            prompt: "Sign"))
        XCTAssertEqual(backend.signCalls, 2)

        backend.signError = nil
        signer.signError = PqExpectedFailure.failure
        XCTAssertThrowsError(try custody.sign(
            reference: reference,
            payload: Data([5]),
            prompt: "Sign"))
        XCTAssertEqual(backend.signCalls, 2, "PQ signing must not run after classical failure")
    }

    func testRecoveryBindsTheCurrentLogicalGenerationAndReturnsOnlyAtomicPlaintext() throws {
        let reference = try custody.rotate(logicalKeyID: "wallet-key", prompt: "Create")
        let envelope = ExperimentalHybridRecoveryEnvelope(
            senderIdentity: "recovery-provider.example",
            recipientIdentity: reference.logicalKeyID,
            keyGeneration: reference.generation,
            classicalEphemeralPublicKey: Data([0x04] + [UInt8](repeating: 1, count: 64)),
            mlKem768Ciphertext: Data(repeating: 2, count: 1_088),
            transcriptHash: Data(repeating: 3, count: 32),
            nonce: Data(repeating: 4, count: 12),
            ciphertext: Data(repeating: 5, count: 32))
        XCTAssertEqual(
            try custody.openRecovery(
                logicalKeyID: "wallet-key",
                context: Data("session".utf8),
                envelope: envelope,
                prompt: "Recover"),
            Data("recovered".utf8))

        let stale = ExperimentalHybridRecoveryEnvelope(
            senderIdentity: envelope.senderIdentity,
            recipientIdentity: envelope.recipientIdentity,
            keyGeneration: reference.generation + 1,
            classicalEphemeralPublicKey: envelope.classicalEphemeralPublicKey,
            mlKem768Ciphertext: envelope.mlKem768Ciphertext,
            transcriptHash: envelope.transcriptHash,
            nonce: envelope.nonce,
            ciphertext: envelope.ciphertext)
        XCTAssertThrowsError(try custody.openRecovery(
            logicalKeyID: "wallet-key",
            context: Data("session".utf8),
            envelope: stale,
            prompt: "Recover")) {
                XCTAssertEqual($0 as? ExperimentalPqCustodyError, .mixedGeneration)
            }
    }

    func testMalformedBackendMaterialIsNeverCommittedAndCandidateKeyIsDeleted() {
        backend.malformed = true
        XCTAssertThrowsError(try custody.rotate(logicalKeyID: "wallet-key", prompt: "Create")) {
            XCTAssertEqual($0 as? ExperimentalPqCustodyError, .malformedMaterial)
        }
        XCTAssertNil(records.values["wallet-key"])
        XCTAssertNil(anchors.values["wallet-key"])
        XCTAssertEqual(keys.deleted, ["wallet-key.hybrid.1.pq-wrap"])
    }

    func testDiagnosticsContainNoCiphertextOrPublicMaterial() throws {
        let reference = try custody.rotate(logicalKeyID: "wallet-key", prompt: "Create")
        let record = records.values["wallet-key"]!
        let debug = record.debugDescription
        XCTAssertTrue(debug.contains("[REDACTED]"))
        XCTAssertFalse(debug.contains(record.encryptedPrivateKey.base64EncodedString()))
        XCTAssertFalse(debug.contains(record.mlDsa65PublicKey.base64EncodedString()))
        XCTAssertFalse(reference.debugDescription.contains("hash"))
    }

    func testAppleRecordStorePersistsOnlyCiphertextAndRoundTrips() throws {
        let reference = try custody.rotate(logicalKeyID: "wallet-key", prompt: "Create")
        let source = records.values["wallet-key"]!
        let root = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        defer { try? FileManager.default.removeItem(at: root) }
        let store = try AppleExperimentalPqRecordStore(applicationSupportRoot: root)
        try store.commit(source)
        XCTAssertEqual(try store.load(logicalKeyID: "wallet-key"), source)

        let files = try FileManager.default.contentsOfDirectory(
            at: root.appendingPathComponent("ExperimentalPqCustody"),
            includingPropertiesForKeys: [.isExcludedFromBackupKey])
        XCTAssertEqual(files.count, 1)
        XCTAssertFalse(files[0].lastPathComponent.contains(reference.logicalKeyID))
        #if os(iOS)
            XCTAssertEqual(
                try files[0].resourceValues(forKeys: [.isExcludedFromBackupKey])
                    .isExcludedFromBackup,
                true)
        #endif
        let raw = try Data(contentsOf: files[0])
        XCTAssertFalse(raw.range(of: Data("EUWALLET-PQ-SEEDS-V1".utf8)) != nil)
    }
}
