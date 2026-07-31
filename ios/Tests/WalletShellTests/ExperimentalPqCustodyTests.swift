import Foundation
import Security
import XCTest
@testable import WalletShell

private final class PqTestSigner: HybridClassicalKeyProviding {
    private(set) var references: [String] = []
    private var publicKeys: [String: Data] = [:]

    func publicKeyRaw(keyRef: String) throws -> Data {
        references.append(keyRef)
        if let existing = publicKeys[keyRef] { return existing }
        let value = Data([0x04] + [UInt8](repeating: UInt8(publicKeys.count + 1), count: 64))
        publicKeys[keyRef] = value
        return value
    }

    func replacePublicKey(for reference: String, with value: Data) {
        publicKeys[reference] = value
    }
}

private final class PqTestBackend: ExperimentalPqGenerating {
    var malformed = false
    private(set) var observedKeyLengths: [Int] = []

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
