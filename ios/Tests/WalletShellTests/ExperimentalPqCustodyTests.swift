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

private final class PqTestBackend: ExperimentalPqGenerating, ExperimentalHybridExportCryptography,
    ExperimentalProviderCredentialVerifying
{
    var malformed = false
    var signError: Error?
    private(set) var observedKeyLengths: [Int] = []
    private(set) var signCalls = 0
    private(set) var lastSealedPlaintext: Data?
    private(set) var lastRecoveryContext: Data?
    private(set) var lastExportDraft: ExperimentalHybridExportDraft?

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
        context: Data,
        envelope _: ExperimentalHybridRecoveryEnvelope
    ) throws -> Data {
        lastRecoveryContext = context
        return Data("recovered".utf8)
    }

    func sealRecovery(
        senderIdentity: String,
        recipientIdentity: String,
        keyGeneration: UInt64,
        recipientClassicalPublicKey _: Data,
        recipientMlKem768PublicKey _: Data,
        context: Data,
        plaintext: Data
    ) throws -> ExperimentalHybridRecoveryEnvelope {
        lastRecoveryContext = context
        lastSealedPlaintext = plaintext
        return ExperimentalHybridRecoveryEnvelope(
            senderIdentity: senderIdentity,
            recipientIdentity: recipientIdentity,
            keyGeneration: keyGeneration,
            classicalEphemeralPublicKey: Data([0x04] + [UInt8](repeating: 1, count: 64)),
            mlKem768Ciphertext: Data(repeating: 2, count: 1_088),
            transcriptHash: Data(repeating: 3, count: 32),
            nonce: Data(repeating: 4, count: 12),
            ciphertext: Data(repeating: 5, count: 32))
    }

    func prepareExport(draft: ExperimentalHybridExportDraft) throws -> Data {
        lastExportDraft = draft
        return Data("canonical-export-tbs".utf8)
    }

    func finalizeExport(
        draft: ExperimentalHybridExportDraft,
        signingMaterial _: ExperimentalHybridSigningMaterial,
        signature: ExperimentalHybridSignature
    ) throws -> Data {
        lastExportDraft = draft
        guard signature.classicalSignature.count == 64,
              signature.postQuantumSignature.count == 3_309
        else { throw PqExpectedFailure.failure }
        return Data("hybrid-export-v2".utf8)
    }

    func openExport(
        artifact _: Data,
        expectedWalletIdentity _: String,
        expectedKeyGeneration _: UInt64,
        expectedPublicKeyEnvelope _: Data,
        nowEpochSeconds _: UInt64
    ) throws -> CoreDurableCheckpoint {
        CoreDurableCheckpoint(generation: 8, bytes: Data("imported-checkpoint".utf8))
    }

    func verifyProviderCredential(
        _ verification: ExperimentalProviderCredentialVerification
    ) throws -> ExperimentalCatalogueCredential {
        guard verification.origin == "https://issuer.example",
              verification.allowedOrigins == ["https://issuer.example"],
              verification.response.offeredKeyAgreementProfiles == ["euwallet-hybrid-pq-v1"],
              verification.response.credentialConfigurationID
                == ExperimentalHybridCredentialAcquisition.configurationID
        else { throw PqExpectedFailure.failure }
        return ExperimentalCatalogueCredential(
            namespacedType: "urn:advatar:experimental:pq:vcissuer-hybrid-credential-v1",
            payload: verification.response.wrapper,
            disclosures: [],
            issuerOrigin: verification.origin,
            keyGeneration: verification.response.keyGeneration)
    }
}

private final class PqProviderTransport: ExperimentalPrivateProviderTransporting {
    private(set) var requestedConfigurationID: String?
    private(set) var requestCount = 0

    func fetchHybridCredential(
        origin _: String,
        credentialConfigurationID: String
    ) async throws -> ExperimentalProviderCredentialResponse {
        requestCount += 1
        requestedConfigurationID = credentialConfigurationID
        return ExperimentalProviderCredentialResponse(
            offeredKeyAgreementProfiles: ["euwallet-hybrid-pq-v1"],
            credentialConfigurationID: credentialConfigurationID,
            credentialFormat: "dev-hybrid-pq+cbor",
            wrapper: Data("verified-wrapper".utf8),
            publicKeyEnvelope: Data("trusted-key".utf8),
            classicalKeyID: "issuer-es256",
            postQuantumKeyID: "issuer-ml-dsa-65",
            keyGeneration: 7,
            transactionID: Data("transaction".utf8),
            nonce: Data(repeating: 5, count: 32))
    }
}

private final class PqRecoveryEngine: DurableWalletEngineDriving {
    var exported = CoreDurableCheckpoint(generation: 8, bytes: Data("checkpoint".utf8))
    private(set) var restored: CoreDurableCheckpoint?

    func handleEventJson(eventJson _: String) throws -> String { "[]" }
    func prepareForDurableRestore(environment _: CoreDurableEnvironment) throws {}
    func makeDurableCheckpoint(generation _: UInt64) throws -> CoreDurableCheckpoint { exported }
    func restoreDurableCheckpointRecord(_ checkpoint: CoreDurableCheckpoint) throws {
        restored = checkpoint
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

    func testCheckpointRecoverySealsAndRestoresActualDurableCoreState() throws {
        let reference = try custody.rotate(logicalKeyID: "wallet-key", prompt: "Create")
        let engine = PqRecoveryEngine()
        let recovery = ExperimentalHybridCheckpointRecovery(
            engine: engine,
            backend: backend,
            custody: custody)
        let session = Data("session-8".utf8)
        let envelope = try recovery.sealCheckpoint(
            checkpointGeneration: 8,
            senderIdentity: "recovery-provider.example",
            recipient: ExperimentalHybridRecoveryRecipient(
                logicalKeyID: reference.logicalKeyID,
                keyGeneration: reference.generation,
                classicalPublicKey: Data([0x04] + [UInt8](repeating: 1, count: 64)),
                mlKem768PublicKey: records.values["wallet-key"]!.mlKem768PublicKey),
            sessionContext: session)
        XCTAssertEqual(backend.lastSealedPlaintext, engine.exported.bytes)

        try recovery.restoreCheckpoint(
            checkpointGeneration: 8,
            logicalKeyID: "wallet-key",
            sessionContext: session,
            envelope: envelope,
            prompt: "Recover")
        XCTAssertEqual(
            engine.restored,
            CoreDurableCheckpoint(generation: 8, bytes: Data("recovered".utf8)))

        let sealedContext = backend.lastRecoveryContext
        XCTAssertThrowsError(try recovery.sealCheckpoint(
            checkpointGeneration: 0,
            senderIdentity: "recovery-provider.example",
            recipient: ExperimentalHybridRecoveryRecipient(
                logicalKeyID: reference.logicalKeyID,
                keyGeneration: reference.generation,
                classicalPublicKey: Data(repeating: 1, count: 65),
                mlKem768PublicKey: Data(repeating: 2, count: 1_184)),
            sessionContext: session))
        XCTAssertEqual(backend.lastRecoveryContext, sealedContext)
    }

    func testHybridExportSignsAndRestoresActualDurableCoreState() throws {
        let reference = try custody.rotate(logicalKeyID: "wallet-key", prompt: "Create")
        let engine = PqRecoveryEngine()
        let exporter = ExperimentalHybridCheckpointExport(
            engine: engine,
            custody: custody,
            crypto: backend)
        let artifact = try exporter.create(
            logicalKeyID: "wallet-key",
            checkpointGeneration: 8,
            nonce: Data(repeating: 7, count: 16),
            createdAtEpochSeconds: 1_000,
            expiresAtEpochSeconds: 2_000,
            prompt: "Export")
        XCTAssertEqual(artifact, Data("hybrid-export-v2".utf8))
        XCTAssertEqual(backend.lastExportDraft?.checkpoint, engine.exported.bytes)
        XCTAssertEqual(backend.lastExportDraft?.keyGeneration, reference.generation)

        try exporter.restore(
            artifact: artifact,
            expectedWalletIdentity: "wallet-key",
            expectedKeyGeneration: reference.generation,
            expectedPublicKeyEnvelope: Data("trusted-key".utf8),
            nowEpochSeconds: 1_500)
        XCTAssertEqual(
            engine.restored,
            CoreDurableCheckpoint(
                generation: 8,
                bytes: Data("imported-checkpoint".utf8)))
    }

    func testPrivateProviderAcquisitionStoresOnlyInExperimentalCatalogue() async throws {
        let transport = PqProviderTransport()
        let catalogue = ExperimentalCredentialCatalogue()
        let acquisition = ExperimentalHybridCredentialAcquisition(
            allowedOrigins: ["https://issuer.example"],
            transport: transport,
            verifier: backend,
            catalogue: catalogue)
        let credential = try await acquisition.acquire(
            origin: "https://issuer.example",
            walletIdentity: Data("wallet-holder".utf8),
            nowEpochSeconds: 1_500)

        XCTAssertEqual(
            transport.requestedConfigurationID,
            ExperimentalHybridCredentialAcquisition.configurationID)
        XCTAssertEqual(catalogue.all(), [credential])
        XCTAssertFalse(credential.satisfiesProductionRequest("eu.europa.ec.eudi.pid.1"))
        XCTAssertTrue(credential.namespacedType.hasPrefix("urn:advatar:experimental:pq:"))

        do {
            _ = try await ExperimentalHybridCredentialAcquisition(
                allowedOrigins: ["https://other.example"],
                transport: transport,
                verifier: backend,
                catalogue: catalogue)
                .acquire(
                    origin: "https://issuer.example",
                    walletIdentity: Data("wallet-holder".utf8),
                    nowEpochSeconds: 1_500)
            XCTFail("expected disallowed origin to fail before transport")
        } catch {
            XCTAssertEqual(error as? ExperimentalPqCustodyError, .malformedMaterial)
        }
        XCTAssertEqual(transport.requestCount, 1)
        XCTAssertEqual(catalogue.all(), [credential])
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
