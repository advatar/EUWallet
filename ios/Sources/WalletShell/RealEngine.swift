import Foundation

// Current app and executor composition keeps the generated UniFFI engine behind this file's
// adapter. They receive only the durable coordinator plus read-only projections, and an
// architecture test guards those sources against known raw mutators. The generated binding itself
// remains a public compatibility surface, so Android integration and stronger API isolation remain
// tracked work.
// Guarded so the package still builds on hosts without the xcframework linked.
#if canImport(wallet_coreFFI)
    import wallet_coreFFI

    /// Generated Rust adapter. Rust generates both PQ keys and returns only AES-GCM-wrapped seeds.
    final class FfiExperimentalPqBackend: ExperimentalPqGenerating,
        ExperimentalHybridExportCryptography, ExperimentalProviderCredentialVerifying
    {
        func generateWrappedMaterial(
            wrappingKey: inout Data
        ) throws -> ExperimentalPqWrappedMaterial {
            var transfer = wrappingKey
            defer { transfer.clearSensitiveBytes() }
            let generated = try generateExperimentalPqWrappedKeyMaterial(
                wrappingKey: transfer)
            return ExperimentalPqWrappedMaterial(
                nonce: generated.nonce,
                encryptedPrivateKey: generated.encryptedPrivateKey,
                mlDsa65PublicKey: generated.mlDsa65PublicKey,
                mlKem768PublicKey: generated.mlKem768PublicKey)
        }

        func signWrappedMaterial(
            wrappingKey: inout Data,
            nonce: Data,
            encryptedPrivateKey: Data,
            payload: Data
        ) throws -> Data {
            var transfer = wrappingKey
            defer { transfer.clearSensitiveBytes() }
            return try signExperimentalPqWrappedKeyMaterial(
                wrappingKey: transfer,
                nonce: nonce,
                encryptedPrivateKey: encryptedPrivateKey,
                payload: payload)
        }


        func openWrappedRecovery(
            wrappingKey: inout Data,
            custodyNonce: Data,
            encryptedPrivateKey: Data,
            recipientClassicalPublicKey: Data,
            recipientMlKem768PublicKey: Data,
            classicalSharedSecret: inout Data,
            context: Data,
            envelope: ExperimentalHybridRecoveryEnvelope
        ) throws -> Data {
            var keyTransfer = wrappingKey
            var secretTransfer = classicalSharedSecret
            defer {
                keyTransfer.clearSensitiveBytes()
                secretTransfer.clearSensitiveBytes()
            }
            return try openExperimentalHybridRecovery(
                request: FfiExperimentalHybridRecoveryOpenRequest(
                    wrappingKey: keyTransfer,
                    custodyNonce: custodyNonce,
                    encryptedPrivateKey: encryptedPrivateKey,
                    recipientClassicalPublicKey: recipientClassicalPublicKey,
                    recipientMlKem768PublicKey: recipientMlKem768PublicKey,
                    classicalSharedSecret: secretTransfer,
                    context: context,
                    envelope: FfiExperimentalHybridRecoveryEnvelope(
                        senderIdentity: envelope.senderIdentity,
                        recipientIdentity: envelope.recipientIdentity,
                        keyGeneration: envelope.keyGeneration,
                        classicalEphemeralPublicKey: envelope.classicalEphemeralPublicKey,
                        mlKem768Ciphertext: envelope.mlKem768Ciphertext,
                        transcriptHash: envelope.transcriptHash,
                        nonce: envelope.nonce,
                        ciphertext: envelope.ciphertext)))
        }

        func sealRecovery(
            senderIdentity: String,
            recipientIdentity: String,
            keyGeneration: UInt64,
            recipientClassicalPublicKey: Data,
            recipientMlKem768PublicKey: Data,
            context: Data,
            plaintext: Data
        ) throws -> ExperimentalHybridRecoveryEnvelope {
            let envelope = try sealExperimentalHybridRecovery(
                senderIdentity: senderIdentity,
                recipientIdentity: recipientIdentity,
                keyGeneration: keyGeneration,
                recipientClassicalPublicKey: recipientClassicalPublicKey,
                recipientMlKem768PublicKey: recipientMlKem768PublicKey,
                context: context,
                plaintext: plaintext)
            return ExperimentalHybridRecoveryEnvelope(
                senderIdentity: envelope.senderIdentity,
                recipientIdentity: envelope.recipientIdentity,
                keyGeneration: envelope.keyGeneration,
                classicalEphemeralPublicKey: envelope.classicalEphemeralPublicKey,
                mlKem768Ciphertext: envelope.mlKem768Ciphertext,
                transcriptHash: envelope.transcriptHash,
                nonce: envelope.nonce,
                ciphertext: envelope.ciphertext)
        }

        func prepareExport(draft: ExperimentalHybridExportDraft) throws -> Data {
            try prepareExperimentalHybridWalletExport(draft: ffiExportDraft(draft))
        }

        func finalizeExport(
            draft: ExperimentalHybridExportDraft,
            signingMaterial: ExperimentalHybridSigningMaterial,
            signature: ExperimentalHybridSignature
        ) throws -> Data {
            try finalizeExperimentalHybridWalletExport(
                request: FfiExperimentalHybridExportFinalizeRequest(
                    draft: ffiExportDraft(draft),
                    classicalPublicKey: signingMaterial.classicalPublicKey,
                    mlDsa65PublicKey: signingMaterial.mlDsa65PublicKey,
                    classicalSignature: signature.classicalSignature,
                    mlDsa65Signature: signature.postQuantumSignature))
        }

        func openExport(
            artifact: Data,
            expectedWalletIdentity: String,
            expectedKeyGeneration: UInt64,
            expectedPublicKeyEnvelope: Data,
            nowEpochSeconds: UInt64
        ) throws -> CoreDurableCheckpoint {
            let checkpoint = try openExperimentalHybridWalletExport(
                request: FfiExperimentalHybridExportOpenRequest(
                    artifact: artifact,
                    expectedWalletIdentity: expectedWalletIdentity,
                    expectedKeyGeneration: expectedKeyGeneration,
                    expectedPublicKeyEnvelope: expectedPublicKeyEnvelope,
                    nowEpochSeconds: nowEpochSeconds))
            return CoreDurableCheckpoint(
                generation: checkpoint.generation,
                bytes: checkpoint.bytes)
        }

        private func ffiExportDraft(
            _ draft: ExperimentalHybridExportDraft
        ) -> FfiExperimentalHybridExportDraft {
            FfiExperimentalHybridExportDraft(
                walletIdentity: draft.walletIdentity,
                keyGeneration: draft.keyGeneration,
                checkpointGeneration: draft.checkpointGeneration,
                nonce: draft.nonce,
                createdAtEpochSeconds: draft.createdAtEpochSeconds,
                expiresAtEpochSeconds: draft.expiresAtEpochSeconds,
                checkpoint: draft.checkpoint)
        }

        func verifyProviderCredential(
            _ verification: ExperimentalProviderCredentialVerification
        ) throws -> ExperimentalCatalogueCredential {
            let response = verification.response
            let credential = try verifyExperimentalProviderCredential(
                request: FfiExperimentalProviderCredentialRequest(
                    origin: verification.origin,
                    allowedOrigins: verification.allowedOrigins,
                    offeredKeyAgreementProfiles: response.offeredKeyAgreementProfiles,
                    credentialConfigurationId: response.credentialConfigurationID,
                    credentialFormat: response.credentialFormat,
                    wrapper: response.wrapper,
                    publicKeyEnvelope: response.publicKeyEnvelope,
                    expectedClassicalKeyId: response.classicalKeyID,
                    expectedPqKeyId: response.postQuantumKeyID,
                    expectedGeneration: response.keyGeneration,
                    walletIdentity: verification.walletIdentity,
                    issuerIdentity: verification.origin,
                    transactionId: response.transactionID,
                    audience: verification.origin,
                    nonce: response.nonce,
                    nowEpochSeconds: verification.nowEpochSeconds))
            return ExperimentalCatalogueCredential(
                namespacedType: credential.namespacedType,
                payload: credential.payload,
                disclosures: credential.disclosures,
                issuerOrigin: credential.issuerOrigin,
                keyGeneration: credential.keyGeneration)
        }
    }

    /// Production composition for one application-scoped hybrid-key custody domain.
    /// PQ material remains software-generated and wrapped; only P-256 uses Secure Enclave.
    enum FfiExperimentalPqCustodyFactory {
        static func make(applicationIdentifier: String) throws -> ExperimentalHybridKeyCustody {
            let serviceRoot = "\(applicationIdentifier).experimental-pq"
            return ExperimentalHybridKeyCustody(
                signer: SecureEnclaveSigner(),
                backend: FfiExperimentalPqBackend(),
                wrappingKeys: AppleExperimentalPqWrappingKeyStore(
                    service: "\(serviceRoot).wrapping"),
                records: try AppleExperimentalPqRecordStore(),
                anchors: AppleExperimentalPqGenerationAnchorStore(
                    service: "\(serviceRoot).generation"))
        }
    }

    extension FfiDurableCheckpoint: CustomStringConvertible, CustomDebugStringConvertible {
        public var description: String { "FfiDurableCheckpoint(redacted)" }
        public var debugDescription: String { description }
    }

    /// The only generated-engine adapter allowed to drive mutating Core operations. File-private
    /// visibility prevents the app and native services from retaining or downcasting to it.
    private final class FfiDurableWalletEngineAdapter: DurableWalletEngineDriving {
        private let engine: WalletEngine

        init(engine: WalletEngine) {
            self.engine = engine
        }

        func handleEventJson(eventJson: String) throws -> String {
            engine.handleEventJson(eventJson: eventJson)
        }

        func prepareForDurableRestore(environment: CoreDurableEnvironment) throws {
            try engine.prepareDurableEnvironment(
                clockEpoch: environment.clockEpoch,
                signedTrustList: environment.signedTrustList,
                operatorPublicKey: environment.operatorPublicKey,
                devicePublicKey: environment.devicePublicKey,
                wuaJwt: environment.wuaJwt,
                wuaProviderPublicKey: environment.wuaProviderPublicKey)
        }

        func makeDurableCheckpoint(generation: UInt64) throws -> CoreDurableCheckpoint {
            let checkpoint = try engine.exportDurableCheckpoint(generation: generation)
            return CoreDurableCheckpoint(
                generation: checkpoint.generation,
                bytes: checkpoint.bytes)
        }

        func restoreDurableCheckpointRecord(_ checkpoint: CoreDurableCheckpoint) throws {
            try engine.restoreDurableCheckpoint(
                checkpoint: FfiDurableCheckpoint(
                    generation: checkpoint.generation,
                    bytes: checkpoint.bytes))
        }

        func durableResumeEffectsJson() -> String {
            engine.durableResumeEffectsJson()
        }
    }

    /// Controlled live composition for the generated Core. Mutations are exposed only through
    /// `lifecycle`; the remaining methods are read-only projections used to render wallet state.
    final class FfiWalletRuntime {
        let lifecycle: DurableLifecycleCoordinator
        private let engine: WalletEngine

        private init(
            applicationIdentifier: String,
            walletClientId: String,
            deviceKeyReference: String,
            environment: CoreDurableEnvironment,
            store: any DurableStateStore
        ) throws {
            let engine = WalletEngine(
                walletClientId: walletClientId,
                deviceKeyRef: deviceKeyReference)
            let context = try DurableLifecycleContextFactory.make(
                applicationIdentifier: applicationIdentifier,
                walletClientId: walletClientId,
                deviceKeyReference: deviceKeyReference)
            let lifecycle = DurableLifecycleCoordinator(
                engine: FfiDurableWalletEngineAdapter(engine: engine),
                store: store,
                context: context)
            self.engine = engine
            self.lifecycle = lifecycle
            try lifecycle.bootstrap(environment: environment)
        }

        /// Explicitly demo/test-only composition. Demo cryptographic identities are regenerated on
        /// launch, so persisting their checkpoint under yesterday's keys would make restore fail.
        /// Production must inject `AppleDurableStateStore` with stable installation identities.
        static func ephemeralDemo(
            applicationIdentifier: String,
            walletClientId: String,
            deviceKeyReference: String,
            environment: CoreDurableEnvironment
        ) throws -> FfiWalletRuntime {
            try durable(
                applicationIdentifier: applicationIdentifier,
                walletClientId: walletClientId,
                deviceKeyReference: deviceKeyReference,
                environment: environment,
                store: DemoEphemeralDurableStateStore())
        }

        /// Compose a generated Core with a caller-owned durable store without exposing the raw
        /// engine. Production composition supplies `AppleDurableStateStore`; simulator assurance
        /// tests inject a process-local store to exercise restart/restore deterministically.
        static func durable(
            applicationIdentifier: String,
            walletClientId: String,
            deviceKeyReference: String,
            environment: CoreDurableEnvironment,
            store: any DurableStateStore
        ) throws -> FfiWalletRuntime {
            try FfiWalletRuntime(
                applicationIdentifier: applicationIdentifier,
                walletClientId: walletClientId,
                deviceKeyReference: deviceKeyReference,
                environment: environment,
                store: store)
        }

        func heldCredentialsJSON() -> String { engine.heldCredentialsJson() }

        /// Drive one event straight through the Core and return its raw effect JSON. The Digital
        /// Credentials API provider extension needs the `emitDcApiResponse` effect, which the
        /// app-shell `EffectExecutor` intentionally drops (the browser response is returned by the
        /// extension via `sendResponse`, not by the executor). This is a read-mostly presentation
        /// path on an engine whose holdings were already seeded through `lifecycle`; the mutating
        /// issuance/seed cascade owns durable staging, so the one-shot presentation that follows on
        /// the ephemeral demo engine does not need it. NOT for mutating flows — those must go
        /// through `lifecycle` so their checkpoints are staged and committed.
        func drivePresentationEvent(_ eventJson: String) -> String {
            engine.handleEventJson(eventJson: eventJson)
        }

        func agentMandatesJSON() -> String { engine.agentMandatesJson() }
        func transactionLogJSON() -> String { engine.transactionLogJson() }
        func transactionReportJSON() -> String { engine.transactionReportJson() }
        func exportJSON() -> String { engine.exportJson() }
        func attestationCatalogueJSON() -> String { engine.attestationCatalogueJson() }
        func durableResumeEffectsJSON() throws -> String {
            try lifecycle.restoredEffectsJSON()
        }
    }

    /// Process-local CAS store used only by the demo/test runtime above. It exercises the exact
    /// coordinator sequencing without pretending that fresh demo keys provide durable identity.
    private final class DemoEphemeralDurableStateStore: DurableStateStore {
        private var record: DurableStateRecord?
        private var boundContext: DurableStateContext?

        func load(context: DurableStateContext) throws -> DurableStateLoadResult {
            if let boundContext, boundContext != context {
                throw DurableStateStoreError.contextMismatch
            }
            boundContext = context
            return record.map(DurableStateLoadResult.record) ?? .empty
        }

        func commit(
            expectedGeneration: UInt64,
            nextGeneration: UInt64,
            plaintext: Data,
            context: DurableStateContext
        ) throws -> DurableStateRecord {
            if let boundContext, boundContext != context {
                throw DurableStateStoreError.contextMismatch
            }
            boundContext = context
            let actualGeneration = record?.generation ?? 0
            guard actualGeneration == expectedGeneration else {
                throw DurableStateStoreError.generationConflict(
                    expected: expectedGeneration,
                    actual: actualGeneration)
            }
            let successor = expectedGeneration.addingReportingOverflow(1)
            guard !successor.overflow, nextGeneration == successor.partialValue else {
                throw DurableStateStoreError.invalidGenerationTransition(
                    expected: expectedGeneration,
                    next: nextGeneration)
            }
            let committed = DurableStateRecord(
                generation: nextGeneration,
                plaintext: plaintext)
            record = committed
            return committed
        }
    }
#endif
