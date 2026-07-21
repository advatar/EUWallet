import Foundation

// Current app and executor composition keeps the generated UniFFI engine behind this file's
// adapter. They receive only the durable coordinator plus read-only projections, and an
// architecture test guards those sources against known raw mutators. The generated binding itself
// remains a public compatibility surface, so Android integration and stronger API isolation remain
// tracked work.
// Guarded so the package still builds on hosts without the xcframework linked.
#if canImport(wallet_coreFFI)
    import wallet_coreFFI

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
        func transactionLogJSON() -> String { engine.transactionLogJson() }
        func transactionReportJSON() -> String { engine.transactionReportJson() }
        func exportJSON() -> String { engine.exportJson() }
        func attestationCatalogueJSON() -> String { engine.attestationCatalogueJson() }
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
