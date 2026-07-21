import CryptoKit
import Foundation

/// Live, independently obtained environment that must be installed in a fresh Core before a
/// durable checkpoint can be authenticated. Its description is intentionally redacted because the
/// signed trust/WUA inputs should not be copied into logs even though they contain no private key.
public struct CoreDurableEnvironment: Sendable, CustomStringConvertible,
    CustomDebugStringConvertible
{
    public let clockEpoch: Int64
    public let signedTrustList: Data
    public let operatorPublicKey: Data
    public let devicePublicKey: Data
    public let wuaJwt: Data
    public let wuaProviderPublicKey: Data

    public init(
        clockEpoch: Int64,
        signedTrustList: Data,
        operatorPublicKey: Data,
        devicePublicKey: Data,
        wuaJwt: Data,
        wuaProviderPublicKey: Data
    ) {
        self.clockEpoch = clockEpoch
        self.signedTrustList = signedTrustList
        self.operatorPublicKey = operatorPublicKey
        self.devicePublicKey = devicePublicKey
        self.wuaJwt = wuaJwt
        self.wuaProviderPublicKey = wuaProviderPublicKey
    }

    public var description: String { "CoreDurableEnvironment(redacted)" }
    public var debugDescription: String { description }
}

/// Native mirror of the typed UniFFI checkpoint record.
public struct CoreDurableCheckpoint: Equatable, Sendable, CustomStringConvertible,
    CustomDebugStringConvertible
{
    public let generation: UInt64
    public let bytes: Data

    public init(generation: UInt64, bytes: Data) {
        self.generation = generation
        self.bytes = bytes
    }

    public var description: String { "CoreDurableCheckpoint(redacted)" }
    public var debugDescription: String { description }
}

/// Extended Core contract required by the durable coordinator. The real implementation is an
/// adapter over generated UniFFI methods; tests use a pure in-process implementation.
public protocol DurableWalletEngineDriving: WalletEngineDriving {
    func prepareForDurableRestore(environment: CoreDurableEnvironment) throws
    func makeDurableCheckpoint(generation: UInt64) throws -> CoreDurableCheckpoint
    func restoreDurableCheckpointRecord(_ checkpoint: CoreDurableCheckpoint) throws
}

/// Retry seam consumed by `EffectExecutor`. The exact event must match the blocked transition;
/// implementations commit the already-computed checkpoint and return its already-computed effects.
public protocol DurableLifecycleRetrying: AnyObject {
    func retryPendingEvent(eventJson: String) throws -> String
}

/// Stable coordinator failures. No case carries an underlying error, event, effect, identifier or
/// checkpoint; callers may log the case without leaking wallet material.
public enum DurableLifecycleError: Error, Equatable, Sendable {
    case invalidIdentity
    case alreadyBootstrapped
    case bootstrapInProgress
    case environmentPreparationFailed
    case storageLoadFailed
    case checkpointRestoreFailed
    case notBootstrapped
    case generationOverflow
    case coreInvocationFailed
    case malformedCoreOutput
    case checkpointExportFailed
    case checkpointGenerationMismatch
    case checkpointTooLarge
    case storageCommitFailed
    case persistenceDiverged
    case commitPending
    case noPendingCommit
    case retryEventMismatch
    case lifecycleFailed
}

extension DurableLifecycleError: LocalizedError {
    public var errorDescription: String? {
        switch self {
        case .invalidIdentity: return "durable_lifecycle_invalid_identity"
        case .alreadyBootstrapped: return "durable_lifecycle_already_bootstrapped"
        case .bootstrapInProgress: return "durable_lifecycle_bootstrap_in_progress"
        case .environmentPreparationFailed: return "durable_environment_preparation_failed"
        case .storageLoadFailed: return "durable_storage_load_failed"
        case .checkpointRestoreFailed: return "durable_checkpoint_restore_failed"
        case .notBootstrapped: return "durable_lifecycle_not_bootstrapped"
        case .generationOverflow: return "durable_generation_overflow"
        case .coreInvocationFailed: return "durable_core_invocation_failed"
        case .malformedCoreOutput: return "durable_core_output_malformed"
        case .checkpointExportFailed: return "durable_checkpoint_export_failed"
        case .checkpointGenerationMismatch: return "durable_checkpoint_generation_mismatch"
        case .checkpointTooLarge: return "durable_checkpoint_too_large"
        case .storageCommitFailed: return "durable_storage_commit_failed"
        case .persistenceDiverged: return "durable_storage_generation_diverged"
        case .commitPending: return "durable_commit_pending"
        case .noPendingCommit: return "durable_no_pending_commit"
        case .retryEventMismatch: return "durable_retry_event_mismatch"
        case .lifecycleFailed: return "durable_lifecycle_failed"
        }
    }
}

/// Builds the same fixed-size, non-secret platform-store binding on iOS and Android.
///
/// The app identifier, wallet profile/client ID, checkpoint schema and device-key reference are
/// length-delimited before SHA-256. The platform store authenticates the resulting digest as AEAD
/// associated data and in its generation anchor.
public enum DurableLifecycleContextFactory {
    private static let maximumIdentityBytes = 1_024
    private static let domain = Data("EUW-LIFECYCLE-CONTEXT-V1".utf8)

    public static func make(
        applicationIdentifier: String,
        walletClientId: String,
        deviceKeyReference: String
    ) throws -> DurableStateContext {
        let fields = [applicationIdentifier, walletClientId, deviceKeyReference].map {
            Data($0.utf8)
        }
        guard fields.allSatisfy({ !$0.isEmpty && $0.count <= maximumIdentityBytes }) else {
            throw DurableLifecycleError.invalidIdentity
        }
        var canonical = domain
        appendUInt32(DurableStateContext.currentSchemaVersion, to: &canonical)
        for field in fields {
            appendUInt32(UInt32(field.count), to: &canonical)
            canonical.append(field)
        }
        return try DurableStateContext(binding: Data(SHA256.hash(data: canonical)))
    }

    private static func appendUInt32(_ value: UInt32, to data: inout Data) {
        var bigEndian = value.bigEndian
        Swift.withUnsafeBytes(of: &bigEndian) { data.append(contentsOf: $0) }
    }
}

/// Sans-I/O lifecycle gate between `EffectExecutor`, Core and the encrypted platform store.
///
/// Each successful Core event is exported at `generation + 1` and compare-and-swap committed before
/// its effect JSON is returned. A commit failure retains the exact event/checkpoint/effect batch in
/// memory; retries never invoke Core again. On process death that uncommitted batch disappears and a
/// new coordinator restores only the last anchored checkpoint. Protocol sessions and pending effects
/// are intentionally not durable, so this seam provides at-most-once release after persistence—not
/// a durable outbox or exactly-once external delivery. Production host composition remains required.
public final class DurableLifecycleCoordinator: WalletEngineDriving, DurableLifecycleRetrying,
    CustomDebugStringConvertible
{
    public static let maximumCheckpointBytes = AppleDurableStateStore.maximumPlaintextBytes

    private struct PendingExport {
        let expectedGeneration: UInt64
        let nextGeneration: UInt64
        let eventJson: String
        let effectsJson: String
    }

    private struct PendingCommit {
        let export: PendingExport
        let checkpoint: CoreDurableCheckpoint
    }

    private enum State {
        case uninitialized
        case bootstrapping
        case ready(UInt64)
        case pendingExport(PendingExport)
        case pendingCommit(PendingCommit)
        case failed
    }

    private let engine: any DurableWalletEngineDriving
    private let store: any DurableStateStore
    private let context: DurableStateContext
    private let lock = NSLock()
    private var state: State = .uninitialized

    public init(
        engine: any DurableWalletEngineDriving,
        store: any DurableStateStore,
        context: DurableStateContext
    ) {
        self.engine = engine
        self.store = store
        self.context = context
    }

    public var debugDescription: String {
        lock.lock()
        defer { lock.unlock() }
        return "DurableLifecycleCoordinator(state: \(stateName))"
    }

    public var hasPendingCommit: Bool {
        lock.lock()
        defer { lock.unlock() }
        switch state {
        case .pendingExport, .pendingCommit: return true
        default: return false
        }
    }

    /// Load the live environment before reading and restoring the authenticated store record.
    /// A failed bootstrap poisons this coordinator because a partially failing external adapter
    /// cannot be proven reusable; construct a fresh engine/coordinator to retry.
    public func bootstrap(environment: CoreDurableEnvironment) throws {
        lock.lock()
        defer { lock.unlock() }
        switch state {
        case .uninitialized: state = .bootstrapping
        case .bootstrapping: throw DurableLifecycleError.bootstrapInProgress
        default: throw DurableLifecycleError.alreadyBootstrapped
        }

        do {
            try engine.prepareForDurableRestore(environment: environment)
        } catch {
            state = .failed
            throw DurableLifecycleError.environmentPreparationFailed
        }

        let loaded: DurableStateLoadResult
        do {
            loaded = try store.load(context: context)
        } catch {
            state = .failed
            throw DurableLifecycleError.storageLoadFailed
        }

        switch loaded {
        case .empty:
            state = .ready(0)
        case .record(let record):
            guard record.generation > 0,
                record.plaintext.count <= Self.maximumCheckpointBytes
            else {
                state = .failed
                throw DurableLifecycleError.checkpointRestoreFailed
            }
            do {
                try engine.restoreDurableCheckpointRecord(
                    CoreDurableCheckpoint(
                        generation: record.generation,
                        bytes: record.plaintext))
            } catch {
                state = .failed
                throw DurableLifecycleError.checkpointRestoreFailed
            }
            state = .ready(record.generation)
        }
    }

    /// `WalletEngineDriving` entry point used transparently by the existing effect executor.
    public func handleEventJson(eventJson: String) throws -> String {
        lock.lock()
        defer { lock.unlock() }
        let generation: UInt64
        switch state {
        case .ready(let current): generation = current
        case .uninitialized, .bootstrapping: throw DurableLifecycleError.notBootstrapped
        case .pendingExport, .pendingCommit: throw DurableLifecycleError.commitPending
        case .failed: throw DurableLifecycleError.lifecycleFailed
        }

        let next = generation.addingReportingOverflow(1)
        guard !next.overflow else { throw DurableLifecycleError.generationOverflow }

        let output: String
        do {
            output = try engine.handleEventJson(eventJson: eventJson)
        } catch {
            state = .failed
            throw DurableLifecycleError.coreInvocationFailed
        }
        switch Self.classifyCoreOutput(output) {
        case .errorEnvelope:
            return output
        case .malformed:
            state = .failed
            throw DurableLifecycleError.malformedCoreOutput
        case .effects:
            break
        }

        let pending = PendingExport(
            expectedGeneration: generation,
            nextGeneration: next.partialValue,
            eventJson: eventJson,
            effectsJson: output)
        state = .pendingExport(pending)
        let checkpoint = try exportPending(pending)
        let commit = PendingCommit(export: pending, checkpoint: checkpoint)
        state = .pendingCommit(commit)
        return try commitPending(commit, reconcileAmbiguousFailure: false)
    }

    /// Retry the exact blocked event. Core is never called; only export (if it previously failed)
    /// and the exact compare-and-swap store commit are retried.
    public func retryPendingEvent(eventJson: String) throws -> String {
        lock.lock()
        defer { lock.unlock() }
        switch state {
        case .pendingExport(let pending):
            guard pending.eventJson == eventJson else {
                throw DurableLifecycleError.retryEventMismatch
            }
            let checkpoint = try exportPending(pending)
            let commit = PendingCommit(export: pending, checkpoint: checkpoint)
            state = .pendingCommit(commit)
            return try commitPending(commit, reconcileAmbiguousFailure: true)
        case .pendingCommit(let commit):
            guard commit.export.eventJson == eventJson else {
                throw DurableLifecycleError.retryEventMismatch
            }
            return try commitPending(commit, reconcileAmbiguousFailure: true)
        case .uninitialized, .bootstrapping: throw DurableLifecycleError.notBootstrapped
        case .ready: throw DurableLifecycleError.noPendingCommit
        case .failed: throw DurableLifecycleError.lifecycleFailed
        }
    }

    private func exportPending(_ pending: PendingExport) throws -> CoreDurableCheckpoint {
        let checkpoint: CoreDurableCheckpoint
        do {
            checkpoint = try engine.makeDurableCheckpoint(generation: pending.nextGeneration)
        } catch {
            state = .pendingExport(pending)
            throw DurableLifecycleError.checkpointExportFailed
        }
        guard checkpoint.generation == pending.nextGeneration else {
            state = .pendingExport(pending)
            throw DurableLifecycleError.checkpointGenerationMismatch
        }
        guard !checkpoint.bytes.isEmpty,
            checkpoint.bytes.count <= Self.maximumCheckpointBytes
        else {
            state = .pendingExport(pending)
            throw DurableLifecycleError.checkpointTooLarge
        }
        return checkpoint
    }

    private func commitPending(
        _ pending: PendingCommit,
        reconcileAmbiguousFailure: Bool
    ) throws -> String {
        do {
            let committed = try store.commit(
                expectedGeneration: pending.export.expectedGeneration,
                nextGeneration: pending.export.nextGeneration,
                plaintext: pending.checkpoint.bytes,
                context: context)
            guard committed.generation == pending.export.nextGeneration,
                committed.plaintext == pending.checkpoint.bytes
            else {
                state = .pendingCommit(pending)
                throw DurableLifecycleError.persistenceDiverged
            }
            state = .ready(pending.export.nextGeneration)
            return pending.export.effectsJson
        } catch let error as DurableLifecycleError {
            throw error
        } catch {
            state = .pendingCommit(pending)
            if reconcileAmbiguousFailure {
                switch reconcileStoreRecord(pending) {
                case .committed:
                    state = .ready(pending.export.nextGeneration)
                    return pending.export.effectsJson
                case .diverged:
                    throw DurableLifecycleError.persistenceDiverged
                case .unchanged, .unavailable:
                    break
                }
            }
            throw DurableLifecycleError.storageCommitFailed
        }
    }

    private enum Reconciliation { case committed, unchanged, diverged, unavailable }

    private func reconcileStoreRecord(_ pending: PendingCommit) -> Reconciliation {
        guard let loaded = try? store.load(context: context) else { return .unavailable }
        switch loaded {
        case .empty:
            return pending.export.expectedGeneration == 0 ? .unchanged : .diverged
        case .record(let record):
            if record.generation == pending.export.nextGeneration,
                record.plaintext == pending.checkpoint.bytes
            {
                return .committed
            }
            if record.generation == pending.export.expectedGeneration {
                return .unchanged
            }
            return .diverged
        }
    }

    private enum CoreOutputKind { case effects, errorEnvelope, malformed }

    private static func classifyCoreOutput(_ output: String) -> CoreOutputKind {
        guard let value = try? JSONSerialization.jsonObject(with: Data(output.utf8)) else {
            return .malformed
        }
        if value is [Any] { return .effects }
        if let object = value as? [String: Any], object.count == 1,
            object["error"] is String
        {
            return .errorEnvelope
        }
        return .malformed
    }

    private var stateName: String {
        switch state {
        case .uninitialized: return "uninitialized"
        case .bootstrapping: return "bootstrapping"
        case .ready: return "ready"
        case .pendingExport: return "pending_export"
        case .pendingCommit: return "pending_commit"
        case .failed: return "failed"
        }
    }
}
