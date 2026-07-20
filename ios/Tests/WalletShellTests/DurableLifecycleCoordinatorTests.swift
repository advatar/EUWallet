import Foundation
import XCTest

@testable import WalletShell

private enum LifecycleTestFailure: Error { case injected, conflict }

private final class LifecycleTrace {
    var entries: [String] = []
}

private final class ScriptedDurableEngine: DurableWalletEngineDriving {
    let trace: LifecycleTrace
    var response = #"[{"type":"render","screen":{"screen":"loading"}}]"#
    var checkpointBytes = Data([0xa1, 0x01, 0x01])
    var exportedGenerationOverride: UInt64?
    var exportFailures = 0
    var preparationFails = false
    var restoreFails = false
    private(set) var handledEvents: [String] = []
    private(set) var exportedGenerations: [UInt64] = []
    private(set) var restored: [CoreDurableCheckpoint] = []

    init(trace: LifecycleTrace = LifecycleTrace()) { self.trace = trace }

    func prepareForDurableRestore(environment: CoreDurableEnvironment) throws {
        trace.entries.append("prepare")
        if preparationFails { throw LifecycleTestFailure.injected }
    }

    func restoreDurableCheckpointRecord(_ checkpoint: CoreDurableCheckpoint) throws {
        trace.entries.append("restore")
        if restoreFails { throw LifecycleTestFailure.injected }
        restored.append(checkpoint)
    }

    func handleEventJson(eventJson: String) throws -> String {
        trace.entries.append("handle")
        handledEvents.append(eventJson)
        return response
    }

    func makeDurableCheckpoint(generation: UInt64) throws -> CoreDurableCheckpoint {
        trace.entries.append("export:\(generation)")
        exportedGenerations.append(generation)
        if exportFailures > 0 {
            exportFailures -= 1
            throw LifecycleTestFailure.injected
        }
        return CoreDurableCheckpoint(
            generation: exportedGenerationOverride ?? generation,
            bytes: checkpointBytes)
    }
}

private final class ScriptedDurableStore: DurableStateStore {
    let trace: LifecycleTrace
    var record: DurableStateRecord?
    var commitFailures = 0
    var commitThenThrow = false
    private(set) var loads = 0
    private(set) var commits: [(UInt64, UInt64, Data, DurableStateContext)] = []

    init(trace: LifecycleTrace = LifecycleTrace(), record: DurableStateRecord? = nil) {
        self.trace = trace
        self.record = record
    }

    func load(context: DurableStateContext) throws -> DurableStateLoadResult {
        trace.entries.append("load")
        loads += 1
        return record.map(DurableStateLoadResult.record) ?? .empty
    }

    func commit(
        expectedGeneration: UInt64,
        nextGeneration: UInt64,
        plaintext: Data,
        context: DurableStateContext
    ) throws -> DurableStateRecord {
        trace.entries.append("commit:\(expectedGeneration)->\(nextGeneration)")
        commits.append((expectedGeneration, nextGeneration, plaintext, context))
        let actual = record?.generation ?? 0
        guard actual == expectedGeneration else { throw LifecycleTestFailure.conflict }
        if commitFailures > 0 {
            commitFailures -= 1
            throw LifecycleTestFailure.injected
        }
        let committed = DurableStateRecord(generation: nextGeneration, plaintext: plaintext)
        record = committed
        if commitThenThrow {
            commitThenThrow = false
            throw LifecycleTestFailure.injected
        }
        return committed
    }
}

final class DurableLifecycleCoordinatorTests: XCTestCase {
    private let environment = CoreDurableEnvironment(
        clockEpoch: 1_790_000_000,
        signedTrustList: Data("trust-secret".utf8),
        operatorPublicKey: Data(repeating: 1, count: 65),
        devicePublicKey: Data(repeating: 2, count: 65),
        wuaJwt: Data("wua-secret".utf8),
        wuaProviderPublicKey: Data(repeating: 3, count: 65))

    private func context(
        application: String = "eu.advatar.wallet",
        wallet: String = "wallet.example",
        device: String = "device-key"
    ) throws -> DurableStateContext {
        try DurableLifecycleContextFactory.make(
            applicationIdentifier: application,
            walletClientId: wallet,
            deviceKeyReference: device)
    }

    private func coordinator(
        engine: ScriptedDurableEngine,
        store: ScriptedDurableStore
    ) throws -> DurableLifecycleCoordinator {
        DurableLifecycleCoordinator(engine: engine, store: store, context: try context())
    }

    func testBootstrapInstallsCurrentEnvironmentBeforeLoadAndRestore() throws {
        let trace = LifecycleTrace()
        let engine = ScriptedDurableEngine(trace: trace)
        let stored = DurableStateRecord(generation: 9, plaintext: Data([9, 9]))
        let store = ScriptedDurableStore(trace: trace, record: stored)
        let lifecycle = try coordinator(engine: engine, store: store)

        try lifecycle.bootstrap(environment: environment)

        XCTAssertEqual(trace.entries, ["prepare", "load", "restore"])
        XCTAssertEqual(
            engine.restored,
            [
                CoreDurableCheckpoint(generation: 9, bytes: Data([9, 9]))
            ])
        XCTAssertFalse(lifecycle.hasPendingCommit)
    }

    func testEveryEffectBatchIsCommittedBeforeRelease() throws {
        let trace = LifecycleTrace()
        let engine = ScriptedDurableEngine(trace: trace)
        let store = ScriptedDurableStore(trace: trace)
        let lifecycle = try coordinator(engine: engine, store: store)
        try lifecycle.bootstrap(environment: environment)

        let output = try lifecycle.handleEventJson(eventJson: #"{"type":"start"}"#)

        XCTAssertEqual(output, engine.response)
        XCTAssertEqual(
            trace.entries,
            ["prepare", "load", "handle", "export:1", "commit:0->1"])
        XCTAssertEqual(store.record?.generation, 1)
        XCTAssertEqual(store.record?.plaintext, engine.checkpointBytes)
    }

    func testCommitFailureRetainsExactBatchAndRetryNeverRehandlesEvent() throws {
        let engine = ScriptedDurableEngine()
        engine.response = #"[{"type":"sign","operationId":7,"keyRef":"device","payload":[4]}]"#
        let store = ScriptedDurableStore()
        store.commitFailures = 1
        let lifecycle = try coordinator(engine: engine, store: store)
        try lifecycle.bootstrap(environment: environment)
        let event = #"{"type":"holderApproved","secret":"do-not-log"}"#

        XCTAssertThrowsError(try lifecycle.handleEventJson(eventJson: event)) {
            XCTAssertEqual($0 as? DurableLifecycleError, .storageCommitFailed)
        }
        XCTAssertTrue(lifecycle.hasPendingCommit)
        XCTAssertEqual(engine.handledEvents, [event])
        XCTAssertThrowsError(try lifecycle.handleEventJson(eventJson: #"{"type":"other"}"#)) {
            XCTAssertEqual($0 as? DurableLifecycleError, .commitPending)
        }
        XCTAssertThrowsError(try lifecycle.retryPendingEvent(eventJson: #"{"type":"other"}"#)) {
            XCTAssertEqual($0 as? DurableLifecycleError, .retryEventMismatch)
        }

        let output = try lifecycle.retryPendingEvent(eventJson: event)
        XCTAssertEqual(output, engine.response)
        XCTAssertEqual(engine.handledEvents, [event])
        XCTAssertEqual(engine.exportedGenerations, [1])
        XCTAssertEqual(store.commits.count, 2)
        XCTAssertEqual(store.commits[0].0, store.commits[1].0)
        XCTAssertEqual(store.commits[0].1, store.commits[1].1)
        XCTAssertEqual(store.commits[0].2, store.commits[1].2)
        XCTAssertFalse(lifecycle.hasPendingCommit)
        XCTAssertThrowsError(try lifecycle.retryPendingEvent(eventJson: event)) {
            XCTAssertEqual($0 as? DurableLifecycleError, .noPendingCommit)
        }
    }

    func testAmbiguousPostCommitFailureReconcilesOnlyTheExactRecord() throws {
        let engine = ScriptedDurableEngine()
        let store = ScriptedDurableStore()
        store.commitThenThrow = true
        let lifecycle = try coordinator(engine: engine, store: store)
        try lifecycle.bootstrap(environment: environment)
        let event = #"{"type":"start"}"#

        XCTAssertThrowsError(try lifecycle.handleEventJson(eventJson: event))
        XCTAssertEqual(store.record?.generation, 1)

        let output = try lifecycle.retryPendingEvent(eventJson: event)
        XCTAssertEqual(output, engine.response)
        XCTAssertEqual(engine.handledEvents.count, 1)
        XCTAssertEqual(store.commits.count, 2)
        XCTAssertGreaterThanOrEqual(store.loads, 2)
    }

    func testStaleGenerationDivergenceNeverReleasesEffects() throws {
        let engine = ScriptedDurableEngine()
        let store = ScriptedDurableStore()
        store.commitFailures = 1
        let lifecycle = try coordinator(engine: engine, store: store)
        try lifecycle.bootstrap(environment: environment)
        let event = #"{"type":"start"}"#
        XCTAssertThrowsError(try lifecycle.handleEventJson(eventJson: event))

        store.record = DurableStateRecord(generation: 8, plaintext: Data([8]))
        XCTAssertThrowsError(try lifecycle.retryPendingEvent(eventJson: event)) {
            XCTAssertEqual($0 as? DurableLifecycleError, .persistenceDiverged)
        }
        XCTAssertTrue(lifecycle.hasPendingCommit)
        XCTAssertEqual(engine.handledEvents.count, 1)
    }

    func testCheckpointExportFailureRetriesWithoutRehandling() throws {
        let engine = ScriptedDurableEngine()
        engine.exportFailures = 1
        let store = ScriptedDurableStore()
        let lifecycle = try coordinator(engine: engine, store: store)
        try lifecycle.bootstrap(environment: environment)
        let event = #"{"type":"start"}"#

        XCTAssertThrowsError(try lifecycle.handleEventJson(eventJson: event)) {
            XCTAssertEqual($0 as? DurableLifecycleError, .checkpointExportFailed)
        }
        XCTAssertEqual(store.commits.count, 0)
        let output = try lifecycle.retryPendingEvent(eventJson: event)
        XCTAssertEqual(output, engine.response)
        XCTAssertEqual(engine.handledEvents.count, 1)
        XCTAssertEqual(engine.exportedGenerations, [1, 1])
    }

    func testProcessDeathRestoresOnlyLastCommittedGenerationAndDropsPendingEffects() throws {
        let sharedStore = ScriptedDurableStore()
        sharedStore.commitFailures = 1
        let oldEngine = ScriptedDurableEngine()
        oldEngine.response =
            #"[{"type":"sign","operationId":7,"keyRef":"device","payload":[115,101,99,114,101,116]}]"#
        var oldLifecycle: DurableLifecycleCoordinator? = try coordinator(
            engine: oldEngine, store: sharedStore)
        try oldLifecycle?.bootstrap(environment: environment)
        XCTAssertThrowsError(
            try oldLifecycle?.handleEventJson(eventJson: #"{"type":"start"}"#))
        XCTAssertTrue(oldLifecycle?.hasPendingCommit == true)

        // Simulated process death: the in-memory pending checkpoint/effects disappear.
        oldLifecycle = nil
        let restartedEngine = ScriptedDurableEngine()
        let restarted = try coordinator(engine: restartedEngine, store: sharedStore)
        try restarted.bootstrap(environment: environment)

        XCTAssertTrue(restartedEngine.restored.isEmpty)
        XCTAssertFalse(restarted.hasPendingCommit)
        XCTAssertThrowsError(try restarted.retryPendingEvent(eventJson: #"{"type":"start"}"#)) {
            XCTAssertEqual($0 as? DurableLifecycleError, .noPendingCommit)
        }
    }

    func testCoreErrorEnvelopeDoesNotAdvanceStoreGeneration() throws {
        let engine = ScriptedDurableEngine()
        engine.response = #"{"error":"stale operation"}"#
        let store = ScriptedDurableStore()
        let lifecycle = try coordinator(engine: engine, store: store)
        try lifecycle.bootstrap(environment: environment)

        XCTAssertEqual(
            try lifecycle.handleEventJson(eventJson: #"{"type":"stale"}"#),
            engine.response)
        XCTAssertTrue(engine.exportedGenerations.isEmpty)
        XCTAssertTrue(store.commits.isEmpty)
    }

    func testMalformedIndividualEffectIsRejectedBeforeCheckpointCommit() throws {
        let engine = ScriptedDurableEngine()
        engine.response = #"[{"type":"unknownNativeEffect","operationId":7}]"#
        let store = ScriptedDurableStore()
        let lifecycle = try coordinator(engine: engine, store: store)
        try lifecycle.bootstrap(environment: environment)

        XCTAssertThrowsError(
            try lifecycle.handleEventJson(eventJson: #"{"type":"start"}"#)
        ) {
            XCTAssertEqual($0 as? DurableLifecycleError, .malformedCoreOutput)
        }
        XCTAssertTrue(engine.exportedGenerations.isEmpty)
        XCTAssertTrue(store.commits.isEmpty)
        XCTAssertFalse(lifecycle.hasPendingCommit)
    }

    func testPlatformContextBindsAppSchemaWalletAndDeviceDeterministically() throws {
        let original = try context()
        XCTAssertEqual(original.binding.count, 32)
        XCTAssertEqual(
            original.binding.map { String(format: "%02x", $0) }.joined(),
            "b959e1adc47d57a0c10b4b78f5c7f29ed3a0b47c52aa4c27879a12c210c669ee")
        XCTAssertEqual(original, try context())
        XCTAssertNotEqual(original, try context(application: "eu.advatar.wallet.beta"))
        XCTAssertNotEqual(original, try context(wallet: "wallet.other"))
        XCTAssertNotEqual(original, try context(device: "device-key-2"))
        XCTAssertThrowsError(try context(application: "")) {
            XCTAssertEqual($0 as? DurableLifecycleError, .invalidIdentity)
        }
    }

    func testExecutorRejectsSecondEventWithoutOverwritingPendingRetry() async throws {
        let engine = ScriptedDurableEngine()
        let store = ScriptedDurableStore()
        store.commitFailures = 1
        let lifecycle = try coordinator(engine: engine, store: store)
        try lifecycle.bootstrap(environment: environment)
        var renders = 0
        let executor = EffectExecutor(
            engine: lifecycle,
            signer: StubSigner(),
            http: StubHttpClient(),
            storage: InMemoryStorage(),
            trust: StubTrustResolver(),
            render: { _, _, _ in renders += 1 })
        let firstEvent = #"{"type":"start"}"#
        let secondEvent = #"{"type":"other"}"#

        do {
            _ = try await executor.send(eventJson: firstEvent)
            XCTFail("commit failure must withhold effects")
        } catch {
            XCTAssertEqual(error as? DurableLifecycleError, .storageCommitFailed)
        }
        do {
            _ = try await executor.send(eventJson: secondEvent)
            XCTFail("a second event must not overwrite the exact pending retry")
        } catch {
            XCTAssertEqual(error as? DurableLifecycleError, .commitPending)
        }
        XCTAssertEqual(renders, 0)
        XCTAssertEqual(engine.handledEvents, [firstEvent])
        XCTAssertEqual(store.commits.count, 1)

        let outcome = try await executor.retryPendingDurableCommit()
        XCTAssertEqual(outcome, .awaitingInput)
        XCTAssertEqual(renders, 1)
        XCTAssertEqual(engine.handledEvents, [firstEvent])
        XCTAssertEqual(store.commits.count, 2)
        do {
            _ = try await executor.retryPendingDurableCommit()
            XCTFail("an already released batch must not be released again")
        } catch {
            XCTAssertEqual(error as? EffectExecutorError, .noPendingDurableCommit)
        }
        XCTAssertEqual(renders, 1)
    }

    func testExecutorRetainsExactEventWheneverCoordinatorRemainsPending() async throws {
        let engine = ScriptedDurableEngine()
        engine.exportedGenerationOverride = 9
        let store = ScriptedDurableStore()
        let lifecycle = try coordinator(engine: engine, store: store)
        try lifecycle.bootstrap(environment: environment)
        var renders = 0
        let executor = EffectExecutor(
            engine: lifecycle,
            signer: StubSigner(),
            http: StubHttpClient(),
            storage: InMemoryStorage(),
            trust: StubTrustResolver(),
            render: { _, _, _ in renders += 1 })
        let firstEvent = #"{"type":"start"}"#

        do {
            _ = try await executor.send(eventJson: firstEvent)
            XCTFail("generation mismatch must retain the original transition")
        } catch {
            XCTAssertEqual(error as? DurableLifecycleError, .checkpointGenerationMismatch)
        }
        let replacementExecutor = EffectExecutor(
            engine: lifecycle,
            signer: StubSigner(),
            http: StubHttpClient(),
            storage: InMemoryStorage(),
            trust: StubTrustResolver(),
            render: { _, _, _ in XCTFail("replacement executor must not render") })
        do {
            _ = try await replacementExecutor.send(eventJson: #"{"type":"other"}"#)
            XCTFail("a replacement executor must not adopt a new event while Core retains one")
        } catch {
            XCTAssertEqual(error as? DurableLifecycleError, .commitPending)
        }
        XCTAssertEqual(engine.handledEvents, [firstEvent])
        XCTAssertTrue(lifecycle.hasPendingCommit)
        XCTAssertTrue(store.commits.isEmpty)

        engine.exportedGenerationOverride = nil
        let outcome = try await executor.retryPendingDurableCommit()
        XCTAssertEqual(outcome, .awaitingInput)
        XCTAssertEqual(engine.handledEvents, [firstEvent])
        XCTAssertEqual(engine.exportedGenerations, [1, 1])
        XCTAssertEqual(store.commits.count, 1)
        XCTAssertEqual(renders, 1)
    }

    func testDiagnosticsRedactEnvironmentCheckpointEventAndEffects() throws {
        let secret = "do-not-log-holder-secret"
        let engine = ScriptedDurableEngine()
        engine.response =
            #"[{"type":"render","screen":{"screen":"loading"},"secret":"do-not-log-holder-secret"}]"#
        let store = ScriptedDurableStore()
        store.commitFailures = 1
        let lifecycle = try coordinator(engine: engine, store: store)
        try lifecycle.bootstrap(environment: environment)
        XCTAssertThrowsError(
            try lifecycle.handleEventJson(
                eventJson: #"{"type":"start","secret":"do-not-log-holder-secret"}"#))

        let values = [
            String(describing: environment),
            String(reflecting: environment),
            String(
                describing: CoreDurableCheckpoint(
                    generation: 1, bytes: Data(secret.utf8))),
            String(
                reflecting: CoreDurableCheckpoint(
                    generation: 1, bytes: Data(secret.utf8))),
            String(reflecting: lifecycle),
            DurableLifecycleError.storageCommitFailed.localizedDescription,
        ]
        XCTAssertTrue(values.allSatisfy { !$0.contains(secret) })
        XCTAssertTrue(values.allSatisfy { !$0.contains("trust-secret") })
        XCTAssertTrue(values.allSatisfy { !$0.contains("wua-secret") })
    }
}
