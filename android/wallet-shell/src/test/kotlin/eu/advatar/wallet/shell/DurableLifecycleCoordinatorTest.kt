package eu.advatar.wallet.shell

import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Test

private class LifecycleInjectedFailure : RuntimeException()

private class AndroidLifecycleTrace {
    val entries = mutableListOf<String>()
}

private class AndroidScriptedDurableEngine(
    val trace: AndroidLifecycleTrace = AndroidLifecycleTrace(),
) : DurableWalletEngineDriving {
    var response = """[{"type":"render","screen":{"screen":"loading"}}]"""
    var checkpointBytes = byteArrayOf(0xa1.toByte(), 1, 1)
    var exportedGenerationOverride: Long? = null
    var exportFailures = 0
    var preparationFails = false
    var restoreFails = false
    val handledEvents = mutableListOf<String>()
    val exportedGenerations = mutableListOf<Long>()
    val restored = mutableListOf<CoreDurableCheckpoint>()

    override fun prepareForDurableRestore(environment: CoreDurableEnvironment) {
        trace.entries += "prepare"
        if (preparationFails) throw LifecycleInjectedFailure()
    }

    override fun restoreDurableCheckpointRecord(checkpoint: CoreDurableCheckpoint) {
        trace.entries += "restore"
        if (restoreFails) throw LifecycleInjectedFailure()
        restored += checkpoint
    }

    override fun handleEventJson(eventJson: String): String {
        trace.entries += "handle"
        handledEvents += eventJson
        return response
    }

    override fun makeDurableCheckpoint(generation: Long): CoreDurableCheckpoint {
        trace.entries += "export:$generation"
        exportedGenerations += generation
        if (exportFailures > 0) {
            exportFailures -= 1
            throw LifecycleInjectedFailure()
        }
        return CoreDurableCheckpoint(
            exportedGenerationOverride ?: generation,
            checkpointBytes,
        )
    }
}

private class AndroidScriptedDurableStore(
    val trace: AndroidLifecycleTrace = AndroidLifecycleTrace(),
    var record: DurableStateRecord? = null,
) : DurableStateStore {
    var commitFailures = 0
    var commitThenThrow = false
    var loads = 0
    val commits = mutableListOf<CommitAttempt>()

    class CommitAttempt(
        val expected: Long,
        val next: Long,
        val bytes: ByteArray,
        val context: DurableStateContext,
    )

    override fun load(context: DurableStateContext): DurableStateLoadResult {
        trace.entries += "load"
        loads += 1
        return record?.let(DurableStateLoadResult::Record) ?: DurableStateLoadResult.Empty
    }

    override fun commit(
        expectedGeneration: Long,
        nextGeneration: Long,
        plaintext: ByteArray,
        context: DurableStateContext,
    ): DurableStateRecord {
        trace.entries += "commit:$expectedGeneration->$nextGeneration"
        commits += CommitAttempt(expectedGeneration, nextGeneration, plaintext.copyOf(), context)
        val actual = record?.generation ?: 0
        if (actual != expectedGeneration) throw LifecycleInjectedFailure()
        if (commitFailures > 0) {
            commitFailures -= 1
            throw LifecycleInjectedFailure()
        }
        val committed = DurableStateRecord(nextGeneration, plaintext)
        record = committed
        if (commitThenThrow) {
            commitThenThrow = false
            throw LifecycleInjectedFailure()
        }
        return committed
    }
}

class DurableLifecycleCoordinatorTest {
    private val environment = CoreDurableEnvironment(
        clockEpoch = 1_790_000_000,
        signedTrustList = "trust-secret".encodeToByteArray(),
        operatorPublicKey = ByteArray(65) { 1 },
        devicePublicKey = ByteArray(65) { 2 },
        wuaJwt = "wua-secret".encodeToByteArray(),
        wuaProviderPublicKey = ByteArray(65) { 3 },
    )

    private fun context(
        application: String = "eu.advatar.wallet",
        wallet: String = "wallet.example",
        device: String = "device-key",
    ): DurableStateContext = DurableLifecycleContextFactory.make(application, wallet, device)

    private fun coordinator(
        engine: AndroidScriptedDurableEngine,
        store: AndroidScriptedDurableStore,
    ) = DurableLifecycleCoordinator(engine, store, context())

    @Test
    fun bootstrapInstallsEnvironmentBeforeLoadAndRestore() {
        val trace = AndroidLifecycleTrace()
        val engine = AndroidScriptedDurableEngine(trace)
        val store = AndroidScriptedDurableStore(
            trace,
            DurableStateRecord(9, byteArrayOf(9, 9)),
        )
        val lifecycle = coordinator(engine, store)

        lifecycle.bootstrap(environment)

        assertEquals(listOf("prepare", "load", "restore"), trace.entries)
        assertEquals(1, engine.restored.size)
        assertEquals(9, engine.restored.single().generation)
        assertArrayEquals(byteArrayOf(9, 9), engine.restored.single().bytes)
        assertFalse(lifecycle.hasPendingCommit)
    }

    @Test
    fun everyEffectBatchIsCommittedBeforeRelease() {
        val trace = AndroidLifecycleTrace()
        val engine = AndroidScriptedDurableEngine(trace)
        val store = AndroidScriptedDurableStore(trace)
        val lifecycle = coordinator(engine, store)
        lifecycle.bootstrap(environment)

        val output = lifecycle.handleEventJson("""{"type":"start"}""")

        assertEquals(engine.response, output)
        assertEquals(
            listOf("prepare", "load", "handle", "export:1", "commit:0->1"),
            trace.entries,
        )
        assertEquals(1L, store.record?.generation)
        assertArrayEquals(engine.checkpointBytes, store.record?.plaintext)
    }

    @Test
    fun commitFailureRetainsExactBatchAndRetryNeverRehandles() {
        val engine = AndroidScriptedDurableEngine()
        engine.response =
            """[{"type":"sign","operationId":7,"keyRef":"device","payload":[4]}]"""
        val store = AndroidScriptedDurableStore()
        store.commitFailures = 1
        val lifecycle = coordinator(engine, store)
        lifecycle.bootstrap(environment)
        val event = """{"type":"approved","secret":"do-not-log"}"""

        assertLifecycleError(DurableLifecycleErrorCode.STORAGE_COMMIT_FAILED) {
            lifecycle.handleEventJson(event)
        }
        assertTrue(lifecycle.hasPendingCommit)
        assertLifecycleError(DurableLifecycleErrorCode.COMMIT_PENDING) {
            lifecycle.handleEventJson("""{"type":"other"}""")
        }
        assertLifecycleError(DurableLifecycleErrorCode.RETRY_EVENT_MISMATCH) {
            lifecycle.retryPendingEvent("""{"type":"other"}""")
        }

        assertEquals(engine.response, lifecycle.retryPendingEvent(event))
        assertEquals(listOf(event), engine.handledEvents)
        assertEquals(listOf(1L), engine.exportedGenerations)
        assertEquals(2, store.commits.size)
        assertEquals(store.commits[0].expected, store.commits[1].expected)
        assertEquals(store.commits[0].next, store.commits[1].next)
        assertArrayEquals(store.commits[0].bytes, store.commits[1].bytes)
        assertLifecycleError(DurableLifecycleErrorCode.NO_PENDING_COMMIT) {
            lifecycle.retryPendingEvent(event)
        }
    }

    @Test
    fun ambiguousPostCommitFailureReconcilesOnlyExactRecord() {
        val engine = AndroidScriptedDurableEngine()
        val store = AndroidScriptedDurableStore()
        store.commitThenThrow = true
        val lifecycle = coordinator(engine, store)
        lifecycle.bootstrap(environment)
        val event = """{"type":"start"}"""

        assertLifecycleError(DurableLifecycleErrorCode.STORAGE_COMMIT_FAILED) {
            lifecycle.handleEventJson(event)
        }
        assertEquals(1L, store.record?.generation)
        assertEquals(engine.response, lifecycle.retryPendingEvent(event))
        assertEquals(1, engine.handledEvents.size)
        assertEquals(2, store.commits.size)
        assertTrue(store.loads >= 2)
    }

    @Test
    fun staleGenerationDivergenceNeverReleasesEffects() {
        val engine = AndroidScriptedDurableEngine()
        val store = AndroidScriptedDurableStore()
        store.commitFailures = 1
        val lifecycle = coordinator(engine, store)
        lifecycle.bootstrap(environment)
        val event = """{"type":"start"}"""
        assertThrows(DurableLifecycleException::class.java) {
            lifecycle.handleEventJson(event)
        }

        store.record = DurableStateRecord(8, byteArrayOf(8))
        assertLifecycleError(DurableLifecycleErrorCode.PERSISTENCE_DIVERGED) {
            lifecycle.retryPendingEvent(event)
        }
        assertTrue(lifecycle.hasPendingCommit)
        assertEquals(1, engine.handledEvents.size)
    }

    @Test
    fun checkpointExportFailureRetriesWithoutRehandling() {
        val engine = AndroidScriptedDurableEngine()
        engine.exportFailures = 1
        val store = AndroidScriptedDurableStore()
        val lifecycle = coordinator(engine, store)
        lifecycle.bootstrap(environment)
        val event = """{"type":"start"}"""

        assertLifecycleError(DurableLifecycleErrorCode.CHECKPOINT_EXPORT_FAILED) {
            lifecycle.handleEventJson(event)
        }
        assertTrue(store.commits.isEmpty())
        assertEquals(engine.response, lifecycle.retryPendingEvent(event))
        assertEquals(1, engine.handledEvents.size)
        assertEquals(listOf(1L, 1L), engine.exportedGenerations)
    }

    @Test
    fun processDeathDropsUncommittedEffectsAndRestoresOnlyAnchoredState() {
        val sharedStore = AndroidScriptedDurableStore()
        sharedStore.commitFailures = 1
        val oldEngine = AndroidScriptedDurableEngine()
        oldEngine.response =
            """[{"type":"sign","operationId":7,"keyRef":"device","payload":[115,101,99,114,101,116]}]"""
        var oldLifecycle: DurableLifecycleCoordinator? = coordinator(oldEngine, sharedStore)
        oldLifecycle!!.bootstrap(environment)
        assertThrows(DurableLifecycleException::class.java) {
            oldLifecycle!!.handleEventJson("""{"type":"start"}""")
        }
        assertTrue(oldLifecycle!!.hasPendingCommit)

        oldLifecycle = null
        val restartedEngine = AndroidScriptedDurableEngine()
        val restarted = coordinator(restartedEngine, sharedStore)
        restarted.bootstrap(environment)

        assertTrue(restartedEngine.restored.isEmpty())
        assertFalse(restarted.hasPendingCommit)
        assertLifecycleError(DurableLifecycleErrorCode.NO_PENDING_COMMIT) {
            restarted.retryPendingEvent("""{"type":"start"}""")
        }
    }

    @Test
    fun coreErrorDoesNotAdvanceGenerationAndContextBindsAllIdentityFields() {
        val engine = AndroidScriptedDurableEngine()
        engine.response = """{"error":"stale operation"}"""
        val store = AndroidScriptedDurableStore()
        val lifecycle = coordinator(engine, store)
        lifecycle.bootstrap(environment)

        assertEquals(engine.response, lifecycle.handleEventJson("""{"type":"stale"}"""))
        assertTrue(engine.exportedGenerations.isEmpty())
        assertTrue(store.commits.isEmpty())

        val original = context()
        assertEquals(32, original.binding.size)
        assertEquals(
            "b959e1adc47d57a0c10b4b78f5c7f29ed3a0b47c52aa4c27879a12c210c669ee",
            original.binding.joinToString("") { "%02x".format(it.toInt() and 0xff) },
        )
        assertArrayEquals(original.binding, context().binding)
        assertFalse(original.binding.contentEquals(context(application = "eu.wallet.beta").binding))
        assertFalse(original.binding.contentEquals(context(wallet = "wallet.other").binding))
        assertFalse(original.binding.contentEquals(context(device = "device-key-2").binding))
        assertLifecycleError(DurableLifecycleErrorCode.INVALID_IDENTITY) {
            context(application = "")
        }
    }

    @Test
    fun malformedIndividualEffectIsRejectedBeforeCheckpointCommit() {
        val engine = AndroidScriptedDurableEngine()
        engine.response = """[{"type":"unknownNativeEffect","operationId":7}]"""
        val store = AndroidScriptedDurableStore()
        val lifecycle = coordinator(engine, store)
        lifecycle.bootstrap(environment)

        assertLifecycleError(DurableLifecycleErrorCode.MALFORMED_CORE_OUTPUT) {
            lifecycle.handleEventJson("""{"type":"start"}""")
        }
        assertTrue(engine.exportedGenerations.isEmpty())
        assertTrue(store.commits.isEmpty())
        assertFalse(lifecycle.hasPendingCommit)
    }

    @Test
    fun executorRejectsSecondEventWithoutOverwritingPendingRetry() {
        val engine = AndroidScriptedDurableEngine()
        val store = AndroidScriptedDurableStore()
        store.commitFailures = 1
        val lifecycle = coordinator(engine, store)
        lifecycle.bootstrap(environment)
        var renders = 0
        val executor = EffectExecutor(
            engine = lifecycle,
            signer = WalletSigner { _, _ -> byteArrayOf(1) },
            httpClient = WalletHttpClient { _, _, _ -> HttpResponse(200, byteArrayOf()) },
            storage = WalletStorage { _, _ -> },
            trustResolver = TrustResolver { TrustResolution(emptyList(), emptyList()) },
            renderer = ScreenRenderer { _, _, _ -> renders += 1 },
        )
        val firstEvent = """{"type":"start"}"""
        val secondEvent = """{"type":"other"}"""

        assertLifecycleError(DurableLifecycleErrorCode.STORAGE_COMMIT_FAILED) {
            executor.send(firstEvent)
        }
        assertLifecycleError(DurableLifecycleErrorCode.COMMIT_PENDING) {
            executor.send(secondEvent)
        }
        assertEquals(0, renders)
        assertEquals(listOf(firstEvent), engine.handledEvents)
        assertEquals(1, store.commits.size)
        assertEquals(EffectCascadeOutcome.AwaitingInput, executor.retryPendingDurableCommit())
        assertEquals(1, renders)
        assertEquals(listOf(firstEvent), engine.handledEvents)
        assertEquals(2, store.commits.size)
        assertThrows(WalletShellException.NoPendingDurableCommit::class.java) {
            executor.retryPendingDurableCommit()
        }
        assertEquals(1, renders)
    }

    @Test
    fun executorRetainsExactEventWheneverCoordinatorRemainsPending() {
        val engine = AndroidScriptedDurableEngine()
        engine.exportedGenerationOverride = 9
        val store = AndroidScriptedDurableStore()
        val lifecycle = coordinator(engine, store)
        lifecycle.bootstrap(environment)
        var renders = 0
        val executor = EffectExecutor(
            engine = lifecycle,
            signer = WalletSigner { _, _ -> byteArrayOf(1) },
            httpClient = WalletHttpClient { _, _, _ -> HttpResponse(200, byteArrayOf()) },
            storage = WalletStorage { _, _ -> },
            trustResolver = TrustResolver { TrustResolution(emptyList(), emptyList()) },
            renderer = ScreenRenderer { _, _, _ -> renders += 1 },
        )
        val firstEvent = """{"type":"start"}"""

        assertLifecycleError(DurableLifecycleErrorCode.CHECKPOINT_GENERATION_MISMATCH) {
            executor.send(firstEvent)
        }
        val replacementExecutor = EffectExecutor(
            engine = lifecycle,
            signer = WalletSigner { _, _ -> byteArrayOf(1) },
            httpClient = WalletHttpClient { _, _, _ -> HttpResponse(200, byteArrayOf()) },
            storage = WalletStorage { _, _ -> },
            trustResolver = TrustResolver { TrustResolution(emptyList(), emptyList()) },
            renderer = ScreenRenderer { _, _, _ -> throw AssertionError("must not render") },
        )
        assertLifecycleError(DurableLifecycleErrorCode.COMMIT_PENDING) {
            replacementExecutor.send("""{"type":"other"}""")
        }
        assertEquals(listOf(firstEvent), engine.handledEvents)
        assertTrue(lifecycle.hasPendingCommit)
        assertTrue(store.commits.isEmpty())

        engine.exportedGenerationOverride = null
        assertEquals(EffectCascadeOutcome.AwaitingInput, executor.retryPendingDurableCommit())
        assertEquals(listOf(firstEvent), engine.handledEvents)
        assertEquals(listOf(1L, 1L), engine.exportedGenerations)
        assertEquals(1, store.commits.size)
        assertEquals(1, renders)
    }

    @Test
    fun diagnosticsRedactEnvironmentCheckpointEventAndEffects() {
        val secret = "do-not-log-holder-secret"
        val engine = AndroidScriptedDurableEngine()
        engine.response =
            """[{"type":"render","screen":{"screen":"loading"},"secret":"$secret"}]"""
        val store = AndroidScriptedDurableStore()
        store.commitFailures = 1
        val lifecycle = coordinator(engine, store)
        lifecycle.bootstrap(environment)
        assertThrows(DurableLifecycleException::class.java) {
            lifecycle.handleEventJson("""{"type":"start","secret":"$secret"}""")
        }

        val values = listOf(
            environment.toString(),
            CoreDurableCheckpoint(1, secret.encodeToByteArray()).toString(),
            lifecycle.toString(),
            DurableLifecycleException(DurableLifecycleErrorCode.STORAGE_COMMIT_FAILED).toString(),
        )
        assertTrue(values.all { secret !in it })
        assertTrue(values.all { "trust-secret" !in it })
        assertTrue(values.all { "wua-secret" !in it })
    }

    private fun assertLifecycleError(
        expected: DurableLifecycleErrorCode,
        block: () -> Unit,
    ) {
        val error = assertThrows(DurableLifecycleException::class.java, block)
        assertEquals(expected, error.code)
        assertEquals(expected.stableMessage, error.message)
        assertNotEquals("", error.message)
    }
}
