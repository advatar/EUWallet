package eu.advatar.wallet.shell

import java.io.ByteArrayOutputStream
import java.security.MessageDigest
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive

/** Current, externally obtained environment installed before any durable Core restore. */
class CoreDurableEnvironment(
    val clockEpoch: Long,
    signedTrustList: ByteArray,
    operatorPublicKey: ByteArray,
    devicePublicKey: ByteArray,
    wuaJwt: ByteArray,
    wuaProviderPublicKey: ByteArray,
) {
    private val trust = signedTrustList.copyOf()
    private val operatorKey = operatorPublicKey.copyOf()
    private val deviceKey = devicePublicKey.copyOf()
    private val attestation = wuaJwt.copyOf()
    private val providerKey = wuaProviderPublicKey.copyOf()

    val signedTrustList: ByteArray get() = trust.copyOf()
    val operatorPublicKey: ByteArray get() = operatorKey.copyOf()
    val devicePublicKey: ByteArray get() = deviceKey.copyOf()
    val wuaJwt: ByteArray get() = attestation.copyOf()
    val wuaProviderPublicKey: ByteArray get() = providerKey.copyOf()

    override fun toString(): String = "CoreDurableEnvironment(redacted)"
}

/** Native mirror of the generated UniFFI checkpoint record. */
class CoreDurableCheckpoint(
    val generation: Long,
    bytes: ByteArray,
) {
    private val checkpoint = bytes.copyOf()
    val bytes: ByteArray get() = checkpoint.copyOf()
    internal fun bytesForCommit(): ByteArray = checkpoint.copyOf()

    override fun toString(): String = "CoreDurableCheckpoint(redacted)"
}

/** Core methods required by the durable lifecycle gate. */
interface DurableWalletEngineDriving : WalletEngineDriving {
    fun prepareForDurableRestore(environment: CoreDurableEnvironment)

    fun makeDurableCheckpoint(generation: Long): CoreDurableCheckpoint

    fun restoreDurableCheckpointRecord(checkpoint: CoreDurableCheckpoint)
}

/** Exact retry seam consumed by [EffectExecutor]. */
fun interface DurableLifecycleRetrying {
    fun retryPendingEvent(eventJson: String): String
}

enum class DurableLifecycleErrorCode(val stableMessage: String) {
    INVALID_IDENTITY("durable_lifecycle_invalid_identity"),
    ALREADY_BOOTSTRAPPED("durable_lifecycle_already_bootstrapped"),
    ENVIRONMENT_PREPARATION_FAILED("durable_environment_preparation_failed"),
    STORAGE_LOAD_FAILED("durable_storage_load_failed"),
    CHECKPOINT_RESTORE_FAILED("durable_checkpoint_restore_failed"),
    NOT_BOOTSTRAPPED("durable_lifecycle_not_bootstrapped"),
    GENERATION_OVERFLOW("durable_generation_overflow"),
    CORE_INVOCATION_FAILED("durable_core_invocation_failed"),
    MALFORMED_CORE_OUTPUT("durable_core_output_malformed"),
    CHECKPOINT_EXPORT_FAILED("durable_checkpoint_export_failed"),
    CHECKPOINT_GENERATION_MISMATCH("durable_checkpoint_generation_mismatch"),
    CHECKPOINT_TOO_LARGE("durable_checkpoint_too_large"),
    STORAGE_COMMIT_FAILED("durable_storage_commit_failed"),
    PERSISTENCE_DIVERGED("durable_storage_generation_diverged"),
    COMMIT_PENDING("durable_commit_pending"),
    NO_PENDING_COMMIT("durable_no_pending_commit"),
    RETRY_EVENT_MISMATCH("durable_retry_event_mismatch"),
    LIFECYCLE_FAILED("durable_lifecycle_failed"),
}

/** Secret-safe exception: no source exception or wallet value is retained. */
class DurableLifecycleException(val code: DurableLifecycleErrorCode) :
    Exception(code.stableMessage)

/** Cross-platform app/schema/wallet/device binding authenticated by the platform store. */
object DurableLifecycleContextFactory {
    private const val MAXIMUM_IDENTITY_BYTES = 1_024
    private val domain = "EUW-LIFECYCLE-CONTEXT-V1".encodeToByteArray()

    fun make(
        applicationIdentifier: String,
        walletClientId: String,
        deviceKeyReference: String,
    ): DurableStateContext {
        val fields = listOf(applicationIdentifier, walletClientId, deviceKeyReference).map {
            it.encodeToByteArray()
        }
        if (fields.any { it.isEmpty() || it.size > MAXIMUM_IDENTITY_BYTES }) {
            fail(DurableLifecycleErrorCode.INVALID_IDENTITY)
        }
        val canonical = ByteArrayOutputStream()
        canonical.write(domain)
        canonical.writeInt(DurableStateContext.CURRENT_SCHEMA_VERSION)
        fields.forEach { field ->
            canonical.writeInt(field.size)
            canonical.write(field)
        }
        return DurableStateContext(
            binding = MessageDigest.getInstance("SHA-256").digest(canonical.toByteArray()),
        )
    }

    private fun ByteArrayOutputStream.writeInt(value: Int) {
        write((value ushr 24) and 0xff)
        write((value ushr 16) and 0xff)
        write((value ushr 8) and 0xff)
        write(value and 0xff)
    }
}

/**
 * Pure lifecycle gate between [EffectExecutor], Core and [DurableStateStore].
 *
 * A successful Core event is exported and compare-and-swap committed before its effects are
 * returned. Commit failure retains the exact event/checkpoint/effect batch; retry never invokes
 * Core. Process death discards that uncommitted in-memory batch and a new process restores only the
 * last anchored checkpoint. Protocol sessions/effects are intentionally not restored, so this is
 * at-most-once release after persistence, not a durable outbox or exactly-once external delivery.
 */
class DurableLifecycleCoordinator(
    private val engine: DurableWalletEngineDriving,
    private val store: DurableStateStore,
    private val context: DurableStateContext,
) : WalletEngineDriving, DurableLifecycleRetrying {
    private sealed interface State {
        data object Uninitialized : State
        data object Bootstrapping : State
        class Ready(val generation: Long) : State
        class PendingExport(val value: Export) : State
        class PendingCommit(val value: Commit) : State
        data object Failed : State
    }

    private class Export(
        val expectedGeneration: Long,
        val nextGeneration: Long,
        val eventJson: String,
        val effectsJson: String,
    )

    private class Commit(
        val export: Export,
        val checkpoint: CoreDurableCheckpoint,
    )

    private enum class CoreOutputKind { EFFECTS, ERROR_ENVELOPE, MALFORMED }
    private enum class Reconciliation { COMMITTED, UNCHANGED, DIVERGED, UNAVAILABLE }

    private var state: State = State.Uninitialized

    val hasPendingCommit: Boolean
        @Synchronized get() = state is State.PendingExport || state is State.PendingCommit

    @Synchronized
    fun bootstrap(environment: CoreDurableEnvironment) {
        if (state !is State.Uninitialized) {
            fail(DurableLifecycleErrorCode.ALREADY_BOOTSTRAPPED)
        }
        state = State.Bootstrapping
        try {
            engine.prepareForDurableRestore(environment)
        } catch (_: Exception) {
            state = State.Failed
            fail(DurableLifecycleErrorCode.ENVIRONMENT_PREPARATION_FAILED)
        }

        val loaded = try {
            store.load(context)
        } catch (_: Exception) {
            state = State.Failed
            fail(DurableLifecycleErrorCode.STORAGE_LOAD_FAILED)
        }
        when (loaded) {
            DurableStateLoadResult.Empty -> state = State.Ready(0)
            is DurableStateLoadResult.Record -> {
                val record = loaded.value
                val bytes = record.plaintext
                if (
                    record.generation <= 0 ||
                    bytes.size > DurableStateLimits.MAXIMUM_PLAINTEXT_BYTES
                ) {
                    state = State.Failed
                    fail(DurableLifecycleErrorCode.CHECKPOINT_RESTORE_FAILED)
                }
                try {
                    engine.restoreDurableCheckpointRecord(
                        CoreDurableCheckpoint(record.generation, bytes),
                    )
                } catch (_: Exception) {
                    state = State.Failed
                    fail(DurableLifecycleErrorCode.CHECKPOINT_RESTORE_FAILED)
                }
                state = State.Ready(record.generation)
            }
        }
    }

    @Synchronized
    override fun handleEventJson(eventJson: String): String {
        val generation = when (val current = state) {
            is State.Ready -> current.generation
            State.Uninitialized, State.Bootstrapping ->
                fail(DurableLifecycleErrorCode.NOT_BOOTSTRAPPED)
            is State.PendingExport, is State.PendingCommit ->
                fail(DurableLifecycleErrorCode.COMMIT_PENDING)
            State.Failed -> fail(DurableLifecycleErrorCode.LIFECYCLE_FAILED)
        }
        if (generation == Long.MAX_VALUE) fail(DurableLifecycleErrorCode.GENERATION_OVERFLOW)
        val nextGeneration = generation + 1

        val output = try {
            engine.handleEventJson(eventJson)
        } catch (_: Exception) {
            state = State.Failed
            fail(DurableLifecycleErrorCode.CORE_INVOCATION_FAILED)
        }
        when (classifyCoreOutput(output)) {
            CoreOutputKind.ERROR_ENVELOPE -> return output
            CoreOutputKind.MALFORMED -> {
                state = State.Failed
                fail(DurableLifecycleErrorCode.MALFORMED_CORE_OUTPUT)
            }
            CoreOutputKind.EFFECTS -> Unit
        }

        val pending = Export(generation, nextGeneration, eventJson, output)
        state = State.PendingExport(pending)
        val checkpoint = exportPending(pending)
        val commit = Commit(pending, checkpoint)
        state = State.PendingCommit(commit)
        return commitPending(commit, reconcileAmbiguousFailure = false)
    }

    @Synchronized
    override fun retryPendingEvent(eventJson: String): String = when (val current = state) {
        is State.PendingExport -> {
            if (current.value.eventJson != eventJson) {
                fail(DurableLifecycleErrorCode.RETRY_EVENT_MISMATCH)
            }
            val checkpoint = exportPending(current.value)
            val commit = Commit(current.value, checkpoint)
            state = State.PendingCommit(commit)
            commitPending(commit, reconcileAmbiguousFailure = true)
        }
        is State.PendingCommit -> {
            if (current.value.export.eventJson != eventJson) {
                fail(DurableLifecycleErrorCode.RETRY_EVENT_MISMATCH)
            }
            commitPending(current.value, reconcileAmbiguousFailure = true)
        }
        State.Uninitialized, State.Bootstrapping ->
            fail(DurableLifecycleErrorCode.NOT_BOOTSTRAPPED)
        is State.Ready -> fail(DurableLifecycleErrorCode.NO_PENDING_COMMIT)
        State.Failed -> fail(DurableLifecycleErrorCode.LIFECYCLE_FAILED)
    }

    private fun exportPending(pending: Export): CoreDurableCheckpoint {
        val checkpoint = try {
            engine.makeDurableCheckpoint(pending.nextGeneration)
        } catch (_: Exception) {
            state = State.PendingExport(pending)
            fail(DurableLifecycleErrorCode.CHECKPOINT_EXPORT_FAILED)
        }
        if (checkpoint.generation != pending.nextGeneration) {
            state = State.PendingExport(pending)
            fail(DurableLifecycleErrorCode.CHECKPOINT_GENERATION_MISMATCH)
        }
        val bytes = checkpoint.bytesForCommit()
        if (bytes.isEmpty() || bytes.size > DurableStateLimits.MAXIMUM_PLAINTEXT_BYTES) {
            state = State.PendingExport(pending)
            fail(DurableLifecycleErrorCode.CHECKPOINT_TOO_LARGE)
        }
        return checkpoint
    }

    private fun commitPending(pending: Commit, reconcileAmbiguousFailure: Boolean): String {
        val bytes = pending.checkpoint.bytesForCommit()
        val committed = try {
            store.commit(
                expectedGeneration = pending.export.expectedGeneration,
                nextGeneration = pending.export.nextGeneration,
                plaintext = bytes,
                context = context,
            )
        } catch (_: Exception) {
            state = State.PendingCommit(pending)
            if (reconcileAmbiguousFailure) {
                when (reconcileStoreRecord(pending, bytes)) {
                    Reconciliation.COMMITTED -> {
                        state = State.Ready(pending.export.nextGeneration)
                        return pending.export.effectsJson
                    }
                    Reconciliation.DIVERGED ->
                        fail(DurableLifecycleErrorCode.PERSISTENCE_DIVERGED)
                    Reconciliation.UNCHANGED, Reconciliation.UNAVAILABLE -> Unit
                }
            }
            fail(DurableLifecycleErrorCode.STORAGE_COMMIT_FAILED)
        }
        if (
            committed.generation != pending.export.nextGeneration ||
            !committed.plaintext.contentEquals(bytes)
        ) {
            state = State.PendingCommit(pending)
            fail(DurableLifecycleErrorCode.PERSISTENCE_DIVERGED)
        }
        state = State.Ready(pending.export.nextGeneration)
        return pending.export.effectsJson
    }

    private fun reconcileStoreRecord(pending: Commit, bytes: ByteArray): Reconciliation {
        val loaded = try {
            store.load(context)
        } catch (_: Exception) {
            return Reconciliation.UNAVAILABLE
        }
        return when (loaded) {
            DurableStateLoadResult.Empty -> if (pending.export.expectedGeneration == 0L) {
                Reconciliation.UNCHANGED
            } else {
                Reconciliation.DIVERGED
            }
            is DurableStateLoadResult.Record -> when {
                loaded.value.generation == pending.export.nextGeneration &&
                    loaded.value.plaintext.contentEquals(bytes) -> Reconciliation.COMMITTED
                loaded.value.generation == pending.export.expectedGeneration ->
                    Reconciliation.UNCHANGED
                else -> Reconciliation.DIVERGED
            }
        }
    }

    private fun classifyCoreOutput(output: String): CoreOutputKind {
        val value = try {
            Json.parseToJsonElement(output)
        } catch (_: Exception) {
            return CoreOutputKind.MALFORMED
        }
        if (value is JsonArray) return CoreOutputKind.EFFECTS
        if (
            value is JsonObject && value.size == 1 &&
            (value["error"] as? JsonPrimitive)?.isString == true
        ) {
            return CoreOutputKind.ERROR_ENVELOPE
        }
        return CoreOutputKind.MALFORMED
    }

    @Synchronized
    override fun toString(): String = "DurableLifecycleCoordinator(state=${stateName()})"

    private fun stateName(): String = when (state) {
        State.Uninitialized -> "uninitialized"
        State.Bootstrapping -> "bootstrapping"
        is State.Ready -> "ready"
        is State.PendingExport -> "pending_export"
        is State.PendingCommit -> "pending_commit"
        State.Failed -> "failed"
    }
}

private fun fail(code: DurableLifecycleErrorCode): Nothing = throw DurableLifecycleException(code)
