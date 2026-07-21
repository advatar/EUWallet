package eu.advatar.wallet.shell

/** Process-local durable store used only to exercise the real lifecycle gate in JVM tests. */
internal class InMemoryDurableStateStore(
    initialRecord: DurableStateRecord? = null,
) : DurableStateStore {
    private var storedRecord = initialRecord?.copy()

    val currentRecord: DurableStateRecord?
        @Synchronized get() = storedRecord?.copy()

    @Synchronized
    override fun load(context: DurableStateContext): DurableStateLoadResult =
        storedRecord?.copy()?.let(DurableStateLoadResult::Record) ?: DurableStateLoadResult.Empty

    @Synchronized
    override fun commit(
        expectedGeneration: Long,
        nextGeneration: Long,
        plaintext: ByteArray,
        context: DurableStateContext,
    ): DurableStateRecord {
        val actualGeneration = storedRecord?.generation ?: 0
        if (actualGeneration != expectedGeneration) {
            throw DurableStateStoreException.GenerationConflict(
                expectedGeneration,
                actualGeneration,
            )
        }
        if (expectedGeneration == Long.MAX_VALUE || nextGeneration != expectedGeneration + 1) {
            throw DurableStateStoreException.InvalidGenerationTransition(
                expectedGeneration,
                nextGeneration,
            )
        }
        if (plaintext.size > DurableStateLimits.MAXIMUM_PLAINTEXT_BYTES) {
            throw DurableStateStoreException.PlaintextTooLarge(
                plaintext.size,
                DurableStateLimits.MAXIMUM_PLAINTEXT_BYTES,
            )
        }
        return DurableStateRecord(nextGeneration, plaintext).also {
            storedRecord = it.copy()
        }
    }

    private fun DurableStateRecord.copy() = DurableStateRecord(generation, plaintext)
}

internal fun bootstrappedTestLifecycle(
    engine: DurableWalletEngineDriving,
    store: DurableStateStore = InMemoryDurableStateStore(),
): DurableLifecycleCoordinator = DurableLifecycleCoordinator(
    engine = engine,
    store = store,
    context = DurableLifecycleContextFactory.make(
        applicationIdentifier = "eu.advatar.wallet.test",
        walletClientId = "test-wallet",
        deviceKeyReference = "test-device-key",
    ),
).also { lifecycle ->
    lifecycle.bootstrap(
        CoreDurableEnvironment(
            clockEpoch = 1_790_000_000,
            signedTrustList = byteArrayOf(1),
            operatorPublicKey = byteArrayOf(2),
            devicePublicKey = byteArrayOf(3),
            wuaJwt = byteArrayOf(4),
            wuaProviderPublicKey = byteArrayOf(5),
        ),
    )
}
