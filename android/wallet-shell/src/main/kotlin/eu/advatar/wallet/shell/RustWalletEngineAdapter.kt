package eu.advatar.wallet.shell

import uniffi.wallet_core.FfiDurableCheckpoint
import uniffi.wallet_core.WalletEngine
import uniffi.wallet_core.WalletEngineInterface

/** Production bridge from the Android lifecycle gate to the generated Rust UniFFI engine. */
class RustWalletEngineAdapter private constructor(
    private val engine: WalletEngineInterface,
) : DurableWalletEngineDriving, AutoCloseable {
    constructor(walletClientId: String, deviceKeyReference: String) :
        this(WalletEngine(walletClientId, deviceKeyReference))

    override fun handleEventJson(eventJson: String): String = engine.handleEventJson(eventJson)

    override fun prepareForDurableRestore(environment: CoreDurableEnvironment) {
        engine.prepareDurableEnvironment(
            clockEpoch = environment.clockEpoch,
            signedTrustList = environment.signedTrustList,
            operatorPublicKey = environment.operatorPublicKey,
            devicePublicKey = environment.devicePublicKey,
            wuaJwt = environment.wuaJwt,
            wuaProviderPublicKey = environment.wuaProviderPublicKey,
        )
    }

    override fun makeDurableCheckpoint(generation: Long): CoreDurableCheckpoint {
        require(generation > 0) { "generation must be positive" }
        val checkpoint = engine.exportDurableCheckpoint(generation.toULong())
        require(checkpoint.generation <= Long.MAX_VALUE.toULong()) { "generation overflow" }
        return CoreDurableCheckpoint(checkpoint.generation.toLong(), checkpoint.bytes)
    }

    override fun restoreDurableCheckpointRecord(checkpoint: CoreDurableCheckpoint) {
        require(checkpoint.generation > 0) { "generation must be positive" }
        engine.restoreDurableCheckpoint(
            FfiDurableCheckpoint(checkpoint.generation.toULong(), checkpoint.bytes),
        )
    }

    override fun durableResumeEffectsJson(): String = engine.durableResumeEffectsJson()

    override fun close() {
        (engine as? AutoCloseable)?.close()
    }

    internal companion object {
        fun wrapping(engine: WalletEngineInterface): RustWalletEngineAdapter =
            RustWalletEngineAdapter(engine)
    }
}
