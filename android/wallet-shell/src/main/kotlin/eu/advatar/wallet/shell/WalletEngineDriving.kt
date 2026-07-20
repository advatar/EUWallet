package eu.advatar.wallet.shell

/**
 * Narrow boundary implemented by the future UniFFI/JNI bridge. The engine consumes one JSON event
 * and returns either a JSON array of effects or the documented `{ "error": "..." }` envelope.
 * Credential ingestion is intentionally not part of this shell interface.
 */
fun interface WalletEngineDriving {
    fun handleEventJson(eventJson: String): String
}
