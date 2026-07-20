package eu.advatar.wallet.shell

/** Typed, terminal failures. None of these are translated into semantic wallet success events. */
sealed class WalletShellException(
    message: String,
    cause: Throwable? = null,
) : Exception(message, cause) {
    class CoreInvocationFailure(cause: Throwable) :
        WalletShellException("Wallet core invocation failed", cause)

    class NoPendingDurableCommit :
        WalletShellException("No durable wallet transition is awaiting retry")

    class DurableRetryUnavailable :
        WalletShellException("The wallet engine has no durable retry seam")

    class CoreRejected(val detail: String) :
        WalletShellException("Wallet core rejected the event: $detail")

    class MalformedCoreOutput(
        val detail: String,
        cause: Throwable? = null,
    ) : WalletShellException("Malformed wallet-core output: $detail", cause)

    class SigningFailure(cause: Throwable) :
        WalletShellException("Hardware signing failed", cause)

    class StorageFailure(cause: Throwable) :
        WalletShellException("Secure storage failed", cause)

    class TransportFailure(cause: Throwable) :
        WalletShellException("HTTP transport failed", cause)

    class HttpStatusFailure(
        val statusCode: Int,
        val responseBody: ByteArray,
    ) : WalletShellException("Wallet delivery failed with HTTP status $statusCode")

    class TrustResolutionFailure(cause: Throwable) :
        WalletShellException("Relying-party trust resolution failed", cause)

    class RenderingFailure(cause: Throwable) :
        WalletShellException("Wallet screen rendering failed", cause)

    class IssuerFailure(cause: Throwable) :
        WalletShellException("Credential issuer interaction failed", cause)

    class MissingDependency(val effectType: String) :
        WalletShellException("No production dependency is configured for $effectType")

    class UnsupportedEffect(val effectType: String) :
        WalletShellException("Effect is not implemented by this shell: $effectType")

    class EffectCascadeLimitExceeded(val limit: Int) :
        WalletShellException("Wallet-core effect cascade exceeded the limit of $limit")
}
