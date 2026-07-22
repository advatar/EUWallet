package eu.advatar.wallet.shell

/** Closed mirror of presenter::ScreenDescription from the wallet core. */
sealed interface WalletScreen {
    enum class VerifierRegistration { REGISTERED, CERTIFICATE_VALIDATED }
    enum class VerifierTrustMark { EUDI_WALLET }

    data class RetentionDisclosure(val policy: Policy, val days: UShort? = null) {
        enum class Policy { NOT_STORED, DAYS, UNSPECIFIED }
    }

    data class OverAskResult(val result: Result, val claims: List<String> = emptyList()) {
        enum class Result {
            WITHIN_REGISTERED_SCOPE,
            EXCEEDS_REGISTERED_SCOPE,
            REGISTRATION_SCOPE_UNAVAILABLE,
        }
    }

    data object Loading : WalletScreen

    data class Error(
        val code: String,
        val message: String,
    ) : WalletScreen

    data class Consent(
        val relyingPartyName: String,
        val purpose: String,
        val requestedClaims: List<String>,
        val notSharedClaims: List<String>,
        val verifierRegistration: VerifierRegistration,
        val trustMark: VerifierTrustMark?,
        val retention: RetentionDisclosure,
        val overAsk: OverAskResult,
    ) : WalletScreen

    data class PaymentConfirmation(
        val creditorName: String,
        val creditorAccount: String,
        val amountMinor: ULong,
        val currency: String,
    ) : WalletScreen

    data class SignConfirmation(
        val documentName: String,
        val qtspId: String,
        val documentHashHex: String,
    ) : WalletScreen

    data object CredentialList : WalletScreen

    data object CredentialDetail : WalletScreen

    data object IssuanceOffer : WalletScreen

    data object PresentQr : WalletScreen

    data object ScanQr : WalletScreen

    data object AuthPrompt : WalletScreen

    data object TransactionHistory : WalletScreen
}
