package eu.advatar.wallet.shell

/** Closed mirror of presenter::ScreenDescription from the wallet core. */
sealed interface WalletScreen {
    enum class CredentialFormat { DC_SD_JWT, MSO_MDOC }
    enum class DocumentStatus { PREPARING, READY, NEEDS_ATTENTION }
    data class DocumentSummary(
        val documentId: String,
        val documentName: String,
        val issuerName: String,
        val format: CredentialFormat,
        val status: DocumentStatus,
        val portraitRequired: Boolean,
    )
    data class DisplayAttribute(val label: String, val value: String)
    enum class NfcReadState { WAITING_FOR_CARD, READING, CONNECTION_LOST }
    enum class IssuanceRecovery {
        WRONG_PIN, PIN_BLOCKED, NFC_INTERRUPTED, NFC_UNAVAILABLE, ISSUER_REJECTED,
        NETWORK_INTERRUPTED, DELAYED, SESSION_INTERRUPTED,
    }
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

    data class CredentialList(val documents: List<DocumentSummary>) : WalletScreen
    data class CredentialDetail(
        val document: DocumentSummary,
        val attributes: List<DisplayAttribute>,
    ) : WalletScreen
    data class IssuanceOffer(
        val issuerName: String,
        val documentName: String,
        val format: CredentialFormat,
        val attributes: List<String>,
        val portraitRequired: Boolean,
    ) : WalletScreen
    data class PinPreparation(val documentName: String) : WalletScreen
    data object PinHelp : WalletScreen
    data class NfcReady(val documentName: String) : WalletScreen
    data class NfcReading(val state: NfcReadState) : WalletScreen
    data class IssuancePreparing(val document: DocumentSummary) : WalletScreen
    data class IssuanceReady(val document: DocumentSummary) : WalletScreen
    data class IssuanceNeedsAttention(
        val document: DocumentSummary,
        val recovery: IssuanceRecovery,
    ) : WalletScreen
    data class IssuanceRecoveryScreen(
        val reason: IssuanceRecovery,
        val documentName: String,
        val attemptsRemaining: UByte?,
        val canResume: Boolean,
    ) : WalletScreen

    data object PresentQr : WalletScreen

    data object ScanQr : WalletScreen

    data object AuthPrompt : WalletScreen

    data object TransactionHistory : WalletScreen
}
