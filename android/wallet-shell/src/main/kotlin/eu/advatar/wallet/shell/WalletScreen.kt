package eu.advatar.wallet.shell

/** Closed mirror of presenter::ScreenDescription from the wallet core. */
sealed interface WalletScreen {
    data object Loading : WalletScreen

    data class Error(
        val code: String,
        val message: String,
    ) : WalletScreen

    data class Consent(
        val relyingPartyName: String,
        val purpose: String,
        val requestedClaims: List<String>,
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
