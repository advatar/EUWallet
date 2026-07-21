package eu.advatar.wallet.shell

fun interface WalletSigner {
    fun sign(keyRef: String, payload: ByteArray): ByteArray
}

data class HttpResponse(
    val statusCode: Int,
    val body: ByteArray,
)

fun interface WalletHttpClient {
    fun post(url: String, body: ByteArray): HttpResponse
}

fun interface WalletStorage {
    fun put(key: String, value: ByteArray)
}

data class TrustResolution(
    val certificateChain: List<ByteArray>,
    val registeredRedirectUris: List<String>,
)

fun interface TrustResolver {
    fun resolve(clientId: String): TrustResolution
}

fun interface ScreenRenderer {
    fun render(screen: WalletScreen)
}

data class TokenResult(
    val bound: Boolean,
    val cNonce: ULong,
)

data class CredentialResult(
    val format: String,
    val bytes: ByteArray,
)

interface IssuerResponder {
    fun token(): TokenResult

    fun credential(proofJwt: ByteArray): CredentialResult
}
