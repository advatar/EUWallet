package eu.advatar.wallet.shell

import java.math.BigInteger
import org.json.JSONArray
import org.json.JSONObject

/** Builders covering the current Rust JSON Event contract. */
object WalletEventJson {
    fun setClock(epoch: Long): String = event("setClock").put("epoch", epoch).toString()

    fun authorizationRequestReceived(request: ByteArray): String = eventWithBytes(
        type = "authorizationRequestReceived",
        key = "request",
        bytes = request,
    )

    fun rpCertChainResolved(resolution: TrustResolution): String = event("rpCertChainResolved")
        .put(
            "rpCertChain",
            JSONArray().apply {
                resolution.certificateChain.forEach { put(byteArray(it)) }
            },
        )
        .put("registeredRedirectUris", JSONArray(resolution.registeredRedirectUris))
        .toString()

    fun userConsented(): String = event("userConsented").toString()

    /** This builder is for an explicit UI rejection only; the executor never calls it on failure. */
    fun userDeclined(): String = event("userDeclined").toString()

    fun deviceSignatureProduced(signature: ByteArray): String = eventWithBytes(
        type = "deviceSignatureProduced",
        key = "signature",
        bytes = signature,
    )

    fun presentationDelivered(): String = event("presentationDelivered").toString()

    fun paymentAuthorizationRequestReceived(request: ByteArray): String = eventWithBytes(
        type = "paymentAuthorizationRequestReceived",
        key = "request",
        bytes = request,
    )

    fun paymentApproved(): String = event("paymentApproved").toString()

    fun paymentDeclined(): String = event("paymentDeclined").toString()

    fun qesSignRequestReceived(request: ByteArray): String = eventWithBytes(
        type = "qesSignRequestReceived",
        key = "request",
        bytes = request,
    )

    fun qesAuthorized(): String = event("qesAuthorized").toString()

    fun qesDeclined(): String = event("qesDeclined").toString()

    fun credentialOfferReceived(
        offer: ByteArray,
        issuerCertificateChain: List<ByteArray>,
        issuerId: String,
    ): String = event("credentialOfferReceived")
        .put("offer", byteArray(offer))
        .put(
            "issuerCertChain",
            JSONArray().apply { issuerCertificateChain.forEach { put(byteArray(it)) } },
        )
        .put("issuerId", issuerId)
        .toString()

    fun parPushed(pkceS256: Boolean): String = event("parPushed")
        .put("pkceS256", pkceS256)
        .toString()

    fun authorizationCodeReturned(code: ByteArray): String = eventWithBytes(
        type = "authorizationCodeReturned",
        key = "code",
        bytes = code,
    )

    fun transactionCodeEntered(code: ByteArray): String = eventWithBytes(
        type = "transactionCodeEntered",
        key = "code",
        bytes = code,
    )

    fun tokenReceived(result: TokenResult): String = event("tokenReceived")
        .put("bound", result.bound)
        .put("cNonce", unsignedNumber(result.cNonce))
        .toString()

    fun credentialReceived(result: CredentialResult): String = event("credentialReceived")
        .put("format", result.format)
        .put("bytes", byteArray(result.bytes))
        .toString()

    fun walletTransferOfferCreated(): String = event("walletTransferOfferCreated").toString()

    fun walletTransferReceived(
        credential: ByteArray,
        issuerCertificateChain: List<ByteArray>,
        senderPublicKey: ByteArray,
        senderSignature: ByteArray,
        senderConsentHash: ByteArray,
        nonce: ULong,
    ): String = event("walletTransferReceived")
        .put("credential", byteArray(credential))
        .put(
            "issuerCertChain",
            JSONArray().apply { issuerCertificateChain.forEach { put(byteArray(it)) } },
        )
        .put("senderPublicKey", byteArray(senderPublicKey))
        .put("senderSignature", byteArray(senderSignature))
        .put("senderConsentHash", byteArray(senderConsentHash))
        .put("nonce", unsignedNumber(nonce))
        .toString()

    private fun event(type: String): JSONObject = JSONObject().put("type", type)

    private fun eventWithBytes(type: String, key: String, bytes: ByteArray): String = event(type)
        .put(key, byteArray(bytes))
        .toString()

    private fun unsignedNumber(value: ULong): BigInteger = BigInteger(value.toString())

    private fun byteArray(bytes: ByteArray): JSONArray = JSONArray().apply {
        bytes.forEach { put(it.toInt() and 0xff) }
    }
}
