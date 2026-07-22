package eu.advatar.wallet.shell

import java.math.BigInteger
import org.json.JSONArray
import org.json.JSONObject

/** Builders covering the current Rust JSON Event contract. */
object WalletEventJson {
    fun setClock(epoch: Long): String = event("setClock").put("epoch", epoch).toString()

    fun redactTransaction(seq: ULong): String = event("redactTransaction")
        .put("seq", unsignedNumber(seq))
        .toString()

    fun wipeTransactionLog(): String = event("wipeTransactionLog").toString()

    fun authorizationRequestReceived(request: ByteArray): String = eventWithBytes(
        type = "authorizationRequestReceived",
        key = "request",
        bytes = request,
    )

    fun rpCertChainResolved(operationId: Long, resolution: TrustResolution): String =
        event("rpCertChainResolved")
        .put("operationId", operationId)
        .put(
            "rpCertChain",
            JSONArray().apply {
                resolution.certificateChain.forEach { put(byteArray(it)) }
            },
        )
        .put("registeredRedirectUris", JSONArray(resolution.registeredRedirectUris))
        .toString()

    fun userConsented(operationId: Long, authorizationHash: ByteArray): String =
        event("userConsented")
        .put("operationId", operationId)
        .put("authorizationHash", byteArray(authorizationHash))
        .toString()

    /** This builder is for an explicit UI rejection only; the executor never calls it on failure. */
    fun userDeclined(operationId: Long): String = event("userDeclined")
        .put("operationId", operationId)
        .toString()

    fun deviceSignatureProduced(operationId: Long, signature: ByteArray): String = eventWithBytes(
        type = "deviceSignatureProduced",
        key = "signature",
        bytes = signature,
        operationId = operationId,
    )

    fun presentationDelivered(operationId: Long): String = operationEvent(
        "presentationDelivered",
        operationId,
    ).toString()

    fun paymentAuthorizationDelivered(operationId: Long): String = operationEvent(
        "paymentAuthorizationDelivered",
        operationId,
    ).toString()

    fun qesAuthorizationDelivered(operationId: Long): String = operationEvent(
        "qesAuthorizationDelivered",
        operationId,
    ).toString()

    fun paymentAuthorizationRequestReceived(request: ByteArray): String = eventWithBytes(
        type = "paymentAuthorizationRequestReceived",
        key = "request",
        bytes = request,
    )

    fun paymentApproved(operationId: Long, authorizationHash: ByteArray): String = operationEvent(
        "paymentApproved",
        operationId,
    ).put("authorizationHash", byteArray(authorizationHash)).toString()

    fun paymentDeclined(operationId: Long): String = operationEvent(
        "paymentDeclined",
        operationId,
    ).toString()

    fun qesSignRequestReceived(request: ByteArray): String = eventWithBytes(
        type = "qesSignRequestReceived",
        key = "request",
        bytes = request,
    )

    fun qesAuthorized(operationId: Long, authorizationHash: ByteArray): String = operationEvent(
        "qesAuthorized",
        operationId,
    ).put("authorizationHash", byteArray(authorizationHash)).toString()

    fun qesDeclined(operationId: Long): String = operationEvent(
        "qesDeclined",
        operationId,
    ).toString()

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

    fun credentialOfferAccepted(operationId: Long, authorizationHash: ByteArray): String =
        operationEvent("credentialOfferAccepted", operationId)
            .put("authorizationHash", byteArray(authorizationHash))
            .toString()

    fun credentialOfferDeclined(operationId: Long): String =
        operationEvent("credentialOfferDeclined", operationId).toString()

    fun parPushed(operationId: Long, pkceS256: Boolean): String = operationEvent(
        "parPushed",
        operationId,
    )
        .put("pkceS256", pkceS256)
        .toString()

    fun authorizationCodeReturned(operationId: Long, code: ByteArray): String = eventWithBytes(
        type = "authorizationCodeReturned",
        key = "code",
        bytes = code,
        operationId = operationId,
    )

    fun transactionCodeEntered(operationId: Long, code: ByteArray): String = eventWithBytes(
        type = "transactionCodeEntered",
        key = "code",
        bytes = code,
        operationId = operationId,
    )

    fun tokenReceived(operationId: Long, result: TokenResult): String = operationEvent(
        "tokenReceived",
        operationId,
    )
        .put("bound", result.bound)
        .put("cNonce", unsignedNumber(result.cNonce))
        .toString()

    fun credentialReceived(operationId: Long, result: CredentialResult): String = operationEvent(
        "credentialReceived",
        operationId,
    )
        .put("format", result.format)
        .put("bytes", byteArray(result.bytes))
        .toString()

    fun statusListReceived(
        operationId: Long,
        uri: String,
        httpStatus: Int,
        token: ByteArray,
        providerCertificateChain: List<ByteArray>,
    ): String = operationEvent("statusListReceived", operationId)
        .put("uri", uri)
        .put("httpStatus", httpStatus)
        .put("token", byteArray(token))
        .put(
            "providerCertChain",
            JSONArray().apply { providerCertificateChain.forEach { put(byteArray(it)) } },
        )
        .toString()

    fun operationSucceeded(operationId: Long): String = operationEvent(
        "operationSucceeded",
        operationId,
    ).toString()

    fun operationFailed(operationId: Long, failure: WalletOperationFailure): String =
        operationEvent("operationFailed", operationId)
            .put("failure", failure.wireValue)
            .toString()

    fun operationCancelled(operationId: Long): String = operationEvent(
        "operationCancelled",
        operationId,
    ).toString()

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

    private fun operationEvent(type: String, operationId: Long): JSONObject = event(type)
        .put("operationId", operationId)

    private fun eventWithBytes(
        type: String,
        key: String,
        bytes: ByteArray,
        operationId: Long? = null,
    ): String = event(type)
        .apply { operationId?.let { put("operationId", it) } }
        .put(key, byteArray(bytes))
        .toString()

    private fun unsignedNumber(value: ULong): BigInteger = BigInteger(value.toString())

    private fun byteArray(bytes: ByteArray): JSONArray = JSONArray().apply {
        bytes.forEach { put(it.toInt() and 0xff) }
    }
}

enum class WalletOperationFailure(val wireValue: String) {
    TRUST("trust"),
    STORAGE("storage"),
    SIGNING("signing"),
    TRANSPORT("transport"),
    HTTP_STATUS("httpStatus"),
    ISSUER("issuer"),
    STATUS("status"),
    RENDERING("rendering"),
    MISSING_DEPENDENCY("missingDependency"),
    UNSUPPORTED("unsupported"),
}
