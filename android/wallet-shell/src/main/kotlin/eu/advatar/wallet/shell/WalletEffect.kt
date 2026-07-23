package eu.advatar.wallet.shell

import kotlinx.serialization.SerializationException
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonNull
import kotlinx.serialization.json.JsonPrimitive

sealed interface WalletEffect {
    data class ResolveRpTrust(val operationId: Long, val clientId: String) : WalletEffect

    data class PersistNonce(val operationId: Long, val nonce: ULong) : WalletEffect

    data class Render(
        val operationId: Long?,
        val authorizationHash: ByteArray?,
        val screen: WalletScreen,
    ) : WalletEffect

    data class Sign(val operationId: Long, val keyRef: String, val payload: ByteArray) : WalletEffect

    data class Http(
        val operationId: Long,
        val resultType: HttpResultType,
        val profile: HttpDeliveryProfile,
        val url: String,
        val body: ByteArray,
    ) : WalletEffect

    data class PushPar(val operationId: Long) : WalletEffect

    data class OpenAuthBrowser(val operationId: Long) : WalletEffect

    data class PromptTxCode(val operationId: Long) : WalletEffect

    data class RequestToken(val operationId: Long) : WalletEffect

    data class RequestCredential(val operationId: Long, val proofJwt: ByteArray) : WalletEffect

    data class FetchStatusList(val operationId: Long, val uri: String) : WalletEffect

    data class PublishTransferOffer(val operationId: Long, val offeredKey: ByteArray) : WalletEffect

    data object Close : WalletEffect
}

enum class HttpResultType(val wireValue: String) {
    PRESENTATION_DELIVERED("presentationDelivered"),
    PAYMENT_AUTHORIZATION_DELIVERED("paymentAuthorizationDelivered"),
    QES_AUTHORIZATION_DELIVERED("qesAuthorizationDelivered"),
    ;

    companion object {
        fun fromWire(value: String): HttpResultType? = entries.firstOrNull { it.wireValue == value }
    }
}

enum class HttpDeliveryProfile(
    val wireValue: String,
    val resultType: HttpResultType,
) {
    OPENID4VP_DIRECT_POST("openid4vpDirectPost", HttpResultType.PRESENTATION_DELIVERED),
    PAYMENT_AUTHORIZATION(
        "paymentAuthorization",
        HttpResultType.PAYMENT_AUTHORIZATION_DELIVERED,
    ),
    QES_AUTHORIZATION("qesAuthorization", HttpResultType.QES_AUTHORIZATION_DELIVERED),
    ;

    companion object {
        fun fromWire(value: String): HttpDeliveryProfile? =
            entries.firstOrNull { it.wireValue == value }
    }
}

/** Strict decoder for the current Rust JSON Effect contract. */
object WalletEffectDecoder {
    private val json = Json {
        isLenient = false
        allowSpecialFloatingPointValues = false
    }
    private val unsignedInteger = Regex("0|[1-9][0-9]*")

    fun decodeCoreOutput(rawJson: String): List<WalletEffect> {
        val root = try {
            json.parseToJsonElement(rawJson)
        } catch (error: SerializationException) {
            throw WalletShellException.MalformedCoreOutput("invalid JSON", error)
        } catch (error: IllegalArgumentException) {
            throw WalletShellException.MalformedCoreOutput("invalid JSON", error)
        }

        if (root is JsonObject) {
            val error = root["error"] as? JsonPrimitive
            if (root.size == 1 && error?.isString == true) {
                throw WalletShellException.CoreRejected(error.content)
            }
            malformed("expected an effect array or a string error envelope")
        }

        val effects = root as? JsonArray ?: malformed("top-level value is not an array")
        return effects.mapIndexed { index, element ->
            val effect = element as? JsonObject
                ?: malformed("effect at index $index is not an object")
            decodeEffect(effect)
        }
    }

    private fun decodeEffect(value: JsonObject): WalletEffect = when (val type = string(value, "type")) {
        "resolveRpTrust" -> WalletEffect.ResolveRpTrust(
            operationId(value),
            string(value, "clientId"),
        )
        "persistNonce" -> WalletEffect.PersistNonce(operationId(value), unsigned(value, "nonce"))
        "render" -> {
            val screen = screen(objectValue(value, "screen"))
            val operationId = optionalOperationId(value)
            val authorizationHash = optionalBytes(value, "authorizationHash")
            if (
                (operationId == null || authorizationHash?.size != 32) &&
                (screen is WalletScreen.Consent ||
                    screen is WalletScreen.PaymentConfirmation ||
                    screen is WalletScreen.SignConfirmation ||
                    screen is WalletScreen.IssuanceOffer)
            ) {
                malformed("interactive render requires operationId and 32-byte authorizationHash")
            }
            WalletEffect.Render(operationId, authorizationHash, screen)
        }
        "sign" -> WalletEffect.Sign(
            operationId = operationId(value),
            keyRef = string(value, "keyRef"),
            payload = bytes(value, "payload"),
        )
        "http" -> {
            val resultType = HttpResultType.fromWire(string(value, "resultType"))
                ?: malformed("unknown HTTP resultType")
            val profile = HttpDeliveryProfile.fromWire(string(value, "profile"))
                ?: malformed("unknown HTTP delivery profile")
            if (profile.resultType != resultType) {
                malformed("HTTP delivery profile does not match resultType")
            }
            WalletEffect.Http(
                operationId = operationId(value),
                resultType = resultType,
                profile = profile,
                url = string(value, "url"),
                body = bytes(value, "body"),
            )
        }
        "pushPar" -> WalletEffect.PushPar(operationId(value))
        "openAuthBrowser" -> WalletEffect.OpenAuthBrowser(operationId(value))
        "promptTxCode" -> WalletEffect.PromptTxCode(operationId(value))
        "requestToken" -> WalletEffect.RequestToken(operationId(value))
        "requestCredential" -> WalletEffect.RequestCredential(
            operationId(value),
            bytes(value, "proofJwt"),
        )
        "fetchStatusList" -> WalletEffect.FetchStatusList(operationId(value), string(value, "uri"))
        "publishTransferOffer" -> WalletEffect.PublishTransferOffer(
            operationId(value),
            bytes(value, "offeredKey"),
        )
        "close" -> WalletEffect.Close
        else -> malformed("unknown effect type: $type")
    }

    private fun screen(value: JsonObject): WalletScreen = when (val type = string(value, "screen")) {
        "loading" -> WalletScreen.Loading
        "error" -> WalletScreen.Error(
            code = string(value, "code"),
            message = string(value, "message"),
        )
        "consent" -> WalletScreen.Consent(
            relyingPartyName = string(value, "rpDisplayName"),
            purpose = string(value, "purpose"),
            requestedClaims = strings(value, "requestedClaims"),
            notSharedClaims = strings(value, "notSharedClaims"),
            verifierRegistration = when (string(value, "verifierRegistration")) {
                "registered" -> WalletScreen.VerifierRegistration.REGISTERED
                "certificateValidated" -> WalletScreen.VerifierRegistration.CERTIFICATE_VALIDATED
                else -> malformed("unknown verifier registration status")
            },
            trustMark = when (optionalString(value, "trustMark")) {
                null -> null
                "eudiWallet" -> WalletScreen.VerifierTrustMark.EUDI_WALLET
                else -> malformed("unknown verifier trust mark")
            },
            retention = retention(objectValue(value, "retention")),
            overAsk = overAsk(objectValue(value, "overAsk")),
        )
        "paymentConfirmation" -> WalletScreen.PaymentConfirmation(
            creditorName = string(value, "creditorName"),
            creditorAccount = string(value, "creditorAccount"),
            amountMinor = unsigned(value, "amountMinor"),
            currency = string(value, "currency"),
        )
        "signConfirmation" -> WalletScreen.SignConfirmation(
            documentName = string(value, "documentName"),
            qtspId = string(value, "qtspId"),
            documentHashHex = string(value, "documentHashHex"),
        )
        "credentialList" -> WalletScreen.CredentialList(documentSummaries(value, "documents"))
        "credentialDetail" -> WalletScreen.CredentialDetail(
            documentSummary(objectValue(value, "document")),
            displayAttributes(value, "attributes"),
        )
        "issuanceOffer" -> WalletScreen.IssuanceOffer(
            issuerName = string(value, "issuerName"),
            documentName = string(value, "documentName"),
            format = credentialFormat(string(value, "format")),
            attributes = strings(value, "attributes"),
            portraitRequired = boolean(value, "portraitRequired"),
        )
        "pinPreparation" -> WalletScreen.PinPreparation(string(value, "documentName"))
        "pinHelp" -> WalletScreen.PinHelp
        "nfcReady" -> WalletScreen.NfcReady(string(value, "documentName"))
        "nfcReading" -> WalletScreen.NfcReading(when (string(value, "state")) {
            "waitingForCard" -> WalletScreen.NfcReadState.WAITING_FOR_CARD
            "reading" -> WalletScreen.NfcReadState.READING
            "connectionLost" -> WalletScreen.NfcReadState.CONNECTION_LOST
            else -> malformed("unknown NFC read state")
        })
        "issuancePreparing" -> WalletScreen.IssuancePreparing(
            documentSummary(objectValue(value, "document")),
        )
        "issuanceReady" -> WalletScreen.IssuanceReady(
            documentSummary(objectValue(value, "document")),
        )
        "issuanceNeedsAttention" -> WalletScreen.IssuanceNeedsAttention(
            documentSummary(objectValue(value, "document")),
            issuanceRecovery(string(value, "recovery")),
        )
        "issuanceRecovery" -> {
            val reason = issuanceRecovery(string(value, "reason"))
            val attempts = if (value["attemptsRemaining"] != null &&
                value["attemptsRemaining"] !is JsonNull
            ) {
                unsigned(value, "attemptsRemaining").takeIf { it in 1uL..UByte.MAX_VALUE.toULong() }
                    ?.toUByte() ?: malformed("attempts remaining outside range")
            } else null
            if ((reason == WalletScreen.IssuanceRecovery.WRONG_PIN) != (attempts != null)) {
                malformed("retry count must be present only for wrong PIN")
            }
            WalletScreen.IssuanceRecoveryScreen(
                reason, string(value, "documentName"), attempts, boolean(value, "canResume"),
            )
        }
        "presentQr" -> WalletScreen.PresentQr
        "scanQr" -> WalletScreen.ScanQr
        "authPrompt" -> WalletScreen.AuthPrompt
        "transactionHistory" -> WalletScreen.TransactionHistory
        else -> malformed("unknown screen type: $type")
    }

    private fun objectValue(value: JsonObject, key: String): JsonObject =
        value[key] as? JsonObject ?: malformed("$key must be an object")

    private fun string(value: JsonObject, key: String): String {
        val primitive = value[key] as? JsonPrimitive ?: malformed("$key must be a string")
        if (!primitive.isString) malformed("$key must be a string")
        return primitive.content
    }

    private fun optionalString(value: JsonObject, key: String): String? {
        val item = value[key] ?: return null
        if (item is JsonNull) return null
        val primitive = item as? JsonPrimitive ?: malformed("$key must be a string or null")
        if (!primitive.isString) malformed("$key must be a string or null")
        return primitive.content
    }

    private fun retention(value: JsonObject): WalletScreen.RetentionDisclosure {
        val policy = when (string(value, "policy")) {
            "notStored" -> WalletScreen.RetentionDisclosure.Policy.NOT_STORED
            "days" -> WalletScreen.RetentionDisclosure.Policy.DAYS
            "unspecified" -> WalletScreen.RetentionDisclosure.Policy.UNSPECIFIED
            else -> malformed("unknown retention policy")
        }
        val days = if ("days" in value) {
            unsigned(value, "days").takeIf { it in 1uL..UShort.MAX_VALUE.toULong() }
                ?.toUShort() ?: malformed("retention days outside range")
        } else {
            null
        }
        if ((policy == WalletScreen.RetentionDisclosure.Policy.DAYS) != (days != null)) {
            malformed("retention days must match policy")
        }
        return WalletScreen.RetentionDisclosure(policy, days)
    }

    private fun overAsk(value: JsonObject): WalletScreen.OverAskResult {
        val result = when (string(value, "result")) {
            "withinRegisteredScope" -> WalletScreen.OverAskResult.Result.WITHIN_REGISTERED_SCOPE
            "exceedsRegisteredScope" -> WalletScreen.OverAskResult.Result.EXCEEDS_REGISTERED_SCOPE
            "registrationScopeUnavailable" ->
                WalletScreen.OverAskResult.Result.REGISTRATION_SCOPE_UNAVAILABLE
            else -> malformed("unknown over-ask result")
        }
        val claims = if ("claims" in value) strings(value, "claims") else emptyList()
        if ((result == WalletScreen.OverAskResult.Result.EXCEEDS_REGISTERED_SCOPE) != claims.isNotEmpty()) {
            malformed("over-ask claims must match result")
        }
        return WalletScreen.OverAskResult(result, claims)
    }

    private fun strings(value: JsonObject, key: String): List<String> {
        val items = value[key] as? JsonArray ?: malformed("$key must be a string array")
        return items.mapIndexed { index, item ->
            val primitive = item as? JsonPrimitive
                ?: malformed("$key[$index] must be a string")
            if (!primitive.isString) malformed("$key[$index] must be a string")
            primitive.content
        }
    }

    private fun credentialFormat(value: String): WalletScreen.CredentialFormat = when (value) {
        "dcSdJwt" -> WalletScreen.CredentialFormat.DC_SD_JWT
        "msoMdoc" -> WalletScreen.CredentialFormat.MSO_MDOC
        else -> malformed("unknown credential display format")
    }

    private fun documentSummary(value: JsonObject): WalletScreen.DocumentSummary =
        WalletScreen.DocumentSummary(
            documentId = string(value, "documentId"),
            documentName = string(value, "documentName"),
            issuerName = string(value, "issuerName"),
            format = credentialFormat(string(value, "format")),
            status = when (string(value, "status")) {
                "preparing" -> WalletScreen.DocumentStatus.PREPARING
                "ready" -> WalletScreen.DocumentStatus.READY
                "needsAttention" -> WalletScreen.DocumentStatus.NEEDS_ATTENTION
                else -> malformed("unknown document status")
            },
            portraitRequired = boolean(value, "portraitRequired"),
        )

    private fun documentSummaries(value: JsonObject, key: String): List<WalletScreen.DocumentSummary> {
        val items = value[key] as? JsonArray ?: malformed("$key must be an object array")
        return items.mapIndexed { index, item ->
            documentSummary(item as? JsonObject ?: malformed("$key[$index] must be an object"))
        }
    }

    private fun displayAttributes(value: JsonObject, key: String): List<WalletScreen.DisplayAttribute> {
        val items = value[key] as? JsonArray ?: malformed("$key must be an object array")
        return items.mapIndexed { index, item ->
            val objectItem = item as? JsonObject ?: malformed("$key[$index] must be an object")
            WalletScreen.DisplayAttribute(string(objectItem, "label"), string(objectItem, "value"))
        }
    }

    private fun issuanceRecovery(value: String): WalletScreen.IssuanceRecovery = when (value) {
        "wrongPin" -> WalletScreen.IssuanceRecovery.WRONG_PIN
        "pinBlocked" -> WalletScreen.IssuanceRecovery.PIN_BLOCKED
        "nfcInterrupted" -> WalletScreen.IssuanceRecovery.NFC_INTERRUPTED
        "nfcUnavailable" -> WalletScreen.IssuanceRecovery.NFC_UNAVAILABLE
        "issuerRejected" -> WalletScreen.IssuanceRecovery.ISSUER_REJECTED
        "networkInterrupted" -> WalletScreen.IssuanceRecovery.NETWORK_INTERRUPTED
        "delayed" -> WalletScreen.IssuanceRecovery.DELAYED
        "sessionInterrupted" -> WalletScreen.IssuanceRecovery.SESSION_INTERRUPTED
        else -> malformed("unknown issuance recovery state")
    }

    private fun boolean(value: JsonObject, key: String): Boolean {
        val primitive = value[key] as? JsonPrimitive ?: malformed("$key must be a boolean")
        return primitive.content.toBooleanStrictOrNull()
            ?.takeIf { !primitive.isString } ?: malformed("$key must be a boolean")
    }

    private fun unsigned(value: JsonObject, key: String): ULong {
        val primitive = value[key] as? JsonPrimitive
            ?: malformed("$key must be an unsigned integer")
        val content = primitive.content
        if (primitive.isString || !unsignedInteger.matches(content)) {
            malformed("$key must be an unsigned integer")
        }
        return content.toULongOrNull() ?: malformed("$key is outside the UInt64 range")
    }

    private fun operationId(value: JsonObject): Long {
        val id = unsigned(value, "operationId")
        if (id == 0uL || id > Long.MAX_VALUE.toULong()) {
            malformed("operationId is outside the positive signed 64-bit range")
        }
        return id.toLong()
    }

    private fun optionalOperationId(value: JsonObject): Long? =
        if ("operationId" in value) operationId(value) else null

    private fun bytes(value: JsonObject, key: String): ByteArray {
        val items = value[key] as? JsonArray ?: malformed("$key must be a byte array")
        return ByteArray(items.size) { index ->
            val primitive = items[index] as? JsonPrimitive
                ?: malformed("$key[$index] must be an integer")
            val content = primitive.content
            val byte = if (primitive.isString || !unsignedInteger.matches(content)) {
                null
            } else {
                content.toIntOrNull()
            }
            if (byte == null || byte !in 0..255) {
                malformed("$key[$index] is outside the byte range")
            }
            byte.toByte()
        }
    }

    private fun optionalBytes(value: JsonObject, key: String): ByteArray? =
        if (key in value) bytes(value, key) else null

    private fun malformed(detail: String): Nothing =
        throw WalletShellException.MalformedCoreOutput(detail)
}
