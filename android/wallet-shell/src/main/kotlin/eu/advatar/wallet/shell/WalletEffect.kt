package eu.advatar.wallet.shell

import kotlinx.serialization.SerializationException
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive

sealed interface WalletEffect {
    data class ResolveRpTrust(val clientId: String) : WalletEffect

    data class PersistNonce(val nonce: ULong) : WalletEffect

    data class Render(val screen: WalletScreen) : WalletEffect

    data class Sign(val keyRef: String, val payload: ByteArray) : WalletEffect

    data class Http(val url: String, val body: ByteArray) : WalletEffect

    data object PushPar : WalletEffect

    data object OpenAuthBrowser : WalletEffect

    data object PromptTxCode : WalletEffect

    data object RequestToken : WalletEffect

    data class RequestCredential(val proofJwt: ByteArray) : WalletEffect

    data class PublishTransferOffer(val offeredKey: ByteArray) : WalletEffect

    data object Close : WalletEffect
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
        "resolveRpTrust" -> WalletEffect.ResolveRpTrust(string(value, "clientId"))
        "persistNonce" -> WalletEffect.PersistNonce(unsigned(value, "nonce"))
        "render" -> WalletEffect.Render(screen(objectValue(value, "screen")))
        "sign" -> WalletEffect.Sign(
            keyRef = string(value, "keyRef"),
            payload = bytes(value, "payload"),
        )
        "http" -> WalletEffect.Http(
            url = string(value, "url"),
            body = bytes(value, "body"),
        )
        "pushPar" -> WalletEffect.PushPar
        "openAuthBrowser" -> WalletEffect.OpenAuthBrowser
        "promptTxCode" -> WalletEffect.PromptTxCode
        "requestToken" -> WalletEffect.RequestToken
        "requestCredential" -> WalletEffect.RequestCredential(bytes(value, "proofJwt"))
        "publishTransferOffer" -> WalletEffect.PublishTransferOffer(bytes(value, "offeredKey"))
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
        "credentialList" -> WalletScreen.CredentialList
        "credentialDetail" -> WalletScreen.CredentialDetail
        "issuanceOffer" -> WalletScreen.IssuanceOffer
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

    private fun strings(value: JsonObject, key: String): List<String> {
        val items = value[key] as? JsonArray ?: malformed("$key must be a string array")
        return items.mapIndexed { index, item ->
            val primitive = item as? JsonPrimitive
                ?: malformed("$key[$index] must be a string")
            if (!primitive.isString) malformed("$key[$index] must be a string")
            primitive.content
        }
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

    private fun malformed(detail: String): Nothing =
        throw WalletShellException.MalformedCoreOutput(detail)
}
