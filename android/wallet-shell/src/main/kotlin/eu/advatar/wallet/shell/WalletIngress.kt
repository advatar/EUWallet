package eu.advatar.wallet.shell

import android.content.Intent
import java.io.ByteArrayOutputStream
import java.net.URI
import java.nio.ByteBuffer
import java.nio.charset.CodingErrorAction
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive

/** A security-classified QR or deep-link payload that the host may hand to a wallet flow. */
sealed interface WalletIngressRequest {
    /** OpenID4VCI credential offer carried inline in the registered offer URI. */
    data class CredentialOffer(
        val issuer: String,
        val configurationIds: List<String>,
    ) : WalletIngressRequest

    /** OpenID4VCI credential offer that must be fetched from [uri]. */
    data class CredentialOfferByReference(val uri: String) : WalletIngressRequest

    /** OpenID4VP request object that must be fetched with GET from [requestUri]. */
    data class PresentationByReference(
        val requestUri: String,
        val clientId: String?,
    ) : WalletIngressRequest

    /** The input is malformed, ambiguous, unsupported, or is not an explicitly enabled route. */
    data object Unrecognized : WalletIngressRequest
}

/**
 * Pure QR/deep-link classifier. It performs no DNS lookup and no network access.
 *
 * Registered wallet schemes must use their exact lower-case spelling and the empty-authority,
 * empty-path `scheme://?query` form. HTTPS links can trigger a flow only when their canonical
 * origin is configured explicitly; Android App Links verification and Activity routing remain the
 * responsibility of the AAR host.
 */
class WalletIngressParser(
    allowedUniversalLinkOrigins: Set<String> = emptySet(),
) {
    private val urlPolicy = ProductionUrlPolicy()
    private val universalLinkOrigins: Set<String>

    init {
        require(allowedUniversalLinkOrigins.size <= MAXIMUM_UNIVERSAL_LINK_ORIGINS) {
            "too many universal-link origins"
        }
        universalLinkOrigins = allowedUniversalLinkOrigins.map { configured ->
            val uri = requireCanonicalHttps(configured, "invalid universal-link origin")
            require(uri.rawQuery == null && (uri.rawPath.isNullOrEmpty() || uri.rawPath == "/")) {
                "universal-link allowlist entries must be origins"
            }
            canonicalOrigin(uri)
        }.toSet()
        require(universalLinkOrigins.size == allowedUniversalLinkOrigins.size) {
            "duplicate canonical universal-link origin"
        }
    }

    /** Classifies [text] without retaining or logging rejected, potentially sensitive input. */
    fun parse(text: String): WalletIngressRequest {
        if (
            text.isEmpty() ||
            text.toByteArray(Charsets.UTF_8).size > MAXIMUM_INPUT_BYTES ||
            text.any { it.code !in 0x21..0x7e } ||
            '\\' in text
        ) {
            return WalletIngressRequest.Unrecognized
        }

        val uri = try {
            URI(text)
        } catch (_: Exception) {
            return WalletIngressRequest.Unrecognized
        }
        if (!uri.isAbsolute || uri.isOpaque || uri.rawFragment != null || uri.rawUserInfo != null) {
            return WalletIngressRequest.Unrecognized
        }

        val scheme = uri.scheme ?: return WalletIngressRequest.Unrecognized
        val isCredentialOfferScheme = scheme == CREDENTIAL_OFFER_SCHEME
        val isPresentationScheme = scheme in PRESENTATION_SCHEMES
        val isUniversalLink = if (scheme == HTTPS_SCHEME) {
            val validated = tryCanonicalHttps(text) ?: return WalletIngressRequest.Unrecognized
            canonicalOrigin(validated) in universalLinkOrigins
        } else {
            false
        }
        if (!isCredentialOfferScheme && !isPresentationScheme && !isUniversalLink) {
            return WalletIngressRequest.Unrecognized
        }

        if (isCredentialOfferScheme || isPresentationScheme) {
            if (
                !text.startsWith("$scheme://?") ||
                uri.rawAuthority != null ||
                !uri.rawPath.isNullOrEmpty() ||
                uri.port != -1
            ) {
                return WalletIngressRequest.Unrecognized
            }
        }

        val parameters = parseQuery(uri.rawQuery ?: return WalletIngressRequest.Unrecognized)
            ?: return WalletIngressRequest.Unrecognized
        val byName = parameters.associateBy { it.name }
        if (byName.size != parameters.size) return WalletIngressRequest.Unrecognized

        val offerParameters = OFFER_PARAMETERS.filterTo(mutableSetOf()) { it in byName }
        val presentationParameters = PRESENTATION_PARAMETERS.filterTo(mutableSetOf()) {
            it in byName
        }
        val presentationSecurityParameters = presentationParameters.toMutableSet().apply {
            if (CLIENT_ID_PARAMETER in byName) add(CLIENT_ID_PARAMETER)
        }
        val securityParameters = offerParameters + presentationSecurityParameters
        if (securityParameters.any { byName.getValue(it).value.isEmpty() }) {
            return WalletIngressRequest.Unrecognized
        }
        if (offerParameters.isNotEmpty() && presentationSecurityParameters.isNotEmpty()) {
            return WalletIngressRequest.Unrecognized
        }
        if (
            isCredentialOfferScheme &&
            (offerParameters.isEmpty() || presentationSecurityParameters.isNotEmpty())
        ) {
            return WalletIngressRequest.Unrecognized
        }
        if (
            isPresentationScheme &&
            (offerParameters.isNotEmpty() || presentationParameters.isEmpty())
        ) {
            return WalletIngressRequest.Unrecognized
        }

        val looksLikeOffer = isCredentialOfferScheme ||
            (isUniversalLink && offerParameters.isNotEmpty())
        if (looksLikeOffer) {
            return parseCredentialOffer(parameters, byName, offerParameters)
        }

        val looksLikePresentation = isPresentationScheme ||
            (isUniversalLink && presentationParameters.isNotEmpty())
        if (looksLikePresentation) {
            return parsePresentation(parameters, byName)
        }

        return WalletIngressRequest.Unrecognized
    }

    private fun parseCredentialOffer(
        parameters: List<QueryParameter>,
        byName: Map<String, QueryParameter>,
        offerParameters: Set<String>,
    ): WalletIngressRequest {
        if (
            parameters.any { it.name !in OFFER_PARAMETERS } ||
            offerParameters.size != 1
        ) {
            return WalletIngressRequest.Unrecognized
        }

        byName[CREDENTIAL_OFFER_URI_PARAMETER]?.let { parameter ->
            if (tryCanonicalHttps(parameter.value) == null) {
                return WalletIngressRequest.Unrecognized
            }
            return WalletIngressRequest.CredentialOfferByReference(parameter.value)
        }

        val inline = byName[CREDENTIAL_OFFER_PARAMETER]?.value
            ?: return WalletIngressRequest.Unrecognized
        if (!hasUniqueObjectKeysAndBoundedDepth(inline)) {
            return WalletIngressRequest.Unrecognized
        }
        val offer = try {
            JSON.parseToJsonElement(inline) as? JsonObject
        } catch (_: Exception) {
            null
        } ?: return WalletIngressRequest.Unrecognized

        val issuer = offer["credential_issuer"].stringValue()
            ?: return WalletIngressRequest.Unrecognized
        val issuerUri = tryCanonicalHttps(issuer) ?: return WalletIngressRequest.Unrecognized
        if (issuerUri.rawQuery != null) return WalletIngressRequest.Unrecognized

        val ids = (offer["credential_configuration_ids"] as? JsonArray)?.map { element ->
            element.stringValue() ?: return WalletIngressRequest.Unrecognized
        } ?: return WalletIngressRequest.Unrecognized
        if (
            ids.size !in 1..MAXIMUM_CONFIGURATION_IDS ||
            ids.toSet().size != ids.size ||
            ids.any {
                it.isEmpty() ||
                    it.toByteArray(Charsets.UTF_8).size > MAXIMUM_CONFIGURATION_ID_BYTES ||
                    it.any(Char::isISOControl)
            }
        ) {
            return WalletIngressRequest.Unrecognized
        }
        return WalletIngressRequest.CredentialOffer(issuer, ids)
    }

    private fun parsePresentation(
        parameters: List<QueryParameter>,
        byName: Map<String, QueryParameter>,
    ): WalletIngressRequest {
        // Inline request objects, PD/DCQL inputs, and request_uri_method are security inputs that
        // the current typed result cannot preserve. Reject them instead of silently dropping them
        // or treating POST as GET.
        if (parameters.any { it.name !in SUPPORTED_PRESENTATION_PARAMETERS }) {
            return WalletIngressRequest.Unrecognized
        }
        val requestUri = byName[REQUEST_URI_PARAMETER]?.value
            ?: return WalletIngressRequest.Unrecognized
        if (tryCanonicalHttps(requestUri) == null) return WalletIngressRequest.Unrecognized

        val clientId = byName[CLIENT_ID_PARAMETER]?.value
        if (
            clientId != null &&
            (
                clientId.isEmpty() ||
                    clientId.toByteArray(Charsets.UTF_8).size > MAXIMUM_CLIENT_ID_BYTES ||
                    clientId.any(Char::isISOControl)
                )
        ) {
            return WalletIngressRequest.Unrecognized
        }
        return WalletIngressRequest.PresentationByReference(requestUri, clientId)
    }

    private fun parseQuery(rawQuery: String): List<QueryParameter>? {
        if (
            rawQuery.isEmpty() ||
            rawQuery.toByteArray(Charsets.US_ASCII).size > MAXIMUM_QUERY_BYTES
        ) {
            return null
        }
        val rawItems = splitPreservingEmpty(rawQuery, '&')
        if (rawItems.size !in 1..MAXIMUM_QUERY_ITEMS) return null

        return rawItems.map { item ->
            if (item.isEmpty() || '+' in item) return null
            val separator = item.indexOf('=')
            if (separator <= 0) return null
            val name = decodeQueryComponent(item.substring(0, separator)) ?: return null
            val value = decodeQueryComponent(item.substring(separator + 1)) ?: return null
            if (
                name.value.isEmpty() ||
                name.byteCount > MAXIMUM_QUERY_NAME_BYTES ||
                value.byteCount > MAXIMUM_QUERY_VALUE_BYTES ||
                name.value.any(Char::isISOControl)
            ) {
                return null
            }
            QueryParameter(name.value, value.value)
        }
    }

    private fun decodeQueryComponent(value: String): DecodedComponent? {
        val bytes = ByteArrayOutputStream(value.length)
        var index = 0
        while (index < value.length) {
            val character = value[index]
            if (character == '%') {
                if (index + 2 >= value.length) return null
                val high = value[index + 1].digitToIntOrNull(16) ?: return null
                val low = value[index + 2].digitToIntOrNull(16) ?: return null
                bytes.write((high shl 4) or low)
                index += 3
            } else {
                if (character.code !in 0x21..0x7e) return null
                bytes.write(character.code)
                index += 1
            }
        }
        val decodedBytes = bytes.toByteArray()
        val decoded = try {
            Charsets.UTF_8.newDecoder()
                .onMalformedInput(CodingErrorAction.REPORT)
                .onUnmappableCharacter(CodingErrorAction.REPORT)
                .decode(ByteBuffer.wrap(decodedBytes))
                .toString()
        } catch (_: Exception) {
            return null
        }
        return DecodedComponent(decoded, decodedBytes.size)
    }

    private fun tryCanonicalHttps(value: String): URI? = try {
        urlPolicy.validateForIngress(value)
    } catch (_: WalletHttpClientException) {
        null
    }

    private fun requireCanonicalHttps(value: String, message: String): URI =
        requireNotNull(tryCanonicalHttps(value)) { message }

    private fun canonicalOrigin(uri: URI): String = "https://${uri.rawAuthority}"

    /**
     * kotlinx.serialization accepts duplicate object keys using last-value-wins semantics. This
     * scanner resolves escaped key spellings and rejects duplicates at every object depth before
     * parsing; the JSON parser remains responsible for full grammar validation.
     */
    private fun hasUniqueObjectKeysAndBoundedDepth(json: String): Boolean {
        data class Context(
            val isObject: Boolean,
            val keys: MutableSet<String> = mutableSetOf(),
            var expectsKey: Boolean = false,
        )

        val contexts = mutableListOf<Context>()
        var index = 0
        var structuralTokens = 0
        while (index < json.length) {
            when (json[index]) {
                '{' -> {
                    contexts += Context(isObject = true, expectsKey = true)
                    structuralTokens += 1
                    if (
                        contexts.size > MAXIMUM_JSON_DEPTH ||
                        structuralTokens > MAXIMUM_JSON_STRUCTURAL_TOKENS
                    ) {
                        return false
                    }
                }
                '[' -> {
                    contexts += Context(isObject = false)
                    structuralTokens += 1
                    if (
                        contexts.size > MAXIMUM_JSON_DEPTH ||
                        structuralTokens > MAXIMUM_JSON_STRUCTURAL_TOKENS
                    ) {
                        return false
                    }
                }
                '}', ']' -> {
                    if (contexts.isEmpty()) return false
                    contexts.removeAt(contexts.lastIndex)
                }
                ',' -> {
                    contexts.lastOrNull()?.takeIf { it.isObject }?.expectsKey = true
                }
                '"' -> {
                    val start = index
                    index += 1
                    var escaped = false
                    while (index < json.length) {
                        val character = json[index]
                        if (escaped) {
                            escaped = false
                        } else if (character == '\\') {
                            escaped = true
                        } else if (character == '"') {
                            break
                        }
                        index += 1
                    }
                    if (index >= json.length) return false

                    val context = contexts.lastOrNull()
                    if (context?.isObject == true && context.expectsKey) {
                        val key = try {
                            (JSON.parseToJsonElement(json.substring(start, index + 1)) as JsonPrimitive)
                                .content
                        } catch (_: Exception) {
                            return false
                        }
                        var lookahead = index + 1
                        while (lookahead < json.length && json[lookahead] in JSON_WHITESPACE) {
                            lookahead += 1
                        }
                        if (lookahead >= json.length || json[lookahead] != ':') return false
                        if (!context.keys.add(key)) return false
                        context.expectsKey = false
                    }
                }
            }
            index += 1
        }
        return contexts.isEmpty()
    }

    private data class QueryParameter(val name: String, val value: String)

    private data class DecodedComponent(val value: String, val byteCount: Int)

    companion object {
        const val MAXIMUM_INPUT_BYTES = 32 * 1024
        const val MAXIMUM_QUERY_BYTES = 24 * 1024
        const val MAXIMUM_QUERY_ITEMS = 64
        const val MAXIMUM_QUERY_NAME_BYTES = 128
        const val MAXIMUM_QUERY_VALUE_BYTES = 16 * 1024
        const val MAXIMUM_CLIENT_ID_BYTES = 2_048
        const val MAXIMUM_UNIVERSAL_LINK_ORIGINS = 32
        const val MAXIMUM_CONFIGURATION_IDS = 32
        const val MAXIMUM_CONFIGURATION_ID_BYTES = 256
        private const val MAXIMUM_JSON_DEPTH = 32
        private const val MAXIMUM_JSON_STRUCTURAL_TOKENS = 4_096

        private const val HTTPS_SCHEME = "https"
        private const val CREDENTIAL_OFFER_SCHEME = "openid-credential-offer"
        private const val CREDENTIAL_OFFER_PARAMETER = "credential_offer"
        private const val CREDENTIAL_OFFER_URI_PARAMETER = "credential_offer_uri"
        private const val REQUEST_URI_PARAMETER = "request_uri"
        private const val CLIENT_ID_PARAMETER = "client_id"

        private val PRESENTATION_SCHEMES = setOf(
            "openid4vp",
            "haip",
            "eudi-openid4vp",
            "mdoc-openid4vp",
        )
        private val OFFER_PARAMETERS = setOf(
            CREDENTIAL_OFFER_PARAMETER,
            CREDENTIAL_OFFER_URI_PARAMETER,
        )
        private val PRESENTATION_PARAMETERS = setOf(
            "request",
            REQUEST_URI_PARAMETER,
            "presentation_definition",
            "presentation_definition_uri",
            "dcql_query",
            "request_uri_method",
        )
        private val SUPPORTED_PRESENTATION_PARAMETERS = setOf(
            REQUEST_URI_PARAMETER,
            CLIENT_ID_PARAMETER,
        )
        private val JSON_WHITESPACE = setOf(' ', '\t', '\n', '\r')

        private val JSON = Json {
            isLenient = false
            allowSpecialFloatingPointValues = false
        }

        private fun splitPreservingEmpty(value: String, delimiter: Char): List<String> {
            val parts = mutableListOf<String>()
            var start = 0
            value.forEachIndexed { index, character ->
                if (character == delimiter) {
                    parts += value.substring(start, index)
                    start = index + 1
                }
            }
            parts += value.substring(start)
            return parts
        }
    }
}

/**
 * Thin Android adapter for externally routed deep links. QR scanners should pass their decoded
 * text directly to [WalletIngressParser.parse]. This AAR deliberately does not declare an
 * Activity or intent filter.
 */
class AndroidWalletIngress(
    private val parser: WalletIngressParser,
) {
    fun parse(intent: Intent): WalletIngressRequest = try {
        parseViewIntent(
            action = intent.action,
            categories = intent.categories.orEmpty(),
            dataString = intent.dataString,
            hasClipData = intent.clipData != null,
            hasSelector = intent.selector != null,
            mimeType = intent.type,
        )
    } catch (_: RuntimeException) {
        WalletIngressRequest.Unrecognized
    }

    internal fun parseViewIntent(
        action: String?,
        categories: Set<String>,
        dataString: String?,
        hasClipData: Boolean,
        hasSelector: Boolean,
        mimeType: String?,
    ): WalletIngressRequest {
        if (
            action != Intent.ACTION_VIEW ||
            Intent.CATEGORY_BROWSABLE !in categories ||
            categories.size > MAXIMUM_INTENT_CATEGORIES ||
            categories.any { it.isEmpty() || it.length > MAXIMUM_INTENT_CATEGORY_CHARACTERS } ||
            dataString == null ||
            hasClipData ||
            hasSelector ||
            mimeType != null
        ) {
            return WalletIngressRequest.Unrecognized
        }
        return parser.parse(dataString)
    }

    companion object {
        private const val MAXIMUM_INTENT_CATEGORIES = 8
        private const val MAXIMUM_INTENT_CATEGORY_CHARACTERS = 256
    }
}

private fun kotlinx.serialization.json.JsonElement?.stringValue(): String? =
    (this as? JsonPrimitive)?.takeIf { it.isString }?.content
