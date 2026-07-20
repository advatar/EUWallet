package eu.advatar.wallet.shell

import java.net.URI
import java.nio.ByteBuffer
import java.nio.charset.CodingErrorAction
import java.nio.charset.StandardCharsets
import java.util.Locale
import kotlinx.serialization.SerializationException
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive

data class OpenId4VpDirectPostResponse(val redirectUri: URI?) {
    companion object {
        const val MAXIMUM_RESPONSE_BYTES = 64 * 1_024
        const val MAXIMUM_REDIRECT_URI_BYTES = 4_096

        private val json = Json {
            isLenient = false
            allowSpecialFloatingPointValues = false
        }
        private val scheme = Regex("[A-Za-z][A-Za-z0-9+.-]*")

        fun parse(response: HttpResponse): OpenId4VpDirectPostResponse {
            if (response.statusCode != 200) {
                throw WalletHttpClientException.InvalidProtocolResponse(
                    "OpenID4VP direct_post requires HTTP 200",
                )
            }
            if (response.body.size > MAXIMUM_RESPONSE_BYTES) {
                throw WalletHttpClientException.ResponseTooLarge(MAXIMUM_RESPONSE_BYTES)
            }
            if (baseMediaType(response.contentType) != UrlConnectionHttpClient.JSON_MEDIA_TYPE) {
                throw WalletHttpClientException.UnacceptableContentType(
                    UrlConnectionHttpClient.JSON_MEDIA_TYPE,
                    response.contentType,
                )
            }
            val text = strictUtf8(response.body)
                ?: throw WalletHttpClientException.InvalidProtocolResponse(
                    "OpenID4VP direct_post response is not UTF-8 JSON",
                )
            val jsonObject = try {
                json.parseToJsonElement(text) as? JsonObject
            } catch (_: SerializationException) {
                null
            } catch (_: IllegalArgumentException) {
                null
            } ?: throw WalletHttpClientException.InvalidProtocolResponse(
                "OpenID4VP direct_post response must be a JSON object",
            )
            if (!hasUniqueRedirectUriKey(text)) {
                throw WalletHttpClientException.InvalidProtocolResponse(
                    "OpenID4VP direct_post response contains duplicate redirect_uri members",
                )
            }
            val redirect = jsonObject["redirect_uri"]
                ?: return OpenId4VpDirectPostResponse(null)
            val value = (redirect as? JsonPrimitive)?.takeIf { it.isString }?.content
                ?: throw WalletHttpClientException.InvalidProtocolResponse(
                    "OpenID4VP redirect_uri must be a string",
                )
            return OpenId4VpDirectPostResponse(parseAbsoluteUri(value))
        }

        fun isUtf8(body: ByteArray): Boolean = strictUtf8(body) != null

        private fun strictUtf8(bytes: ByteArray): String? = try {
            StandardCharsets.UTF_8.newDecoder()
                .onMalformedInput(CodingErrorAction.REPORT)
                .onUnmappableCharacter(CodingErrorAction.REPORT)
                .decode(ByteBuffer.wrap(bytes))
                .toString()
        } catch (_: Exception) {
            null
        }

        private fun baseMediaType(raw: String?): String? {
            if (raw == null || ',' in raw) return null
            return raw.substringBefore(';').trim().lowercase(Locale.ROOT).ifEmpty { null }
        }

        private fun parseAbsoluteUri(value: String): URI {
            val bytes = value.toByteArray(StandardCharsets.UTF_8)
            if (
                value.isEmpty() ||
                bytes.size > MAXIMUM_REDIRECT_URI_BYTES ||
                bytes.any { it.toInt() !in 0x21..0x7e } ||
                '\\' in value ||
                !hasValidPercentEscapes(bytes)
            ) {
                throw invalidRedirect()
            }
            val uri = try {
                URI(value)
            } catch (_: Exception) {
                throw invalidRedirect()
            }
            if (!uri.isAbsolute || uri.scheme?.matches(scheme) != true) {
                throw invalidRedirect()
            }
            return uri
        }

        private fun hasValidPercentEscapes(bytes: ByteArray): Boolean {
            var index = 0
            while (index < bytes.size) {
                if (bytes[index] == '%'.code.toByte()) {
                    if (
                        index + 2 >= bytes.size ||
                        !bytes[index + 1].isAsciiHexDigit() ||
                        !bytes[index + 2].isAsciiHexDigit()
                    ) {
                        return false
                    }
                    index += 3
                } else {
                    index += 1
                }
            }
            return true
        }

        /** Reject last-member-wins ambiguity for the one response member that triggers routing. */
        private fun hasUniqueRedirectUriKey(text: String): Boolean {
            var index = 0

            fun skipWhitespace() {
                while (index < text.length && text[index] in " \t\r\n") index += 1
            }

            fun consumeStringToken(): String? {
                if (index >= text.length || text[index] != '"') return null
                val start = index
                index += 1
                var escaped = false
                while (index < text.length) {
                    val character = text[index]
                    index += 1
                    if (escaped) {
                        escaped = false
                    } else if (character == '\\') {
                        escaped = true
                    } else if (character == '"') {
                        val token = text.substring(start, index)
                        return try {
                            (json.parseToJsonElement(token) as? JsonPrimitive)
                                ?.takeIf { it.isString }
                                ?.content
                        } catch (_: Exception) {
                            null
                        }
                    }
                }
                return null
            }

            fun skipValue(): Boolean {
                var objectDepth = 0
                var arrayDepth = 0
                var inString = false
                var escaped = false
                while (index < text.length) {
                    val character = text[index]
                    if (inString) {
                        index += 1
                        if (escaped) {
                            escaped = false
                        } else if (character == '\\') {
                            escaped = true
                        } else if (character == '"') {
                            inString = false
                        }
                        continue
                    }
                    when (character) {
                        '"' -> {
                            inString = true
                            index += 1
                        }
                        '{' -> {
                            objectDepth += 1
                            index += 1
                        }
                        '[' -> {
                            arrayDepth += 1
                            index += 1
                        }
                        '}' -> {
                            if (objectDepth == 0 && arrayDepth == 0) return true
                            objectDepth -= 1
                            if (objectDepth < 0) return false
                            index += 1
                        }
                        ']' -> {
                            arrayDepth -= 1
                            if (arrayDepth < 0) return false
                            index += 1
                        }
                        ',' -> if (objectDepth == 0 && arrayDepth == 0) return true else index += 1
                        else -> index += 1
                    }
                }
                return false
            }

            skipWhitespace()
            if (index >= text.length || text[index] != '{') return false
            index += 1
            skipWhitespace()
            if (index < text.length && text[index] == '}') return true

            var redirectCount = 0
            while (index < text.length) {
                skipWhitespace()
                val key = consumeStringToken() ?: return false
                if (key == "redirect_uri") {
                    redirectCount += 1
                    if (redirectCount > 1) return false
                }
                skipWhitespace()
                if (index >= text.length || text[index] != ':') return false
                index += 1
                skipWhitespace()
                if (!skipValue()) return false
                skipWhitespace()
                if (index >= text.length) return false
                if (text[index] == ',') {
                    index += 1
                    continue
                }
                if (text[index] != '}') return false
                index += 1
                skipWhitespace()
                return index == text.length
            }
            return false
        }

        private fun Byte.isAsciiHexDigit(): Boolean {
            val character = toInt().toChar()
            return character in '0'..'9' || character in 'A'..'F' || character in 'a'..'f'
        }

        private fun invalidRedirect() = WalletHttpClientException.InvalidProtocolResponse(
            "OpenID4VP redirect_uri must be a bounded absolute URI",
        )
    }
}
