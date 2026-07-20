package eu.advatar.wallet.shell

import java.io.ByteArrayOutputStream
import java.io.InputStream
import java.net.IDN
import java.net.Inet4Address
import java.net.Inet6Address
import java.net.InetAddress
import java.net.URI
import java.util.Locale
import javax.net.ssl.HttpsURLConnection

sealed class WalletHttpClientException(message: String, cause: Throwable? = null) :
    Exception(message, cause) {
    class InvalidUrl(url: String) : WalletHttpClientException(
        "Invalid HTTPS URL (${url.length} characters)",
    )

    class UnsafeDestination(host: String) :
        WalletHttpClientException("Unsafe network destination: $host")

    class RedirectRejected(val location: String?) :
        WalletHttpClientException("HTTP redirect rejected")

    class UnacceptableContentType(
        val expected: String,
        val actual: String?,
    ) : WalletHttpClientException(
        "Unexpected HTTP Content-Type (expected $expected, received ${actual ?: "none"})",
    )

    class ResponseTooLarge(limit: Int) :
        WalletHttpClientException("HTTP response exceeded $limit bytes")

    class Transport(cause: Throwable) : WalletHttpClientException("HTTP transport failed", cause)

}

internal fun interface HostAddressResolver {
    fun resolve(host: String): List<InetAddress>
}

private object SystemHostAddressResolver : HostAddressResolver {
    override fun resolve(host: String): List<InetAddress> =
        InetAddress.getAllByName(host).toList()
}

/**
 * Validates one HTTPS destination before a connection is opened. Every DNS answer must be public;
 * empty, excessive, and mixed public/private answer sets are rejected.
 *
 * This is only a DNS preflight. [HttpsURLConnection] performs its own lookup while connecting, so
 * this class does not pin the validated address to the TLS socket and does not eliminate DNS
 * time-of-check/time-of-use attacks.
 */
class ProductionUrlPolicy internal constructor(
    private val resolver: HostAddressResolver,
) {
    constructor() : this(SystemHostAddressResolver)

    fun validate(url: String): URI {
        if (
            url.length > MAXIMUM_URL_BYTES ||
            url.toByteArray(Charsets.UTF_8).size > MAXIMUM_URL_BYTES ||
            url.any { it.code !in 0x21..0x7e } ||
            '\\' in url
        ) {
            throw WalletHttpClientException.InvalidUrl(url)
        }

        val uri = try {
            URI(url)
        } catch (_: Exception) {
            throw WalletHttpClientException.InvalidUrl(url)
        }
        val host = uri.host?.removePrefix("[")?.removeSuffix("]")
        val port = uri.port
        val portIsAllowed = port == -1 || port in 1..65_535 && port != DEFAULT_HTTPS_PORT
        if (
            !uri.isAbsolute ||
            uri.isOpaque ||
            uri.scheme != "https" ||
            host.isNullOrBlank() ||
            uri.rawUserInfo != null ||
            uri.fragment != null ||
            !portIsAllowed ||
            uri.rawAuthority?.contains('%') != false
        ) {
            throw WalletHttpClientException.InvalidUrl(url)
        }

        val canonicalHost = canonicalHost(host)
            ?: throw WalletHttpClientException.UnsafeDestination(host)
        if (host != canonicalHost || uri.rawAuthority != canonicalAuthority(canonicalHost, port)) {
            throw WalletHttpClientException.InvalidUrl(url)
        }

        val literalAddress = parseLiteralAddress(canonicalHost)
        if (literalAddress != null) {
            if (
                literalAddress is Inet6Address &&
                renderCanonicalIpv6(literalAddress.address) != canonicalHost
            ) {
                throw WalletHttpClientException.InvalidUrl(url)
            }
            if (!literalAddress.isPublicWalletDestination()) {
                throw WalletHttpClientException.UnsafeDestination(canonicalHost)
            }
            return uri
        }

        val addresses = try {
            resolver.resolve(canonicalHost)
        } catch (_: Exception) {
            throw WalletHttpClientException.UnsafeDestination(canonicalHost)
        }
        if (
            addresses.isEmpty() ||
            addresses.size > MAXIMUM_DNS_ADDRESSES ||
            addresses.any { !it.isPublicWalletDestination() }
        ) {
            throw WalletHttpClientException.UnsafeDestination(canonicalHost)
        }
        return uri
    }

    private fun canonicalHost(host: String): String? {
        if (!host.isAscii() || host.any { it.isWhitespace() || it.isISOControl() }) return null
        val lower = host.lowercase(Locale.ROOT)
        if (
            lower == "localhost" ||
            lower.endsWith(".localhost") ||
            lower.endsWith(".local") ||
            lower.endsWith('.')
        ) {
            return null
        }
        if (':' in lower) {
            // URI has already required brackets around the literal. The address parser below
            // validates its syntax and rejects mapped/compatible aliases.
            return lower
        }

        val ascii = try {
            IDN.toASCII(lower, IDN.USE_STD3_ASCII_RULES)
        } catch (_: IllegalArgumentException) {
            return null
        }
        if (ascii != lower || ascii.length > MAXIMUM_HOST_BYTES) return null

        // Never let platform-specific integer/octal/short IPv4 spellings reach DNS or URL parsing.
        if (ascii.all { it.isDigit() || it == '.' }) {
            val labels = ascii.split('.')
            if (
                labels.size != 4 ||
                labels.any { label ->
                    label.isEmpty() ||
                        label.length > 1 && label.startsWith('0') ||
                        label.toIntOrNull()?.let { it !in 0..255 } != false
                }
            ) {
                return null
            }
            return ascii
        }

        val labels = ascii.split('.')
        if (
            labels.size < 2 ||
            labels.any { label ->
                label.isEmpty() ||
                    label.length > MAXIMUM_HOST_LABEL_BYTES ||
                    label.startsWith('-') ||
                    label.endsWith('-') ||
                    label.any { !(it.isLetterOrDigit() || it == '-') } ||
                    !isCanonicalPunycodeLabel(label)
            }
        ) {
            return null
        }
        return ascii
    }

    private fun isCanonicalPunycodeLabel(label: String): Boolean {
        if (!label.startsWith("xn--")) return true
        val unicode = IDN.toUnicode(label)
        if (unicode == label) return false
        return try {
            IDN.toASCII(unicode, IDN.USE_STD3_ASCII_RULES).lowercase(Locale.ROOT) == label
        } catch (_: IllegalArgumentException) {
            false
        }
    }

    private fun canonicalAuthority(host: String, port: Int): String {
        val renderedHost = if (':' in host) "[$host]" else host
        return if (port == -1) renderedHost else "$renderedHost:$port"
    }

    private fun parseLiteralAddress(host: String): InetAddress? {
        if (':' !in host && !host.all { it.isDigit() || it == '.' }) return null
        val address = try {
            InetAddress.getByName(host)
        } catch (_: Exception) {
            throw WalletHttpClientException.UnsafeDestination(host)
        }
        // Java represents IPv4-mapped IPv6 literals as Inet4Address. Rejecting the alias avoids
        // two textual address families being treated differently by later network layers.
        if (':' in host && address !is Inet6Address) {
            throw WalletHttpClientException.UnsafeDestination(host)
        }
        return address
    }

    private fun renderCanonicalIpv6(bytes: ByteArray): String {
        val words = List(8) { index ->
            val offset = index * 2
            ((bytes[offset].toInt() and 0xff) shl 8) or
                (bytes[offset + 1].toInt() and 0xff)
        }
        var bestStart = -1
        var bestLength = 0
        var index = 0
        while (index < words.size) {
            if (words[index] != 0) {
                index += 1
                continue
            }
            val start = index
            while (index < words.size && words[index] == 0) index += 1
            val length = index - start
            if (length >= 2 && length > bestLength) {
                bestStart = start
                bestLength = length
            }
        }
        if (bestStart == -1) return words.joinToString(":") { it.toString(16) }

        val before = words.take(bestStart).joinToString(":") { it.toString(16) }
        val after = words.drop(bestStart + bestLength).joinToString(":") { it.toString(16) }
        return when {
            before.isEmpty() && after.isEmpty() -> "::"
            before.isEmpty() -> "::$after"
            after.isEmpty() -> "$before::"
            else -> "$before::$after"
        }
    }

    companion object {
        const val MAXIMUM_URL_BYTES = 4_096
        const val MAXIMUM_DNS_ADDRESSES = 32
        private const val DEFAULT_HTTPS_PORT = 443
        private const val MAXIMUM_HOST_BYTES = 253
        private const val MAXIMUM_HOST_LABEL_BYTES = 63
    }
}

private fun String.isAscii(): Boolean = all { it.code in 0..0x7f }

private fun InetAddress.isPublicWalletDestination(): Boolean {
    if (
        isAnyLocalAddress ||
        isLoopbackAddress ||
        isLinkLocalAddress ||
        isSiteLocalAddress ||
        isMulticastAddress
    ) {
        return false
    }
    val address = address
    return when (this) {
        is Inet4Address -> isPublicIpv4(address)
        is Inet6Address -> isPublicIpv6(address)
        else -> false
    }
}

private fun isPublicIpv4(bytes: ByteArray): Boolean {
    if (bytes.size != 4) return false
    val a = bytes[0].toInt() and 0xff
    val b = bytes[1].toInt() and 0xff
    val c = bytes[2].toInt() and 0xff
    // Wallet protocol endpoints must be ordinary public unicast destinations. This deliberately
    // rejects every IANA special-purpose block, including anycast blocks whose registry entry is
    // marked globally reachable, rather than trying to maintain per-protocol exceptions.
    return when {
        a == 0 || a == 10 || a == 127 -> false
        a == 100 && b in 64..127 -> false // carrier-grade NAT
        a == 169 && b == 254 -> false
        a == 172 && b in 16..31 -> false
        a == 192 && b == 0 && c == 0 -> false
        a == 192 && b == 0 && c == 2 -> false // documentation
        a == 192 && b == 31 && c == 196 -> false // AS112-v4
        a == 192 && b == 52 && c == 193 -> false // AMT
        a == 192 && b == 88 && c == 99 -> false
        a == 192 && b == 168 -> false
        a == 192 && b == 175 && c == 48 -> false // Direct Delegation AS112
        a == 198 && b in 18..19 -> false // benchmark networks
        a == 198 && b == 51 && c == 100 -> false // documentation
        a == 203 && b == 0 && c == 113 -> false // documentation
        a >= 224 -> false
        else -> true
    }
}

private fun isPublicIpv6(bytes: ByteArray): Boolean {
    if (bytes.size != 16) return false
    val first = bytes[0].toInt() and 0xff
    val second = bytes[1].toInt() and 0xff
    // Current RIR/global allocations are in 2000::/4. IANA still reserves 3000::/5, so accepting
    // the historical wider 2000::/3 definition would admit presently non-global destinations.
    if (first !in 0x20..0x2f) return false
    if (first == 0x20 && second == 0x01) {
        val third = bytes[2].toInt() and 0xff
        val fourth = bytes[3].toInt() and 0xff
        if (third == 0x00 && fourth == 0x02) return false // benchmark
        if (third <= 0x01) return false // IETF protocol assignments in 2001::/23
        if (third == 0x0d && fourth == 0xb8) return false // documentation
    }
    if (first == 0x20 && second == 0x02) return false // 6to4 can tunnel non-public IPv4
    if (
        first == 0x26 &&
        second == 0x20 &&
        bytes[2] == 0.toByte() &&
        bytes[3] == 0x4f.toByte() &&
        bytes[4] == 0x80.toByte() &&
        bytes[5] == 0.toByte()
    ) {
        return false // Direct Delegation AS112 service
    }
    return true
}

internal fun interface HttpsConnectionFactory {
    fun open(uri: URI): HttpsURLConnection
}

private object SystemHttpsConnectionFactory : HttpsConnectionFactory {
    override fun open(uri: URI): HttpsURLConnection =
        uri.toURL().openConnection() as? HttpsURLConnection
            ?: throw WalletHttpClientException.InvalidUrl(uri.toString())
}

/** Blocking HTTPS transport; callers must invoke the executor from a worker thread. */
class UrlConnectionHttpClient internal constructor(
    private val timeoutMilliseconds: Int,
    private val maximumResponseBytes: Int,
    private val urlPolicy: ProductionUrlPolicy,
    private val connectionFactory: HttpsConnectionFactory,
) : WalletHttpClient {
    constructor(
        timeoutMilliseconds: Int = DEFAULT_TIMEOUT_MILLISECONDS,
        maximumResponseBytes: Int = DEFAULT_MAXIMUM_RESPONSE_BYTES,
    ) : this(
        timeoutMilliseconds,
        maximumResponseBytes,
        ProductionUrlPolicy(),
        SystemHttpsConnectionFactory,
    )

    init {
        require(timeoutMilliseconds > 0) { "timeoutMilliseconds must be positive" }
        require(maximumResponseBytes > 0) { "maximumResponseBytes must be positive" }
    }

    /**
     * Posts a core-owned payload. The current effect contract mixes OID4VP, payment, and QES
     * deliveries and carries no response-media profile, so this generic boundary does not parse or
     * assert a response MIME. Destination, redirect, timeout, and body-size policy still apply.
     */
    override fun post(url: String, body: ByteArray): HttpResponse =
        execute(
            url = url,
            method = "POST",
            body = body,
            accept = ACCEPT_ANY_MEDIA_TYPE,
            expectedContentTypes = null,
            responseLimit = maximumResponseBytes,
        )

    /** Derives and fetches an OpenID4VCI issuer's unsigned JSON metadata endpoint. */
    fun fetchIssuerMetadata(issuer: String): HttpResponse {
        val issuerUri = urlPolicy.validate(issuer)
        if (issuerUri.rawQuery != null) {
            throw WalletHttpClientException.InvalidUrl(issuer)
        }
        val issuerPath = issuerUri.rawPath.orEmpty().let { if (it == "/") "" else it }
        val metadataUrl =
            "https://${issuerUri.rawAuthority}/.well-known/openid-credential-issuer$issuerPath"
        return getJson(metadataUrl, ISSUER_METADATA_MAXIMUM_BYTES)
    }

    /** Fetches a Token Status List using its registered JWT media type. */
    fun fetchStatusList(url: String): HttpResponse =
        get(
            url = url,
            acceptedContentTypes = setOf(STATUS_LIST_MEDIA_TYPE),
            protocolLimit = STATUS_LIST_MAXIMUM_BYTES,
        )

    /** Fetches the JSON object referenced by an OpenID4VCI `credential_offer_uri`. */
    fun fetchCredentialOffer(url: String): HttpResponse =
        getJson(url, CREDENTIAL_OFFER_MAXIMUM_BYTES)

    /** Fetches the signed Request Object referenced by an OpenID4VP `request_uri`. */
    fun fetchPresentationRequest(url: String): HttpResponse =
        get(
            url = url,
            acceptedContentTypes = REQUEST_OBJECT_MEDIA_TYPES,
            protocolLimit = REQUEST_OBJECT_MAXIMUM_BYTES,
        )

    private fun getJson(url: String, protocolLimit: Int): HttpResponse =
        get(
            url = url,
            acceptedContentTypes = setOf(JSON_MEDIA_TYPE),
            protocolLimit = protocolLimit,
        )

    private fun get(
        url: String,
        acceptedContentTypes: Set<String>,
        protocolLimit: Int,
    ): HttpResponse = execute(
        url = url,
        method = "GET",
        body = null,
        accept = acceptedContentTypes.sorted().joinToString(", "),
        expectedContentTypes = acceptedContentTypes,
        responseLimit = minOf(maximumResponseBytes, protocolLimit),
    )

    private fun execute(
        url: String,
        method: String,
        body: ByteArray?,
        accept: String,
        expectedContentTypes: Set<String>?,
        responseLimit: Int,
    ): HttpResponse {
        val uri = urlPolicy.validate(url)
        val connection = try {
            connectionFactory.open(uri)
        } catch (error: WalletHttpClientException) {
            throw error
        } catch (error: Exception) {
            throw WalletHttpClientException.Transport(error)
        }

        return try {
            connection.instanceFollowRedirects = false
            connection.connectTimeout = timeoutMilliseconds
            connection.readTimeout = timeoutMilliseconds
            connection.requestMethod = method
            connection.doOutput = body != null
            connection.useCaches = false
            connection.setRequestProperty("Accept", accept)
            if (body != null) {
                connection.setRequestProperty("Content-Type", contentType(body))
                connection.setFixedLengthStreamingMode(body.size)
                connection.outputStream.use { output -> output.write(body) }
            }

            val statusCode = connection.responseCode
            if (statusCode in 300..399) {
                throw WalletHttpClientException.RedirectRejected(
                    connection.getHeaderField("Location"),
                )
            }
            val declaredLength = connection.contentLengthLong
            if (declaredLength > responseLimit) {
                throw WalletHttpClientException.ResponseTooLarge(responseLimit)
            }
            val responseHasNoContent = statusCode == 204 || statusCode == 205
            if (expectedContentTypes != null) {
                val rawContentType = responseContentType(connection)
                val actualContentType = baseMediaType(rawContentType)
                if (actualContentType !in expectedContentTypes) {
                    throw WalletHttpClientException.UnacceptableContentType(
                        expectedContentTypes.sorted().joinToString(", "),
                        rawContentType,
                    )
                }
            }
            val stream = if (responseHasNoContent) {
                null
            } else if (statusCode in 200..299) {
                connection.inputStream
            } else {
                connection.errorStream
            }
            HttpResponse(statusCode, readBody(stream, responseLimit))
        } catch (error: WalletHttpClientException) {
            throw error
        } catch (error: Exception) {
            throw WalletHttpClientException.Transport(error)
        } finally {
            connection.disconnect()
        }
    }

    internal fun readBody(
        stream: InputStream?,
        limit: Int = maximumResponseBytes,
    ): ByteArray {
        require(limit > 0) { "limit must be positive" }
        if (stream == null) return ByteArray(0)
        return stream.use { input ->
            val output = ByteArrayOutputStream()
            val buffer = ByteArray(DEFAULT_BUFFER_SIZE)
            while (true) {
                val read = input.read(buffer)
                if (read < 0) break
                if (read > limit - output.size()) {
                    throw WalletHttpClientException.ResponseTooLarge(limit)
                }
                output.write(buffer, 0, read)
            }
            output.toByteArray()
        }
    }

    private fun baseMediaType(raw: String?): String? {
        if (raw == null || ',' in raw) return null
        return raw.substringBefore(';').trim().lowercase(Locale.ROOT).ifEmpty { null }
    }

    private fun responseContentType(connection: HttpsURLConnection): String? {
        val values = connection.headerFields.entries
            .filter { (name, _) -> name.equals("Content-Type", ignoreCase = true) }
            .flatMap { it.value }
        return when (values.size) {
            0 -> connection.getHeaderField("Content-Type")
            1 -> values.single()
            else -> values.joinToString(", ")
        }
    }

    private fun contentType(body: ByteArray): String {
        val first = body.firstOrNull { byte ->
            byte != ' '.code.toByte() &&
                byte != '\t'.code.toByte() &&
                byte != '\r'.code.toByte() &&
                byte != '\n'.code.toByte()
        }
        return if (first == '{'.code.toByte() || first == '['.code.toByte()) {
            JSON_MEDIA_TYPE
        } else {
            FORM_MEDIA_TYPE
        }
    }

    companion object {
        const val DEFAULT_TIMEOUT_MILLISECONDS = 30_000
        const val DEFAULT_MAXIMUM_RESPONSE_BYTES = 1_048_576
        const val ISSUER_METADATA_MAXIMUM_BYTES = 512 * 1_024
        const val CREDENTIAL_OFFER_MAXIMUM_BYTES = 256 * 1_024
        const val REQUEST_OBJECT_MAXIMUM_BYTES = 512 * 1_024
        const val STATUS_LIST_MAXIMUM_BYTES = 2 * 1_024 * 1_024

        const val JSON_MEDIA_TYPE = "application/json"
        const val JWT_MEDIA_TYPE = "application/jwt"
        const val STATUS_LIST_MEDIA_TYPE = "application/statuslist+jwt"
        const val REQUEST_OBJECT_MEDIA_TYPE = "application/oauth-authz-req+jwt"
        val REQUEST_OBJECT_MEDIA_TYPES: Set<String> =
            setOf(JWT_MEDIA_TYPE, REQUEST_OBJECT_MEDIA_TYPE)
        private const val ACCEPT_ANY_MEDIA_TYPE = "*/*"
        private const val FORM_MEDIA_TYPE = "application/x-www-form-urlencoded"
    }
}
