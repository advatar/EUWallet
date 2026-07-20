package eu.advatar.wallet.shell

import java.io.ByteArrayOutputStream
import java.io.InputStream
import java.net.IDN
import java.net.Inet4Address
import java.net.Inet6Address
import java.net.InetAddress
import java.net.URI
import javax.net.ssl.HttpsURLConnection

sealed class WalletHttpClientException(message: String, cause: Throwable? = null) :
    Exception(message, cause) {
    class InvalidUrl(url: String) : WalletHttpClientException("Invalid HTTPS URL: $url")

    class UnsafeDestination(host: String) :
        WalletHttpClientException("Unsafe network destination: $host")

    class ResponseTooLarge(limit: Int) :
        WalletHttpClientException("HTTP response exceeded $limit bytes")

    class Transport(cause: Throwable) : WalletHttpClientException("HTTP transport failed", cause)
}

fun interface HostAddressResolver {
    fun resolve(host: String): List<InetAddress>
}

private object SystemHostAddressResolver : HostAddressResolver {
    override fun resolve(host: String): List<InetAddress> =
        InetAddress.getAllByName(host).toList()
}

/**
 * Validates one HTTPS destination before a connection is opened. Every DNS answer must be public;
 * a mixed public/private answer is rejected. `HttpsURLConnection` performs its own connection-time
 * lookup, so a production network stack must additionally bind this validated answer to the
 * socket to eliminate the remaining DNS time-of-check/time-of-use window.
 */
class ProductionUrlPolicy(
    private val resolver: HostAddressResolver = SystemHostAddressResolver,
) {
    fun validate(url: String): URI {
        val uri = try {
            URI(url)
        } catch (error: Exception) {
            throw WalletHttpClientException.InvalidUrl(url)
        }
        val host = uri.host?.removePrefix("[")?.removeSuffix("]")
        val portIsValid = uri.port == -1 || uri.port in 1..65_535
        if (
            !uri.isAbsolute ||
            uri.isOpaque ||
            uri.scheme != "https" ||
            host.isNullOrBlank() ||
            uri.userInfo != null ||
            uri.fragment != null ||
            !portIsValid ||
            uri.rawAuthority?.contains('%') == true ||
            uri.rawPath?.contains('\\') == true
        ) {
            throw WalletHttpClientException.InvalidUrl(url)
        }

        val canonicalHost = canonicalHost(host)
            ?: throw WalletHttpClientException.UnsafeDestination(host)
        val addresses = try {
            resolver.resolve(canonicalHost)
        } catch (_: Exception) {
            throw WalletHttpClientException.UnsafeDestination(canonicalHost)
        }
        if (addresses.isEmpty() || addresses.any { !it.isPublicWalletDestination() }) {
            throw WalletHttpClientException.UnsafeDestination(canonicalHost)
        }
        return uri
    }

    private fun canonicalHost(host: String): String? {
        if (!host.isAscii() || host.any { it.isWhitespace() || it.isISOControl() }) return null
        val lower = host.lowercase()
        if (
            lower == "localhost" ||
            lower.endsWith(".localhost") ||
            lower.endsWith(".local") ||
            lower.endsWith('.')
        ) {
            return null
        }
        if (':' in lower) return lower // A literal IPv6 address; address policy decides its scope.

        val ascii = try {
            IDN.toASCII(lower, IDN.USE_STD3_ASCII_RULES)
        } catch (_: IllegalArgumentException) {
            return null
        }
        if (ascii != lower || ascii.length > 253) return null

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
                    label.length > 63 ||
                    label.startsWith('-') ||
                    label.endsWith('-') ||
                    label.any { !(it.isLetterOrDigit() || it == '-') }
            }
        ) {
            return null
        }
        return ascii
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
    return when {
        a == 0 || a == 10 || a == 127 -> false
        a == 100 && b in 64..127 -> false // carrier-grade NAT
        a == 169 && b == 254 -> false
        a == 172 && b in 16..31 -> false
        a == 192 && b == 0 && c == 0 -> false
        a == 192 && b == 0 && c == 2 -> false // documentation
        a == 192 && b == 88 && c == 99 -> false
        a == 192 && b == 168 -> false
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
    // Conservatively allow only global-unicast 2000::/3, then remove special transition/test nets.
    if (first !in 0x20..0x3f) return false
    if (first == 0x20 && second == 0x01) {
        val third = bytes[2].toInt() and 0xff
        val fourth = bytes[3].toInt() and 0xff
        if (third == 0x0d && fourth == 0xb8) return false // documentation
        if (third == 0x00 && fourth == 0x00) return false // Teredo/special-purpose
        if (third == 0x00 && fourth == 0x02) return false // benchmark
    }
    if (first == 0x20 && second == 0x02) return false // 6to4 can tunnel non-public IPv4
    if (first == 0x3f && second == 0xff && (bytes[2].toInt() and 0xf0) == 0) {
        return false // documentation prefix 3fff:0000::/20
    }
    return true
}

/** Blocking HTTPS transport; callers must invoke the executor from a worker thread. */
class UrlConnectionHttpClient(
    private val timeoutMilliseconds: Int = 30_000,
    private val maximumResponseBytes: Int = 1_048_576,
    private val urlPolicy: ProductionUrlPolicy = ProductionUrlPolicy(),
) : WalletHttpClient {
    init {
        require(timeoutMilliseconds > 0) { "timeoutMilliseconds must be positive" }
        require(maximumResponseBytes > 0) { "maximumResponseBytes must be positive" }
    }

    override fun post(url: String, body: ByteArray): HttpResponse {
        val uri = urlPolicy.validate(url)

        val connection = try {
            uri.toURL().openConnection() as? HttpsURLConnection
                ?: throw WalletHttpClientException.InvalidUrl(url)
        } catch (error: WalletHttpClientException) {
            throw error
        } catch (error: Exception) {
            throw WalletHttpClientException.Transport(error)
        }

        return try {
            connection.instanceFollowRedirects = false
            connection.connectTimeout = timeoutMilliseconds
            connection.readTimeout = timeoutMilliseconds
            connection.requestMethod = "POST"
            connection.doOutput = true
            connection.useCaches = false
            connection.setRequestProperty("Accept", "application/json")
            connection.setRequestProperty("Content-Type", contentType(body))
            connection.setFixedLengthStreamingMode(body.size)
            connection.outputStream.use { output -> output.write(body) }

            val statusCode = connection.responseCode
            val declaredLength = connection.contentLengthLong
            if (declaredLength > maximumResponseBytes) {
                throw WalletHttpClientException.ResponseTooLarge(maximumResponseBytes)
            }
            val stream = if (statusCode in 200..299) {
                connection.inputStream
            } else {
                connection.errorStream
            }
            HttpResponse(statusCode, readBody(stream))
        } catch (error: WalletHttpClientException) {
            throw error
        } catch (error: Exception) {
            throw WalletHttpClientException.Transport(error)
        } finally {
            connection.disconnect()
        }
    }

    internal fun readBody(stream: InputStream?): ByteArray {
        if (stream == null) return ByteArray(0)
        return stream.use { input ->
            val output = ByteArrayOutputStream()
            val buffer = ByteArray(DEFAULT_BUFFER_SIZE)
            while (true) {
                val read = input.read(buffer)
                if (read < 0) break
                if (output.size() + read > maximumResponseBytes) {
                    throw WalletHttpClientException.ResponseTooLarge(maximumResponseBytes)
                }
                output.write(buffer, 0, read)
            }
            output.toByteArray()
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
            "application/json"
        } else {
            "application/x-www-form-urlencoded"
        }
    }
}
