package eu.advatar.wallet.shell

import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream
import java.io.InputStream
import java.net.InetAddress
import java.net.URI
import java.net.URL
import javax.net.ssl.HttpsURLConnection
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Test

class UrlConnectionHttpClientTest {
    @Test
    fun rejectsNonCanonicalOrAmbiguousUrlsBeforeNetworkAccess() {
        var resolutions = 0
        val policy = ProductionUrlPolicy {
            resolutions += 1
            listOf(ipv4(93, 184, 216, 34))
        }

        listOf(
            "http://rp.example",
            "/relative/path",
            "HTTPS://rp.example/callback",
            "https://RP.example/callback",
            "https://user:pass@rp.example",
            "https://user%40rp.example@evil.example/callback",
            "https://%72p.example/callback",
            "https://rp.example/callback#fragment",
            "https://rp.example:0/callback",
            "https://rp.example:443/callback",
            "https://rp.example:08443/callback",
            "https://rp.example:65536/callback",
            "https://rp.example:/callback",
            "https://rp.example:not-a-port/callback",
            "https://rp.example\\@127.0.0.1/callback",
            "https://rp.example/path\\segment",
            "https://rp.example/café",
            "not a url",
            "https://rp.example/" + "a".repeat(ProductionUrlPolicy.MAXIMUM_URL_BYTES),
            "https://rp.example/" + "é".repeat(2_040),
        ).forEach { url ->
            assertThrows(url, WalletHttpClientException.InvalidUrl::class.java) {
                policy.validate(url)
            }
        }

        assertEquals(0, resolutions)
    }

    @Test
    fun rejectsSingleLabelLocalAndAmbiguousNumericHosts() {
        val policy = publicPolicy()

        listOf(
            "https://localhost/callback",
            "https://service.localhost/callback",
            "https://service.local/callback",
            "https://single-label/callback",
            "https://wallet.example./callback",
            "https://wallet..example/callback",
            "https://xn--a.example/callback",
            "https://münich.example/callback",
            "https://0177.0.0.1/callback",
            "https://127.1/callback",
            "https://2130706433/callback",
            "https://0x7f000001/callback",
        ).forEach { url ->
            assertThrows(url, WalletHttpClientException::class.java) {
                policy.validate(url)
            }
        }
    }

    @Test
    fun rejectsPrivateReservedAndAliasedLiteralAddressesWithoutConsultingDns() {
        var resolutions = 0
        val policy = ProductionUrlPolicy {
            resolutions += 1
            listOf(ipv4(93, 184, 216, 34))
        }
        val unsafeAddresses = listOf(
            "0.0.0.0",
            "10.0.0.1",
            "100.64.0.1",
            "127.0.0.1",
            "169.254.1.1",
            "172.16.0.1",
            "192.0.0.1",
            "192.0.2.1",
            "192.31.196.1",
            "192.52.193.1",
            "192.88.99.1",
            "192.168.1.1",
            "192.175.48.1",
            "198.18.0.1",
            "198.51.100.1",
            "203.0.113.1",
            "224.0.0.1",
            "240.0.0.1",
            "255.255.255.255",
            "[::]",
            "[::1]",
            "[::ffff:127.0.0.1]",
            "[fc00::1]",
            "[fe80::1]",
            "[ff02::1]",
            "[2001::1]",
            "[2001:2::1]",
            "[2001:10::1]",
            "[2001:db8::1]",
            "[2002:808:808::1]",
            "[2620:4f:8000::1]",
            "[3000::1]",
            "[3fff::1]",
        )

        unsafeAddresses.forEach { address ->
            assertThrows(address, WalletHttpClientException.UnsafeDestination::class.java) {
                policy.validate("https://$address/status")
            }
        }
        assertEquals(0, resolutions)
    }

    @Test
    fun rejectsEmptyMixedPrivateAndOverBudgetDnsAnswers() {
        val empty = ProductionUrlPolicy { emptyList() }
        assertUnsafe(empty)

        val mixed = ProductionUrlPolicy {
            listOf(ipv4(93, 184, 216, 34), ipv4(127, 0, 0, 1))
        }
        assertUnsafe(mixed)

        val overBudget = ProductionUrlPolicy {
            List(ProductionUrlPolicy.MAXIMUM_DNS_ADDRESSES + 1) {
                ipv4(93, 184, 216, 34)
            }
        }
        assertUnsafe(overBudget)

        val malformed = ProductionUrlPolicy {
            listOf(InetAddress.getByAddress(byteArrayOf(1, 2, 3)))
        }
        assertUnsafe(malformed)
    }

    @Test
    fun acceptsCanonicalPublicDnsAndLiteralDestinations() {
        val policy = ProductionUrlPolicy {
            listOf(
                ipv4(93, 184, 216, 34),
                InetAddress.getByName("2606:4700:4700::1111"),
            )
        }
        assertEquals(
            URI("https://wallet.example:8443/callback?state=one"),
            policy.validate("https://wallet.example:8443/callback?state=one"),
        )
        policy.validate("https://xn--mnich-kva.example/credential-offer")
        val prefix = "https://wallet.example/"
        policy.validate(prefix + "a".repeat(ProductionUrlPolicy.MAXIMUM_URL_BYTES - prefix.length))

        val noDns = ProductionUrlPolicy { throw AssertionError("literal address used DNS") }
        noDns.validate("https://93.184.216.34/callback")
        noDns.validate("https://[2606:4700:4700::1111]/callback")
        assertThrows(WalletHttpClientException.InvalidUrl::class.java) {
            noDns.validate("https://[2606:4700:4700:0:0:0:0:1111]/callback")
        }
    }

    @Test
    fun appliesUrlAndDnsPolicyBeforeBothPostAndProtocolGet() {
        var opened = 0
        val factory = HttpsConnectionFactory {
            opened += 1
            FakeHttpsURLConnection(it.toURL())
        }
        val client = client(
            connectionFactory = factory,
            policy = publicPolicy(),
        )

        assertThrows(WalletHttpClientException.UnsafeDestination::class.java) {
            client.post("https://127.0.0.1/submit", ByteArray(0))
        }
        assertThrows(WalletHttpClientException.UnsafeDestination::class.java) {
            client.fetchCredentialOffer("https://single-label/offer")
        }
        assertEquals(0, opened)
    }

    @Test
    fun postPreservesPublicApiAndConfiguresARestrictedConnection() {
        val fake = FakeHttpsURLConnection(
            URL("https://wallet.example/submit"),
            responseContentType = UrlConnectionHttpClient.JSON_MEDIA_TYPE,
            responseBody = "ok".encodeToByteArray(),
        )
        val client = client(fake)
        val requestBody = "  {\"vp_token\":\"value\"}".encodeToByteArray()

        val response = client.post("https://wallet.example/submit", requestBody)

        assertEquals(200, response.statusCode)
        assertArrayEquals("ok".encodeToByteArray(), response.body)
        assertEquals("POST", fake.requestMethod)
        assertEquals("*/*", fake.getRequestProperty("Accept"))
        assertEquals("application/json", fake.getRequestProperty("Content-Type"))
        assertArrayEquals(requestBody, fake.requestBody.toByteArray())
        assertFalse(fake.instanceFollowRedirects)
        assertFalse(fake.useCaches)
        assertTrue(fake.doOutput)
        assertEquals(30_000, fake.connectTimeout)
        assertEquals(30_000, fake.readTimeout)
        assertTrue(fake.disconnected)
    }

    @Test
    fun postLeavesMixedProtocolResponseMimeUntypedAndAllowsBodylessNoContent() {
        val represented = FakeHttpsURLConnection(
            URL("https://wallet.example/token"),
            responseContentType = "text/html",
            responseBody = "error".encodeToByteArray(),
        )
        val representedResponse =
            client(represented).post("https://wallet.example/token", ByteArray(0))
        assertArrayEquals("error".encodeToByteArray(), representedResponse.body)
        assertTrue(represented.inputRequested)

        val noContent = FakeHttpsURLConnection(
            URL("https://wallet.example/notification"),
            responseCodeValue = 204,
        )
        val response = client(noContent).post(
            "https://wallet.example/notification",
            "{}".encodeToByteArray(),
        )
        assertEquals(204, response.statusCode)
        assertEquals(0, response.body.size)
        assertFalse(noContent.inputRequested)
        assertTrue(noContent.disconnected)
    }

    @Test
    fun protocolGetHelpersSendExactAcceptHeadersAndRequireExactBaseMediaTypes() {
        data class Endpoint(
            val mediaTypes: Set<String>,
            val fetch: (UrlConnectionHttpClient, String) -> HttpResponse,
        )

        val endpoints = listOf(
            Endpoint(setOf(UrlConnectionHttpClient.JSON_MEDIA_TYPE)) { client, url ->
                client.fetchIssuerMetadata(url)
            },
            Endpoint(setOf(UrlConnectionHttpClient.STATUS_LIST_MEDIA_TYPE)) { client, url ->
                client.fetchStatusList(url)
            },
            Endpoint(setOf(UrlConnectionHttpClient.JSON_MEDIA_TYPE)) { client, url ->
                client.fetchCredentialOffer(url)
            },
            Endpoint(UrlConnectionHttpClient.REQUEST_OBJECT_MEDIA_TYPES) { client, url ->
                client.fetchPresentationRequest(url)
            },
        )

        endpoints.forEach { endpoint ->
            val returnedMediaType = endpoint.mediaTypes.sorted().first()
            val fake = FakeHttpsURLConnection(
                URL("https://wallet.example/resource"),
                responseContentType = returnedMediaType.uppercase() + "; charset=UTF-8",
                responseBody = byteArrayOf(1, 2, 3),
            )
            val response = endpoint.fetch(client(fake), "https://wallet.example/resource")

            assertArrayEquals(byteArrayOf(1, 2, 3), response.body)
            assertEquals("GET", fake.requestMethod)
            assertEquals(
                endpoint.mediaTypes.sorted().joinToString(", "),
                fake.getRequestProperty("Accept"),
            )
            assertFalse(fake.doOutput)
            assertFalse(fake.instanceFollowRedirects)
            assertTrue(fake.disconnected)
        }
    }

    @Test
    fun acceptsBothStandardsValidRequestObjectMediaTypes() {
        UrlConnectionHttpClient.REQUEST_OBJECT_MEDIA_TYPES.forEach { mediaType ->
            val fake = FakeHttpsURLConnection(
                URL("https://wallet.example/request"),
                responseContentType = mediaType,
                responseBody = "signed.jwt.value".encodeToByteArray(),
            )
            val response = client(fake)
                .fetchPresentationRequest("https://wallet.example/request")
            assertArrayEquals("signed.jwt.value".encodeToByteArray(), response.body)
        }
    }

    @Test
    fun derivesIssuerMetadataWellKnownUrlAndRejectsIssuerQueries() {
        val fake = FakeHttpsURLConnection(
            URL("https://issuer.example/.well-known/openid-credential-issuer/tenant"),
            responseContentType = UrlConnectionHttpClient.JSON_MEDIA_TYPE,
            responseBody = "{}".encodeToByteArray(),
        )
        var openedUri: URI? = null
        val client = client(
            connectionFactory = HttpsConnectionFactory { uri ->
                openedUri = uri
                fake
            },
        )

        client.fetchIssuerMetadata("https://issuer.example:8443/tenant")
        assertEquals(
            URI("https://issuer.example:8443/.well-known/openid-credential-issuer/tenant"),
            openedUri,
        )

        openedUri = null
        assertThrows(WalletHttpClientException.InvalidUrl::class.java) {
            client.fetchIssuerMetadata("https://issuer.example/tenant?configuration=pid")
        }
        assertEquals(null, openedUri)
    }

    @Test
    fun protocolGetRejectsMissingWrongAndAmbiguousContentTypes() {
        listOf(null, "text/html", "application/json, text/html").forEach { contentType ->
            val fake = FakeHttpsURLConnection(
                URL("https://wallet.example/offer"),
                responseContentType = contentType,
                responseBody = byteArrayOf(1),
            )

            val error = assertThrows(
                WalletHttpClientException.UnacceptableContentType::class.java,
            ) {
                client(fake).fetchCredentialOffer("https://wallet.example/offer")
            }
            assertEquals(UrlConnectionHttpClient.JSON_MEDIA_TYPE, error.expected)
            assertEquals(contentType, error.actual)
            assertFalse(fake.inputRequested)
            assertTrue(fake.disconnected)
        }

        val bodylessGet = FakeHttpsURLConnection(
            URL("https://wallet.example/offer"),
            responseCodeValue = 204,
        )
        assertThrows(WalletHttpClientException.UnacceptableContentType::class.java) {
            client(bodylessGet).fetchCredentialOffer("https://wallet.example/offer")
        }
        assertFalse(bodylessGet.inputRequested)
        assertTrue(bodylessGet.disconnected)

        val duplicateContentType = FakeHttpsURLConnection(
            URL("https://wallet.example/offer"),
            responseContentTypeValues = listOf("application/json", "text/html"),
            responseBody = byteArrayOf(1),
        )
        assertThrows(WalletHttpClientException.UnacceptableContentType::class.java) {
            client(duplicateContentType).fetchCredentialOffer("https://wallet.example/offer")
        }
        assertFalse(duplicateContentType.inputRequested)
    }

    @Test
    fun explicitlyRejectsRedirectsForPostAndGetWithoutReadingResponse() {
        val operations = listOf<(UrlConnectionHttpClient) -> Unit>(
            { client -> client.post("https://wallet.example/submit", ByteArray(0)) },
            { client -> client.fetchStatusList("https://wallet.example/status") },
        )

        operations.forEach { operation ->
            val fake = FakeHttpsURLConnection(
                URL("https://wallet.example/resource"),
                responseCodeValue = 302,
                responseHeaders = mapOf("Location" to "https://other.example/next"),
                responseContentType = UrlConnectionHttpClient.STATUS_LIST_MEDIA_TYPE,
            )

            val error = assertThrows(WalletHttpClientException.RedirectRejected::class.java) {
                operation(client(fake))
            }
            assertEquals("https://other.example/next", error.location)
            assertFalse(fake.instanceFollowRedirects)
            assertFalse(fake.inputRequested)
            assertTrue(fake.disconnected)
        }
    }

    @Test
    fun rejectsDeclaredAndStreamedResponsesOverTheConfiguredLimit() {
        val declared = FakeHttpsURLConnection(
            URL("https://wallet.example/offer"),
            declaredLength = 5,
            responseContentType = UrlConnectionHttpClient.JSON_MEDIA_TYPE,
            responseBody = ByteArray(0),
        )
        assertThrows(WalletHttpClientException.ResponseTooLarge::class.java) {
            client(declared, maximumResponseBytes = 4)
                .fetchCredentialOffer("https://wallet.example/offer")
        }
        assertFalse(declared.inputRequested)
        assertTrue(declared.disconnected)

        val streamed = FakeHttpsURLConnection(
            URL("https://wallet.example/offer"),
            declaredLength = -1,
            responseContentType = UrlConnectionHttpClient.JSON_MEDIA_TYPE,
            responseBody = byteArrayOf(1, 2, 3, 4, 5),
        )
        assertThrows(WalletHttpClientException.ResponseTooLarge::class.java) {
            client(streamed, maximumResponseBytes = 4)
                .fetchCredentialOffer("https://wallet.example/offer")
        }
        assertTrue(streamed.inputRequested)
        assertTrue(streamed.disconnected)
    }

    @Test
    fun validatesResourceLimits() {
        assertThrows(IllegalArgumentException::class.java) {
            UrlConnectionHttpClient(timeoutMilliseconds = 0)
        }
        assertThrows(IllegalArgumentException::class.java) {
            UrlConnectionHttpClient(maximumResponseBytes = 0)
        }

        val bounded = UrlConnectionHttpClient(maximumResponseBytes = 4)
        assertArrayEquals(
            byteArrayOf(1, 2, 3, 4),
            bounded.readBody(ByteArrayInputStream(byteArrayOf(1, 2, 3, 4))),
        )
        assertThrows(WalletHttpClientException.ResponseTooLarge::class.java) {
            bounded.readBody(ByteArrayInputStream(byteArrayOf(1, 2, 3, 4, 5)))
        }
    }

    private fun assertUnsafe(policy: ProductionUrlPolicy) {
        assertThrows(WalletHttpClientException.UnsafeDestination::class.java) {
            policy.validate("https://wallet.example/callback")
        }
    }

    private fun publicPolicy(): ProductionUrlPolicy =
        ProductionUrlPolicy { listOf(ipv4(93, 184, 216, 34)) }

    private fun client(
        connection: FakeHttpsURLConnection,
        maximumResponseBytes: Int = UrlConnectionHttpClient.DEFAULT_MAXIMUM_RESPONSE_BYTES,
    ): UrlConnectionHttpClient = client(
        connectionFactory = HttpsConnectionFactory { connection },
        maximumResponseBytes = maximumResponseBytes,
    )

    private fun client(
        connectionFactory: HttpsConnectionFactory,
        maximumResponseBytes: Int = UrlConnectionHttpClient.DEFAULT_MAXIMUM_RESPONSE_BYTES,
        policy: ProductionUrlPolicy = publicPolicy(),
    ): UrlConnectionHttpClient = UrlConnectionHttpClient(
        timeoutMilliseconds = UrlConnectionHttpClient.DEFAULT_TIMEOUT_MILLISECONDS,
        maximumResponseBytes = maximumResponseBytes,
        urlPolicy = policy,
        connectionFactory = connectionFactory,
    )

    private fun ipv4(a: Int, b: Int, c: Int, d: Int): InetAddress =
        InetAddress.getByAddress(byteArrayOf(a.toByte(), b.toByte(), c.toByte(), d.toByte()))
}

private class FakeHttpsURLConnection(
    url: URL,
    private val responseCodeValue: Int = 200,
    private val responseHeaders: Map<String, String> = emptyMap(),
    private val responseContentType: String? = null,
    private val responseContentTypeValues: List<String>? = null,
    private val declaredLength: Long = -1,
    private val responseBody: ByteArray = ByteArray(0),
) : HttpsURLConnection(url) {
    val requestBody = ByteArrayOutputStream()
    var disconnected = false
        private set
    var inputRequested = false
        private set

    override fun connect() = Unit

    override fun disconnect() {
        disconnected = true
    }

    override fun usingProxy(): Boolean = false

    override fun getCipherSuite(): String = "TLS_AES_128_GCM_SHA256"

    override fun getLocalCertificates(): Array<java.security.cert.Certificate>? = null

    override fun getServerCertificates(): Array<java.security.cert.Certificate> = emptyArray()

    override fun getResponseCode(): Int = responseCodeValue

    override fun getContentLengthLong(): Long = declaredLength

    override fun getHeaderField(name: String?): String? = when {
        name.equals("Content-Type", ignoreCase = true) ->
            responseContentTypeValues?.lastOrNull() ?: responseContentType
        name == null -> null
        else -> responseHeaders.entries.firstOrNull { it.key.equals(name, ignoreCase = true) }?.value
    }

    override fun getHeaderFields(): Map<String, List<String>> {
        val fields = responseHeaders.mapValues { listOf(it.value) }.toMutableMap()
        val contentTypes = responseContentTypeValues ?: responseContentType?.let(::listOf)
        if (contentTypes != null) fields["Content-Type"] = contentTypes
        return fields
    }

    override fun getInputStream(): InputStream {
        inputRequested = true
        return ByteArrayInputStream(responseBody)
    }

    override fun getErrorStream(): InputStream {
        inputRequested = true
        return ByteArrayInputStream(responseBody)
    }

    override fun getOutputStream(): ByteArrayOutputStream = requestBody
}
