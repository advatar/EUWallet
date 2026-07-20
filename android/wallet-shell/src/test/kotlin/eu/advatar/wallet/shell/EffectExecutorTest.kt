package eu.advatar.wallet.shell

import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Test

private class RecordingEngine(
    private val response: (String) -> String,
) : WalletEngineDriving {
    val events = mutableListOf<String>()

    override fun handleEventJson(eventJson: String): String {
        events += eventJson
        return response(eventJson)
    }
}

private class ExpectedFailure : RuntimeException()

class EffectExecutorTest {
    @Test
    fun drainsSignAndHttpCascadeOnGenuineSuccess() {
        val engine = RecordingEngine { event ->
            when {
                event.contains("userConsented") ->
                    "[{\"type\":\"sign\",\"keyRef\":\"device\",\"payload\":[1,2]}]"
                event.contains("deviceSignatureProduced") ->
                    "[{\"type\":\"http\",\"url\":\"https://rp.example/cb\",\"body\":[3]}]"
                event.contains("presentationDelivered") -> "[{\"type\":\"close\"}]"
                else -> "[]"
            }
        }
        val signed = mutableListOf<ByteArray>()
        val posted = mutableListOf<Pair<String, ByteArray>>()
        val executor = makeExecutor(
            engine = engine,
            signer = WalletSigner { _, payload ->
                signed += payload
                byteArrayOf(9, 8)
            },
            http = WalletHttpClient { url, body ->
                posted += url to body
                HttpResponse(204, ByteArray(0))
            },
        )

        executor.send(WalletEventJson.userConsented())

        assertEquals(1, signed.size)
        assertArrayEquals(byteArrayOf(1, 2), signed.single())
        assertEquals("https://rp.example/cb", posted.single().first)
        assertArrayEquals(byteArrayOf(3), posted.single().second)
        assertEquals(3, engine.events.size)
    }

    @Test
    fun storageFailureStopsWithoutSemanticSuccessOrDecline() {
        val engine = RecordingEngine { "[{\"type\":\"persistNonce\",\"nonce\":42}]" }
        val executor = makeExecutor(
            engine = engine,
            storage = WalletStorage { _, _ -> throw ExpectedFailure() },
        )

        assertThrows(WalletShellException.StorageFailure::class.java) {
            executor.send("{\"type\":\"start\"}")
        }
        assertNoFabricatedOutcome(engine)
    }

    @Test
    fun signingFailureStopsWithoutSemanticSuccessOrDecline() {
        val engine = RecordingEngine {
            "[{\"type\":\"sign\",\"keyRef\":\"device\",\"payload\":[1]}]"
        }
        val executor = makeExecutor(
            engine = engine,
            signer = WalletSigner { _, _ -> throw ExpectedFailure() },
        )

        assertThrows(WalletShellException.SigningFailure::class.java) {
            executor.send(WalletEventJson.userConsented())
        }
        assertNoFabricatedOutcome(engine)
    }

    @Test
    fun transportAndNon2xxFailuresNeverBecomePresentationDelivered() {
        listOf<WalletHttpClient>(
            WalletHttpClient { _, _ -> throw ExpectedFailure() },
            WalletHttpClient { _, _ -> HttpResponse(503, "unavailable".encodeToByteArray()) },
        ).forEach { client ->
            val engine = RecordingEngine {
                "[{\"type\":\"http\",\"url\":\"https://rp.example\",\"body\":[]}]"
            }
            val executor = makeExecutor(engine = engine, http = client)

            val error = assertThrows(WalletShellException::class.java) {
                executor.send("{\"type\":\"start\"}")
            }
            assertTrue(
                error is WalletShellException.TransportFailure ||
                    error is WalletShellException.HttpStatusFailure,
            )
            assertNoFabricatedOutcome(engine)
        }
    }

    @Test
    fun non2xxPreservesStatusAndResponseBody() {
        val engine = RecordingEngine {
            "[{\"type\":\"http\",\"url\":\"https://rp.example\",\"body\":[]}]"
        }
        val body = "unavailable".encodeToByteArray()
        val executor = makeExecutor(
            engine = engine,
            http = WalletHttpClient { _, _ -> HttpResponse(503, body) },
        )

        val error = assertThrows(WalletShellException.HttpStatusFailure::class.java) {
            executor.send("{\"type\":\"start\"}")
        }
        assertEquals(503, error.statusCode)
        assertArrayEquals(body, error.responseBody)
        assertNoFabricatedOutcome(engine)
    }

    @Test
    fun malformedAndRejectedCoreOutputsRemainDistinct() {
        val malformed = makeExecutor(engine = RecordingEngine { "not-json" })
        assertThrows(WalletShellException.MalformedCoreOutput::class.java) {
            malformed.send("{}")
        }

        val rejected = makeExecutor(engine = RecordingEngine { "{\"error\":\"invalid\"}" })
        val error = assertThrows(WalletShellException.CoreRejected::class.java) {
            rejected.send("{}")
        }
        assertEquals("invalid", error.detail)
    }

    @Test
    fun coreInvocationFailureIsTyped() {
        val executor = makeExecutor(engine = RecordingEngine { throw ExpectedFailure() })

        assertThrows(WalletShellException.CoreInvocationFailure::class.java) {
            executor.send("{}")
        }
    }

    @Test
    fun missingAndUnsupportedDependenciesFailClosed() {
        val missingIssuer = makeExecutor(
            engine = RecordingEngine { "[{\"type\":\"requestToken\"}]" },
        )
        assertThrows(WalletShellException.MissingDependency::class.java) {
            missingIssuer.send("{}")
        }

        val unsupported = makeExecutor(
            engine = RecordingEngine { "[{\"type\":\"openAuthBrowser\"}]" },
        )
        assertThrows(WalletShellException.UnsupportedEffect::class.java) {
            unsupported.send("{}")
        }
    }

    @Test
    fun rendererAndTrustFailuresAreTyped() {
        val renderExecutor = makeExecutor(
            engine = RecordingEngine {
                "[{\"type\":\"render\",\"screen\":{\"screen\":\"loading\"}}]"
            },
            renderer = ScreenRenderer { throw ExpectedFailure() },
        )
        assertThrows(WalletShellException.RenderingFailure::class.java) {
            renderExecutor.send("{}")
        }

        val trustExecutor = makeExecutor(
            engine = RecordingEngine {
                "[{\"type\":\"resolveRpTrust\",\"clientId\":\"rp\"}]"
            },
            trust = TrustResolver { throw ExpectedFailure() },
        )
        assertThrows(WalletShellException.TrustResolutionFailure::class.java) {
            trustExecutor.send("{}")
        }
    }

    @Test
    fun statusListFetchReturnsTokenAndProviderChainToCore() {
        val engine = RecordingEngine { event ->
            if (event.contains("statusListReceived")) {
                "[{\"type\":\"close\"}]"
            } else {
                "[{\"type\":\"fetchStatusList\",\"uri\":\"https://status.example/list\"}]"
            }
        }
        val resolver = StatusListResolver { uri ->
            assertEquals("https://status.example/list", uri)
            StatusListResolution(
                response = HttpResponse(200, byteArrayOf(1, 2, 3)),
                providerCertificateChain = listOf(byteArrayOf(4, 5)),
            )
        }

        makeExecutor(engine = engine, statusLists = resolver).send("{\"type\":\"start\"}")

        val event = engine.events.single { it.contains("statusListReceived") }
        assertTrue(event.contains("\"httpStatus\":200"))
        assertTrue(event.contains("\"token\":[1,2,3]"))
        assertTrue(event.contains("\"providerCertChain\":[[4,5]]"))
    }

    @Test
    fun missingFailedAndOversizedStatusResolversDriveExplicitFailure() {
        val resolvers = listOf<StatusListResolver?>(
            null,
            StatusListResolver { throw ExpectedFailure() },
            StatusListResolver {
                StatusListResolution(
                    response = HttpResponse(200, ByteArray(2 * 1_024 * 1_024 + 1)),
                    providerCertificateChain = listOf(byteArrayOf(1)),
                )
            },
            StatusListResolver {
                StatusListResolution(
                    response = HttpResponse(100_000, byteArrayOf(1)),
                    providerCertificateChain = listOf(byteArrayOf(1)),
                )
            },
        )

        resolvers.forEach { resolver ->
            val engine = RecordingEngine { event ->
                if (event.contains("statusListReceived")) {
                    "[{\"type\":\"close\"}]"
                } else {
                    "[{\"type\":\"fetchStatusList\",\"uri\":\"https://status.example/list\"}]"
                }
            }

            makeExecutor(engine = engine, statusLists = resolver).send("{\"type\":\"start\"}")

            val event = engine.events.single { it.contains("statusListReceived") }
            assertTrue(event.contains("\"httpStatus\":0"))
            assertTrue(event.contains("\"token\":[]"))
            assertTrue(event.contains("\"providerCertChain\":[]"))
            assertNoFabricatedOutcome(engine)
        }
    }

    private fun makeExecutor(
        engine: RecordingEngine,
        signer: WalletSigner = WalletSigner { _, _ -> byteArrayOf(1) },
        http: WalletHttpClient = WalletHttpClient { _, _ -> HttpResponse(204, ByteArray(0)) },
        storage: WalletStorage = WalletStorage { _, _ -> },
        trust: TrustResolver = TrustResolver { TrustResolution(emptyList(), emptyList()) },
        renderer: ScreenRenderer = ScreenRenderer { },
        statusLists: StatusListResolver? = null,
    ): EffectExecutor = EffectExecutor(
        engine = engine,
        signer = signer,
        httpClient = http,
        storage = storage,
        trustResolver = trust,
        renderer = renderer,
        statusListResolver = statusLists,
    )

    private fun assertNoFabricatedOutcome(engine: RecordingEngine) {
        assertFalse(engine.events.any { it.contains("userDeclined") })
        assertFalse(engine.events.any { it.contains("presentationDelivered") })
    }
}
