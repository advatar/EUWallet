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
private val AUTHORIZATION_HASH = ByteArray(32)
private const val AUTHORIZATION_HASH_JSON =
    "[0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0]"
private const val ERROR_CLOSE =
    "[{\"type\":\"render\",\"screen\":{\"screen\":\"error\",\"code\":\"operation_failed\",\"message\":\"Operation failed\"}},{\"type\":\"close\"}]"

class EffectExecutorTest {
    @Test
    fun drainsSignAndHttpCascadeOnGenuineSuccess() {
        val engine = RecordingEngine { event ->
            when {
                event.contains("userConsented") ->
                    "[{\"type\":\"sign\",\"operationId\":2,\"keyRef\":\"device\",\"payload\":[1,2]}]"
                event.contains("deviceSignatureProduced") ->
                    "[{\"type\":\"http\",\"operationId\":3,\"resultType\":\"presentationDelivered\",\"url\":\"https://rp.example/cb\",\"body\":[3]}]"
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

        val outcome = executor.send(WalletEventJson.userConsented(1, AUTHORIZATION_HASH))

        assertEquals(1, signed.size)
        assertArrayEquals(byteArrayOf(1, 2), signed.single())
        assertEquals("https://rp.example/cb", posted.single().first)
        assertArrayEquals(byteArrayOf(3), posted.single().second)
        assertEquals(3, engine.events.size)
        assertEquals(EffectCascadeOutcome.Succeeded, outcome)
    }

    @Test
    fun httpSuccessUsesTheProtocolSpecificCompletionEvent() {
        val engine = RecordingEngine { event ->
            if (event.contains("paymentAuthorizationDelivered")) {
                "[{\"type\":\"close\"}]"
            } else {
                "[{\"type\":\"http\",\"operationId\":13,\"resultType\":\"paymentAuthorizationDelivered\",\"url\":\"https://psp.example\",\"body\":[]}]"
            }
        }

        val outcome = makeExecutor(engine = engine).send("{\"type\":\"paymentApproved\"}")

        assertEquals(EffectCascadeOutcome.Succeeded, outcome)
        assertTrue(engine.events.any {
            it.contains("\"type\":\"paymentAuthorizationDelivered\"") &&
                it.contains("\"operationId\":13")
        })
        assertFalse(engine.events.any { it.contains("presentationDelivered") })
    }

    @Test
    fun emptyCloseOnlyAndErrorFlowsAreNeverSuccess() {
        val empty = makeExecutor(engine = RecordingEngine { "[]" })
        assertEquals(
            EffectCascadeOutcome.Aborted(EffectAbortReason.MissingTerminalOutcome),
            empty.send(WalletEventJson.userConsented(1, AUTHORIZATION_HASH)),
        )

        val closeOnly = makeExecutor(engine = RecordingEngine { "[{\"type\":\"close\"}]" })
        assertEquals(
            EffectCascadeOutcome.Aborted(EffectAbortReason.ClosedWithoutSuccess),
            closeOnly.send(WalletEventJson.userConsented(1, AUTHORIZATION_HASH)),
        )

        val coreError = makeExecutor(
            engine = RecordingEngine {
                """[{"type":"render","screen":{"screen":"error","code":"STATUS_UNAVAILABLE","message":"Status unavailable"}},{"type":"close"}]"""
            },
        )
        assertEquals(
            EffectCascadeOutcome.Aborted(
                EffectAbortReason.CoreError("STATUS_UNAVAILABLE", "Status unavailable"),
            ),
            coreError.send(WalletEventJson.userConsented(1, AUTHORIZATION_HASH)),
        )
    }

    @Test
    fun explicitDeclineAndRenderedPromptHaveDistinctOutcomes() {
        val decline = makeExecutor(engine = RecordingEngine { "[{\"type\":\"close\"}]" })
        assertEquals(
            EffectCascadeOutcome.Declined,
            decline.send(WalletEventJson.userDeclined(1)),
        )

        val prompt = makeExecutor(
            engine = RecordingEngine {
                "[{\"type\":\"render\",\"screen\":{\"screen\":\"loading\"}}]"
            },
        )
        assertEquals(
            EffectCascadeOutcome.AwaitingInput,
            prompt.send("{\"type\":\"authorizationRequestReceived\"}"),
        )
    }

    @Test
    fun interactiveRenderCarriesDecisionIdAndAuthorizationHash() {
        var operationId: Long? = null
        var authorizationHash: ByteArray? = null
        val executor = makeExecutor(
            engine = RecordingEngine {
                "[{\"type\":\"render\",\"operationId\":44,\"authorizationHash\":$AUTHORIZATION_HASH_JSON,\"screen\":{\"screen\":\"consent\",\"rpDisplayName\":\"RP\",\"purpose\":\"Age\",\"requestedClaims\":[]}}]"
            },
            renderer = ScreenRenderer { id, hash, _ ->
                operationId = id
                authorizationHash = hash
            },
        )

        assertEquals(
            EffectCascadeOutcome.AwaitingInput,
            executor.send("{\"type\":\"authorizationRequestReceived\"}"),
        )
        assertEquals(44L, operationId)
        assertArrayEquals(AUTHORIZATION_HASH, requireNotNull(authorizationHash))
    }

    @Test
    fun publishedTransferOfferWaitsForPeerInput() {
        val published = mutableListOf<ByteArray>()
        val engine = RecordingEngine { event ->
            if (event.contains("operationSucceeded")) {
                "[]"
            } else {
                "[{\"type\":\"publishTransferOffer\",\"operationId\":45,\"offeredKey\":[1,2,3]}]"
            }
        }
        val executor = makeExecutor(
            engine = engine,
            transferOffers = TransferOfferPublisher { published += it },
        )

        val outcome = executor.send("{}")

        assertEquals(1, published.size)
        assertArrayEquals(byteArrayOf(1, 2, 3), published.single())
        assertTrue(engine.events.any {
            it.contains("\"type\":\"operationSucceeded\"") &&
                it.contains("\"operationId\":45")
        })
        assertEquals(EffectCascadeOutcome.AwaitingInput, outcome)
    }

    @Test
    fun staleDecisionCoreRejectionCannotBecomeSuccess() {
        val executor = makeExecutor(
            engine = RecordingEngine { "{\"error\":\"stale or unknown operationId 7\"}" },
        )
        val error = assertThrows(WalletShellException.CoreRejected::class.java) {
            executor.send(WalletEventJson.userConsented(7, AUTHORIZATION_HASH))
        }
        assertTrue(error.detail.contains("stale or unknown"))
    }

    @Test
    fun effectAfterCloseAbortsWithoutRenderingIt() {
        var rendered = false
        val executor = makeExecutor(
            engine = RecordingEngine {
                """[{"type":"close"},{"type":"render","screen":{"screen":"loading"}}]"""
            },
            renderer = ScreenRenderer { _, _, _ -> rendered = true },
        )

        assertEquals(
            EffectCascadeOutcome.Aborted(EffectAbortReason.EffectAfterClose),
            executor.send(WalletEventJson.userConsented(1, AUTHORIZATION_HASH)),
        )
        assertFalse(rendered)
    }

    @Test
    fun storageFailureIsReportedToCoreAndResetsCascade() {
        val engine = RecordingEngine { event ->
            if (event.contains("operationFailed")) ERROR_CLOSE else
                "[{\"type\":\"persistNonce\",\"operationId\":4,\"nonce\":42}]"
        }
        val executor = makeExecutor(
            engine = engine,
            storage = WalletStorage { _, _ -> throw ExpectedFailure() },
        )

        assertEquals(
            EffectCascadeOutcome.Aborted(
                EffectAbortReason.CoreError("operation_failed", "Operation failed"),
            ),
            executor.send("{\"type\":\"start\"}"),
        )
        assertTrue(engine.events.any { it.contains("\"failure\":\"storage\"") })
        assertNoFabricatedOutcome(engine)
    }

    @Test
    fun signingFailureStopsWithoutSemanticSuccessOrDecline() {
        val engine = RecordingEngine { event ->
            if (event.contains("operationFailed")) ERROR_CLOSE else
                "[{\"type\":\"sign\",\"operationId\":5,\"keyRef\":\"device\",\"payload\":[1]}]"
        }
        val executor = makeExecutor(
            engine = engine,
            signer = WalletSigner { _, _ -> throw ExpectedFailure() },
        )

        assertEquals(
            EffectCascadeOutcome.Aborted(
                EffectAbortReason.CoreError("operation_failed", "Operation failed"),
            ),
            executor.send(WalletEventJson.userConsented(1, AUTHORIZATION_HASH)),
        )
        assertTrue(engine.events.any { it.contains("\"failure\":\"signing\"") })
        assertNoFabricatedOutcome(engine)
    }

    @Test
    fun signingCancellationUsesTheTypedCorrelatedCancellationEvent() {
        val engine = RecordingEngine { event ->
            if (event.contains("operationCancelled")) ERROR_CLOSE else
                "[{\"type\":\"sign\",\"operationId\":55,\"keyRef\":\"device\",\"payload\":[1]}]"
        }
        val executor = makeExecutor(
            engine = engine,
            signer = WalletSigner { _, _ ->
                throw java.util.concurrent.CancellationException("cancelled")
            },
        )

        val outcome = executor.send("{}")

        assertTrue(outcome is EffectCascadeOutcome.Aborted)
        assertTrue(engine.events.any {
            it.contains("\"type\":\"operationCancelled\"") &&
                it.contains("\"operationId\":55")
        })
        assertNoFabricatedOutcome(engine)
    }

    @Test
    fun transportAndNon2xxFailuresNeverBecomePresentationDelivered() {
        listOf<WalletHttpClient>(
            WalletHttpClient { _, _ -> throw ExpectedFailure() },
            WalletHttpClient { _, _ -> HttpResponse(503, "unavailable".encodeToByteArray()) },
        ).forEach { client ->
            val engine = RecordingEngine { event ->
                if (event.contains("operationFailed")) ERROR_CLOSE else
                    "[{\"type\":\"http\",\"operationId\":6,\"resultType\":\"presentationDelivered\",\"url\":\"https://rp.example\",\"body\":[]}]"
            }
            val executor = makeExecutor(engine = engine, http = client)

            assertEquals(
                EffectCascadeOutcome.Aborted(
                    EffectAbortReason.CoreError("operation_failed", "Operation failed"),
                ),
                executor.send("{\"type\":\"start\"}"),
            )
            assertTrue(engine.events.any { it.contains("\"type\":\"operationFailed\"") })
            assertNoFabricatedOutcome(engine)
        }
    }

    @Test
    fun non2xxIsTypedBeforeItCrossesBackIntoCore() {
        val engine = RecordingEngine { event ->
            if (event.contains("operationFailed")) ERROR_CLOSE else
                "[{\"type\":\"http\",\"operationId\":7,\"resultType\":\"presentationDelivered\",\"url\":\"https://rp.example\",\"body\":[]}]"
        }
        val body = "unavailable".encodeToByteArray()
        val executor = makeExecutor(
            engine = engine,
            http = WalletHttpClient { _, _ -> HttpResponse(503, body) },
        )

        executor.send("{\"type\":\"start\"}")
        assertTrue(engine.events.any { it.contains("\"failure\":\"httpStatus\"") })
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
            engine = RecordingEngine { event ->
                if (event.contains("operationFailed")) ERROR_CLOSE else
                    "[{\"type\":\"requestToken\",\"operationId\":8}]"
            },
        )
        assertTrue(missingIssuer.send("{}") is EffectCascadeOutcome.Aborted)

        val unsupported = makeExecutor(
            engine = RecordingEngine { event ->
                if (event.contains("operationFailed")) ERROR_CLOSE else
                    "[{\"type\":\"openAuthBrowser\",\"operationId\":9}]"
            },
        )
        assertTrue(unsupported.send("{}") is EffectCascadeOutcome.Aborted)
    }

    @Test
    fun rendererAndTrustFailuresAreTyped() {
        val renderExecutor = makeExecutor(
            engine = RecordingEngine {
                "[{\"type\":\"render\",\"screen\":{\"screen\":\"loading\"}}]"
            },
            renderer = ScreenRenderer { _, _, _ -> throw ExpectedFailure() },
        )
        assertThrows(WalletShellException.RenderingFailure::class.java) {
            renderExecutor.send("{}")
        }

        val trustExecutor = makeExecutor(
            engine = RecordingEngine { event ->
                if (event.contains("operationFailed")) ERROR_CLOSE else
                    "[{\"type\":\"resolveRpTrust\",\"operationId\":10,\"clientId\":\"rp\"}]"
            },
            trust = TrustResolver { throw ExpectedFailure() },
        )
        assertTrue(trustExecutor.send("{}") is EffectCascadeOutcome.Aborted)
    }

    @Test
    fun statusListFetchReturnsTokenAndProviderChainToCore() {
        val engine = RecordingEngine { event ->
            if (event.contains("statusListReceived")) {
                "[{\"type\":\"close\"}]"
            } else {
                "[{\"type\":\"fetchStatusList\",\"operationId\":11,\"uri\":\"https://status.example/list\"}]"
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
        assertTrue(event.contains("\"operationId\":11"))
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
                if (event.contains("operationFailed")) {
                    ERROR_CLOSE
                } else {
                    "[{\"type\":\"fetchStatusList\",\"operationId\":12,\"uri\":\"https://status.example/list\"}]"
                }
            }

            val outcome = makeExecutor(
                engine = engine,
                statusLists = resolver,
            ).send("{\"type\":\"start\"}")

            val event = engine.events.single { it.contains("operationFailed") }
            assertTrue(event.contains("\"failure\":\"status\""))
            assertTrue(outcome is EffectCascadeOutcome.Aborted)
            assertNoFabricatedOutcome(engine)
        }
    }

    private fun makeExecutor(
        engine: RecordingEngine,
        signer: WalletSigner = WalletSigner { _, _ -> byteArrayOf(1) },
        http: WalletHttpClient = WalletHttpClient { _, _ -> HttpResponse(204, ByteArray(0)) },
        storage: WalletStorage = WalletStorage { _, _ -> },
        trust: TrustResolver = TrustResolver { TrustResolution(emptyList(), emptyList()) },
        renderer: ScreenRenderer = ScreenRenderer { _, _, _ -> },
        statusLists: StatusListResolver? = null,
        transferOffers: TransferOfferPublisher? = null,
    ): EffectExecutor = EffectExecutor(
        engine = engine,
        signer = signer,
        httpClient = http,
        storage = storage,
        trustResolver = trust,
        renderer = renderer,
        statusListResolver = statusLists,
        transferOfferPublisher = transferOffers,
    )

    private fun assertNoFabricatedOutcome(engine: RecordingEngine) {
        assertFalse(engine.events.any { it.contains("userDeclined") })
        assertFalse(engine.events.any { it.contains("presentationDelivered") })
    }
}
