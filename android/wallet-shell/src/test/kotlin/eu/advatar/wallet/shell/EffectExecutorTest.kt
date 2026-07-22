package eu.advatar.wallet.shell

import java.net.URI
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Test

private class RecordingEngine(
    private val response: (String) -> String,
) : DurableWalletEngineDriving {
    val events = mutableListOf<String>()

    override fun prepareForDurableRestore(environment: CoreDurableEnvironment) = Unit

    override fun makeDurableCheckpoint(generation: Long): CoreDurableCheckpoint =
        CoreDurableCheckpoint(generation, byteArrayOf(1))

    override fun restoreDurableCheckpointRecord(checkpoint: CoreDurableCheckpoint) = Unit

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

private class RecordingRedirectHandler(
    private val shouldFail: Boolean = false,
    private val onHandle: () -> Unit = {},
) : OpenId4VpRedirectHandler {
    val redirects = mutableListOf<URI>()

    override fun handle(redirectUri: URI) {
        onHandle()
        if (shouldFail) throw ExpectedFailure()
        redirects += redirectUri
    }
}

class EffectExecutorTest {
    @Test
    fun publicConstructorsRequireConcreteDurableLifecycleCoordinator() {
        val constructors = EffectExecutor::class.java.constructors

        assertTrue(constructors.isNotEmpty())
        assertTrue(constructors.all {
            it.parameterTypes.firstOrNull() == DurableLifecycleCoordinator::class.java
        })
        assertFalse(constructors.any {
            WalletEngineDriving::class.java in it.parameterTypes
        })
    }

    @Test
    fun transactionHistoryMutationsCommitAsSuccessfulLocalEvents() {
        val engine = RecordingEngine { "[]" }
        val durableStore = InMemoryDurableStateStore()
        val executor = makeExecutor(engine = engine, durableStore = durableStore)

        assertEquals(
            EffectCascadeOutcome.Idle,
            executor.send(WalletEventJson.redactTransaction(17u)),
        )
        assertEquals(
            EffectCascadeOutcome.Idle,
            executor.send(WalletEventJson.wipeTransactionLog()),
        )
        assertEquals(2, engine.events.size)
        assertEquals(2L, durableStore.currentRecord?.generation)
    }

    @Test
    fun blockedTransactionHistoryMutationCannotBeReportedAsIdleSuccess() {
        val executor = makeExecutor(
            engine = RecordingEngine {
                """[{"type":"render","screen":{"screen":"error","code":"history_mutation_in_progress","message":"History cannot be changed while a wallet operation is active"}},{"type":"close"}]"""
            },
        )

        assertEquals(
            EffectCascadeOutcome.Aborted(
                EffectAbortReason.CoreError(
                    "history_mutation_in_progress",
                    "History cannot be changed while a wallet operation is active",
                ),
            ),
            executor.send(WalletEventJson.wipeTransactionLog()),
        )
    }

    @Test
    fun credentialCallbackIsAcknowledgedOnlyAfterCoreAcceptsIt() {
        val issuer = object : IssuerResponder {
            override fun token(): TokenResult = TokenResult(bound = true, cNonce = 1u)

            override fun credential(proofJwt: ByteArray): CredentialResult =
                CredentialResult(format = "dc+sd-jwt", bytes = byteArrayOf(9, 8, 7))
        }
        val rejection = RecordingEngine { event ->
            if (event.contains("\"type\":\"credentialReceived\"")) {
                """[{"type":"render","screen":{"screen":"error","code":"credential_issuance_rejected","message":"Credential issuance was rejected"}},{"type":"close"}]"""
            } else {
                """[{"type":"requestCredential","operationId":73,"proofJwt":[1,2]}]"""
            }
        }

        val rejectedOutcome = makeExecutor(
            engine = rejection,
            issuer = issuer,
        ).send("{\"type\":\"start\"}")

        assertEquals(
            EffectCascadeOutcome.Aborted(
                EffectAbortReason.CoreError(
                    "credential_issuance_rejected",
                    "Credential issuance was rejected",
                ),
            ),
            rejectedOutcome,
        )
        assertFalse(rejectedOutcome is EffectCascadeOutcome.Succeeded)
        assertTrue(rejection.events.any { it.contains("\"type\":\"credentialReceived\"") })

        val acceptance = RecordingEngine { event ->
            if (event.contains("\"type\":\"credentialReceived\"")) {
                """[{"type":"close"}]"""
            } else {
                """[{"type":"requestCredential","operationId":74,"proofJwt":[3,4]}]"""
            }
        }

        assertEquals(
            EffectCascadeOutcome.Succeeded,
            makeExecutor(engine = acceptance, issuer = issuer).send("{\"type\":\"start\"}"),
        )
    }

    @Test
    fun drainsSignAndHttpCascadeOnGenuineSuccess() {
        val engine = RecordingEngine { event ->
            when {
                event.contains("userConsented") ->
                    "[{\"type\":\"sign\",\"operationId\":2,\"keyRef\":\"device\",\"payload\":[1,2]}]"
                event.contains("deviceSignatureProduced") ->
                    "[{\"type\":\"http\",\"operationId\":3,\"resultType\":\"presentationDelivered\",\"profile\":\"openid4vpDirectPost\",\"url\":\"https://rp.example/cb\",\"body\":[3]}]"
                event.contains("presentationDelivered") -> "[{\"type\":\"close\"}]"
                else -> "[]"
            }
        }
        val signed = mutableListOf<ByteArray>()
        val posted = mutableListOf<Triple<String, ByteArray, HttpDeliveryProfile>>()
        val executor = makeExecutor(
            engine = engine,
            signer = WalletSigner { _, payload ->
                signed += payload
                byteArrayOf(9, 8)
            },
            http = WalletHttpClient { url, body, profile ->
                posted += Triple(url, body, profile)
                HttpResponse(200, "{}".encodeToByteArray(), "application/json")
            },
        )

        val outcome = executor.send(WalletEventJson.userConsented(1, AUTHORIZATION_HASH))

        assertEquals(1, signed.size)
        assertArrayEquals(byteArrayOf(1, 2), signed.single())
        assertEquals("https://rp.example/cb", posted.single().first)
        assertArrayEquals(byteArrayOf(3), posted.single().second)
        assertEquals(HttpDeliveryProfile.OPENID4VP_DIRECT_POST, posted.single().third)
        assertEquals(3, engine.events.size)
        assertEquals(EffectCascadeOutcome.Succeeded, outcome)
    }

    @Test
    fun httpSuccessUsesTheProtocolSpecificCompletionEvent() {
        val engine = RecordingEngine { event ->
            if (event.contains("paymentAuthorizationDelivered")) {
                "[{\"type\":\"close\"}]"
            } else {
                "[{\"type\":\"http\",\"operationId\":13,\"resultType\":\"paymentAuthorizationDelivered\",\"profile\":\"paymentAuthorization\",\"url\":\"https://psp.example\",\"body\":[]}]"
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
                "[{\"type\":\"render\",\"operationId\":44,\"authorizationHash\":$AUTHORIZATION_HASH_JSON,\"screen\":{\"screen\":\"consent\",\"rpDisplayName\":\"RP\",\"purpose\":\"Age\",\"requestedClaims\":[],\"notSharedClaims\":[],\"verifierRegistration\":\"certificateValidated\",\"trustMark\":null,\"retention\":{\"policy\":\"unspecified\"},\"overAsk\":{\"result\":\"registrationScopeUnavailable\"}}}]"
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
            WalletHttpClient { _, _, _ -> throw ExpectedFailure() },
            WalletHttpClient { _, _, _ ->
                HttpResponse(503, "unavailable".encodeToByteArray(), "application/json")
            },
        ).forEach { client ->
            val engine = RecordingEngine { event ->
                if (event.contains("operationFailed")) ERROR_CLOSE else
                    "[{\"type\":\"http\",\"operationId\":6,\"resultType\":\"presentationDelivered\",\"profile\":\"openid4vpDirectPost\",\"url\":\"https://rp.example\",\"body\":[]}]"
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
                "[{\"type\":\"http\",\"operationId\":7,\"resultType\":\"presentationDelivered\",\"profile\":\"openid4vpDirectPost\",\"url\":\"https://rp.example\",\"body\":[]}]"
        }
        val body = "unavailable".encodeToByteArray()
        val executor = makeExecutor(
            engine = engine,
            http = WalletHttpClient { _, _, _ ->
                HttpResponse(503, body, "application/json")
            },
        )

        executor.send("{\"type\":\"start\"}")
        assertTrue(engine.events.any { it.contains("\"failure\":\"httpStatus\"") })
        assertNoFabricatedOutcome(engine)
    }

    @Test
    fun openId4VpResponseRequiresExactStatusMimeObjectUtf8AndBounds() {
        val invalidResponses = listOf(
            "201" to HttpResponse(201, "{}".encodeToByteArray(), "application/json"),
            "204" to HttpResponse(204, "{}".encodeToByteArray(), "application/json"),
            "missing MIME" to HttpResponse(200, "{}".encodeToByteArray()),
            "wrong MIME" to HttpResponse(200, "{}".encodeToByteArray(), "text/html"),
            "ambiguous MIME" to HttpResponse(
                200,
                "{}".encodeToByteArray(),
                "application/json, text/html",
            ),
            "array" to HttpResponse(200, "[]".encodeToByteArray(), "application/json"),
            "scalar" to HttpResponse(200, "true".encodeToByteArray(), "application/json"),
            "invalid JSON" to HttpResponse(200, "{".encodeToByteArray(), "application/json"),
            "non-UTF8" to HttpResponse(200, byteArrayOf(0xff.toByte()), "application/json"),
            "oversize" to HttpResponse(
                200,
                ByteArray(OpenId4VpDirectPostResponse.MAXIMUM_RESPONSE_BYTES + 1) { ' '.code.toByte() },
                "application/json",
            ),
        )

        invalidResponses.forEach { (name, response) ->
            val engine = directPostEngine()
            val outcome = makeExecutor(
                engine = engine,
                http = WalletHttpClient { _, _, _ -> response },
            ).send("{}")

            assertTrue(name, outcome is EffectCascadeOutcome.Aborted)
            assertNoFabricatedOutcome(engine)
        }
    }

    @Test
    fun openId4VpRedirectRejectsMalformedAmbiguousAndOversizedValues() {
        val oversized = "wallet:" + "a".repeat(
            OpenId4VpDirectPostResponse.MAXIMUM_REDIRECT_URI_BYTES,
        )
        val invalidBodies = listOf(
            "{\"redirect_uri\":7}",
            "{\"redirect_uri\":\"relative/path\"}",
            "{\"redirect_uri\":\"https://client.example/%zz\"}",
            "{\"redirect_uri\":\"$oversized\"}",
            "{\"redirect_uri\":\"https://one.example\",\"redirect_uri\":\"https://two.example\"}",
            "{\"redirect_uri\":\"https://one.example\",\"\\u0072edirect_uri\":\"https://two.example\"}",
        )

        invalidBodies.forEach { body ->
            val engine = directPostEngine()
            makeExecutor(
                engine = engine,
                http = WalletHttpClient { _, _, _ ->
                    HttpResponse(200, body.encodeToByteArray(), "application/json")
                },
                redirectHandler = RecordingRedirectHandler(),
            ).send("{}")
            assertNoFabricatedOutcome(engine)
        }
    }

    @Test
    fun openId4VpUnknownMembersAreIgnoredAndOpaqueRedirectOnlyReachesInjectedHandler() {
        val engine = directPostEngine()
        var acknowledgedBeforeHandler = false
        val handler = RecordingRedirectHandler {
            acknowledgedBeforeHandler = engine.events.any { it.contains("presentationDelivered") }
        }
        val outcome = makeExecutor(
            engine = engine,
            http = WalletHttpClient { _, _, _ ->
                HttpResponse(
                    200,
                    """{"future":{"nested":[1,2,3]},"redirect_uri":"wallet:continue?response_code=abc"}"""
                        .encodeToByteArray(),
                    "Application/JSON; charset=UTF-8",
                )
            },
            redirectHandler = handler,
        ).send("{}")

        assertEquals(EffectCascadeOutcome.Succeeded, outcome)
        assertFalse(acknowledgedBeforeHandler)
        assertEquals(listOf(URI("wallet:continue?response_code=abc")), handler.redirects)
    }

    @Test
    fun openId4VpRedirectRequiresHandlerAndRefusalNeverAcknowledges() {
        listOf<OpenId4VpRedirectHandler?>(null, RecordingRedirectHandler(shouldFail = true))
            .forEach { handler ->
                val engine = directPostEngine()
                makeExecutor(
                    engine = engine,
                    http = WalletHttpClient { _, _, _ ->
                        HttpResponse(
                            200,
                            """{"redirect_uri":"https://client.example/cb#code=abc"}"""
                                .encodeToByteArray(),
                            "application/json",
                        )
                    },
                    redirectHandler = handler,
                ).send("{}")
                assertNoFabricatedOutcome(engine)
            }
    }

    @Test
    fun openId4VpRequestBodyMustBeUtf8BeforeTransport() {
        var posts = 0
        val engine = directPostEngine(body = "[255]")
        makeExecutor(
            engine = engine,
            http = WalletHttpClient { _, _, _ ->
                posts += 1
                HttpResponse(200, "{}".encodeToByteArray(), "application/json")
            },
        ).send("{}")

        assertEquals(0, posts)
        assertNoFabricatedOutcome(engine)
    }

    @Test
    fun malformedAndRejectedCoreOutputsRemainDistinct() {
        val malformed = makeExecutor(engine = RecordingEngine { "not-json" })
        val malformedError = assertThrows(DurableLifecycleException::class.java) {
            malformed.send("{}")
        }
        assertEquals(DurableLifecycleErrorCode.MALFORMED_CORE_OUTPUT, malformedError.code)

        val rejected = makeExecutor(engine = RecordingEngine { "{\"error\":\"invalid\"}" })
        val error = assertThrows(WalletShellException.CoreRejected::class.java) {
            rejected.send("{}")
        }
        assertEquals("invalid", error.detail)
    }

    @Test
    fun coreInvocationFailureIsTyped() {
        val executor = makeExecutor(engine = RecordingEngine { throw ExpectedFailure() })

        val error = assertThrows(DurableLifecycleException::class.java) {
            executor.send("{}")
        }
        assertEquals(DurableLifecycleErrorCode.CORE_INVOCATION_FAILED, error.code)
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
        durableStore: DurableStateStore = InMemoryDurableStateStore(),
        signer: WalletSigner = WalletSigner { _, _ -> byteArrayOf(1) },
        http: WalletHttpClient = WalletHttpClient { _, _, _ ->
            HttpResponse(200, "{}".encodeToByteArray(), "application/json")
        },
        storage: WalletStorage = WalletStorage { _, _ -> },
        trust: TrustResolver = TrustResolver { TrustResolution(emptyList(), emptyList()) },
        renderer: ScreenRenderer = ScreenRenderer { _, _, _ -> },
        issuer: IssuerResponder? = null,
        statusLists: StatusListResolver? = null,
        transferOffers: TransferOfferPublisher? = null,
        redirectHandler: OpenId4VpRedirectHandler? = null,
    ): EffectExecutor = EffectExecutor(
        lifecycle = bootstrappedTestLifecycle(engine, durableStore),
        signer = signer,
        httpClient = http,
        storage = storage,
        trustResolver = trust,
        renderer = renderer,
        issuerResponder = issuer,
        statusListResolver = statusLists,
        transferOfferPublisher = transferOffers,
        presentationRedirectHandler = redirectHandler,
    )

    private fun assertNoFabricatedOutcome(engine: RecordingEngine) {
        assertFalse(engine.events.any { it.contains("userDeclined") })
        assertFalse(engine.events.any { it.contains("presentationDelivered") })
    }

    private fun directPostEngine(body: String = "[]"): RecordingEngine = RecordingEngine { event ->
        if (event.contains("operationFailed") || event.contains("operationCancelled")) {
            ERROR_CLOSE
        } else if (event.contains("presentationDelivered")) {
            "[{\"type\":\"close\"}]"
        } else {
            "[{\"type\":\"http\",\"operationId\":71,\"resultType\":\"presentationDelivered\",\"profile\":\"openid4vpDirectPost\",\"url\":\"https://rp.example/response\",\"body\":$body}]"
        }
    }
}
