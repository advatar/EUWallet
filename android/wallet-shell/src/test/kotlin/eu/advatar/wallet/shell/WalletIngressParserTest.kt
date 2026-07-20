package eu.advatar.wallet.shell

import android.content.Intent
import org.junit.Assert.assertEquals
import org.junit.Assert.assertThrows
import org.junit.Test

class WalletIngressParserTest {
    @Test
    fun acceptsBoundedInlineAndByReferenceCredentialOffers() {
        val parser = WalletIngressParser()
        val inline =
            """{"credential_issuer":"https://issuer.example/tenant","credential_configuration_ids":["pid","mdl"],"grants":{"authorization_code":{}}}"""

        assertEquals(
            WalletIngressRequest.CredentialOffer(
                issuer = "https://issuer.example/tenant",
                configurationIds = listOf("pid", "mdl"),
            ),
            parser.parse(walletUrl("openid-credential-offer", "credential_offer" to inline)),
        )
        assertEquals(
            WalletIngressRequest.CredentialOfferByReference(
                "https://issuer.example/offers/one?language=de",
            ),
            parser.parse(
                walletUrl(
                    "openid-credential-offer",
                    "credential_offer_uri" to "https://issuer.example/offers/one?language=de",
                ),
            ),
        )
    }

    @Test
    fun acceptsExactPresentationSchemesAndPreservesByReferenceBindingInputs() {
        val parser = WalletIngressParser()
        val expected = WalletIngressRequest.PresentationByReference(
            requestUri = "https://verifier.example/requests/one",
            clientId = "x509_san_dns:verifier.example",
        )

        listOf("openid4vp", "haip", "eudi-openid4vp", "mdoc-openid4vp").forEach { scheme ->
            assertEquals(
                expected,
                parser.parse(
                    walletUrl(
                        scheme,
                        "request_uri" to "https://verifier.example/requests/one",
                        "client_id" to "x509_san_dns:verifier.example",
                    ),
                ),
            )
        }
    }

    @Test
    fun allowsOnlyExplicitCanonicalUniversalLinkOrigins() {
        val parser = WalletIngressParser(
            setOf("https://wallet.bund.de/", "https://wallet.example:8443"),
        )
        val query = query("request_uri" to "https://verifier.example/request/one")

        assertEquals(
            WalletIngressRequest.PresentationByReference(
                "https://verifier.example/request/one",
                null,
            ),
            parser.parse("https://wallet.bund.de/open/presentation?$query"),
        )
        assertEquals(
            WalletIngressRequest.PresentationByReference(
                "https://verifier.example/request/one",
                null,
            ),
            parser.parse("https://wallet.example:8443/another/path?$query"),
        )
        listOf(
            "https://wallet.bund.de.evil.example/open?$query",
            "https://attacker.example/open?$query",
            "https://wallet.example/open?$query",
            "https://wallet.example:9443/open?$query",
        ).forEach { link ->
            assertEquals(link, WalletIngressRequest.Unrecognized, parser.parse(link))
        }
        assertEquals(
            WalletIngressRequest.Unrecognized,
            WalletIngressParser().parse("https://wallet.bund.de/open?$query"),
        )
    }

    @Test
    fun rejectsCustomSchemeAuthorityPathCaseUserInfoAndFragments() {
        val validQuery = query("request_uri" to "https://verifier.example/request")
        listOf(
            "OPENID4VP://?$validQuery",
            "openid4vp:?$validQuery",
            "openid4vp:///$validQuery",
            "openid4vp://verifier.example?$validQuery",
            "openid4vp://user@verifier.example?$validQuery",
            "openid4vp://:8443?$validQuery",
            "openid4vp://?$validQuery#fragment",
            "openid4vp://?/path&$validQuery",
            "openid4vp-evil://?$validQuery",
            " openid4vp://?$validQuery",
            "openid4vp://?$validQuery\n",
            "openid4vp://?$validQuery\\suffix",
        ).forEach { input ->
            assertEquals(input, WalletIngressRequest.Unrecognized, WalletIngressParser().parse(input))
        }
    }

    @Test
    fun rejectsUnsafeOrNonCanonicalReferenceDestinationsAndIssuers() {
        val parser = WalletIngressParser()
        val unsafeTargets = listOf(
            "http://issuer.example/offer",
            "https://localhost/offer",
            "https://service.local/offer",
            "https://single-label/offer",
            "https://127.0.0.1/offer",
            "https://169.254.169.254/latest/meta-data",
            "https://[::1]/offer",
            "https://user@example.com/offer",
            "https://issuer.example/offer#fragment",
            "https://issuer.example:443/offer",
            "https://ISSUER.example/offer",
            "https://0177.0.0.1/offer",
            "https://xn--a.example/offer",
        )

        unsafeTargets.forEach { target ->
            assertEquals(
                target,
                WalletIngressRequest.Unrecognized,
                parser.parse(
                    walletUrl("openid-credential-offer", "credential_offer_uri" to target),
                ),
            )
            assertEquals(
                target,
                WalletIngressRequest.Unrecognized,
                parser.parse(walletUrl("openid4vp", "request_uri" to target)),
            )
        }

        val inlineHttp =
            """{"credential_issuer":"http://issuer.example","credential_configuration_ids":["pid"]}"""
        val inlineQuery =
            """{"credential_issuer":"https://issuer.example?tenant=one","credential_configuration_ids":["pid"]}"""
        listOf(inlineHttp, inlineQuery).forEach { offer ->
            assertEquals(
                WalletIngressRequest.Unrecognized,
                parser.parse(walletUrl("openid-credential-offer", "credential_offer" to offer)),
            )
        }
    }

    @Test
    fun rejectsDuplicateConflictingAndDroppedInputs() {
        val parser = WalletIngressParser()
        val inline =
            """{"credential_issuer":"https://issuer.example","credential_configuration_ids":["pid"]}"""
        val requestUri = "https://verifier.example/request"
        val hostileQueries = listOf(
            query("request_uri" to requestUri, "request_uri" to "https://other.example/request"),
            "request_uri=${encode(requestUri)}&request%5Furi=${encode(requestUri)}",
            query("request_uri" to requestUri, "client_id" to "one", "client_id" to "two"),
            query("request_uri" to requestUri, "credential_offer" to inline),
            query("request_uri" to requestUri, "dcql_query" to "{}"),
            query("request_uri" to requestUri, "ignored" to "security-value"),
            query("request" to "signed.jwt", "request_uri" to requestUri),
        )
        hostileQueries.forEach { hostile ->
            assertEquals(
                hostile,
                WalletIngressRequest.Unrecognized,
                parser.parse("openid4vp://?$hostile"),
            )
        }

        listOf(
            query("credential_offer" to inline, "credential_offer_uri" to "https://issuer.example/o"),
            query("credential_offer" to inline, "client_id" to "verifier.example"),
            query("credential_offer" to inline, "ignored" to "security-value"),
        ).forEach { hostile ->
            assertEquals(
                WalletIngressRequest.Unrecognized,
                parser.parse("openid-credential-offer://?$hostile"),
            )
        }
    }

    @Test
    fun rejectsUnsupportedPresentationInputsAndEveryRequestUriMethod() {
        val parser = WalletIngressParser()
        val requestUri = "https://verifier.example/request"
        val unsupported = listOf(
            listOf("request" to "signed.jwt"),
            listOf("presentation_definition" to "{}"),
            listOf("presentation_definition_uri" to "https://verifier.example/pd"),
            listOf("dcql_query" to "{}"),
            listOf("request_uri" to requestUri, "request_uri_method" to "get"),
            listOf("request_uri" to requestUri, "request_uri_method" to "post"),
            listOf("request_uri" to requestUri, "request_uri_method" to "GET"),
        )

        unsupported.forEach { parameters ->
            assertEquals(
                parameters.toString(),
                WalletIngressRequest.Unrecognized,
                parser.parse(walletUrl("openid4vp", *parameters.toTypedArray())),
            )
        }
        assertEquals(
            WalletIngressRequest.Unrecognized,
            parser.parse(walletUrl("openid4vp", "client_id" to "verifier.example")),
        )
    }

    @Test
    fun rejectsMalformedEmptyAndAmbiguousQueryEncoding() {
        val parser = WalletIngressParser()
        val requestUri = encode("https://verifier.example/request")
        listOf(
            "openid4vp://?request_uri",
            "openid4vp://?request_uri=",
            "openid4vp://?=value",
            "openid4vp://?request_uri=$requestUri&",
            "openid4vp://?&request_uri=$requestUri",
            "openid4vp://?request_uri=$requestUri&&client_id=one",
            "openid4vp://?request%ZZuri=$requestUri",
            "openid4vp://?request_uri=%C3%28",
            "openid4vp://?request_uri=$requestUri&client_id=one+two",
            "openid4vp://?request_uri=$requestUri&client%00id=one",
            "openid4vp://?request_uri=$requestUri&client_id=one%00two",
        ).forEach { input ->
            assertEquals(input, WalletIngressRequest.Unrecognized, parser.parse(input))
        }
    }

    @Test
    fun enforcesInputQueryItemAndClientIdBudgets() {
        val parser = WalletIngressParser()
        assertEquals(
            WalletIngressRequest.Unrecognized,
            parser.parse("a".repeat(WalletIngressParser.MAXIMUM_INPUT_BYTES + 1)),
        )
        assertEquals(
            WalletIngressRequest.Unrecognized,
            parser.parse(
                "openid4vp://?" +
                    "a".repeat(WalletIngressParser.MAXIMUM_QUERY_NAME_BYTES + 1) +
                    "=value",
            ),
        )
        assertEquals(
            WalletIngressRequest.Unrecognized,
            parser.parse(
                "openid4vp://?ignored=" +
                    "a".repeat(WalletIngressParser.MAXIMUM_QUERY_VALUE_BYTES + 1),
            ),
        )
        val tooMany = (0..WalletIngressParser.MAXIMUM_QUERY_ITEMS).map { "ignored$it" to "value" }
        assertEquals(
            WalletIngressRequest.Unrecognized,
            parser.parse(walletUrl("openid4vp", *tooMany.toTypedArray())),
        )
        assertEquals(
            WalletIngressRequest.Unrecognized,
            parser.parse(
                walletUrl(
                    "openid4vp",
                    "request_uri" to "https://verifier.example/request",
                    "client_id" to "a".repeat(WalletIngressParser.MAXIMUM_CLIENT_ID_BYTES + 1),
                ),
            ),
        )

        val rawOverBudget = "ignored=" + "a".repeat(WalletIngressParser.MAXIMUM_QUERY_BYTES)
        assertEquals(
            WalletIngressRequest.Unrecognized,
            parser.parse("openid4vp://?$rawOverBudget"),
        )
    }

    @Test
    fun rejectsMalformedAmbiguousOrOversizedInlineOffers() {
        val parser = WalletIngressParser()
        val ids = (0..WalletIngressParser.MAXIMUM_CONFIGURATION_IDS).joinToString(",") {
            "\"credential-$it\""
        }
        val cases = listOf(
            "[]",
            "{}",
            """{"credential_issuer":7,"credential_configuration_ids":["pid"]}""",
            """{"credential_issuer":"https://issuer.example","credential_configuration_ids":"pid"}""",
            """{"credential_issuer":"https://issuer.example","credential_configuration_ids":[7]}""",
            """{"credential_issuer":"https://issuer.example","credential_configuration_ids":[]}""",
            """{"credential_issuer":"https://issuer.example","credential_configuration_ids":[""]}""",
            """{"credential_issuer":"https://issuer.example","credential_configuration_ids":["pid","pid"]}""",
            """{"credential_issuer":"https://issuer.example","credential_configuration_ids":["${"a".repeat(WalletIngressParser.MAXIMUM_CONFIGURATION_ID_BYTES + 1)}"]}""",
            """{"credential_issuer":"https://issuer.example","credential_configuration_ids":[$ids]}""",
            """{"credential_issuer":"https://issuer.example","credential_configuration_ids":["pid"]""",
            """{"credential_issuer":"https://one.example","credential_issuer":"https://two.example","credential_configuration_ids":["pid"]}""",
            """{"credential_issuer":"https://one.example","credential_\u0069ssuer":"https://two.example","credential_configuration_ids":["pid"]}""",
            """{"credential_issuer":"https://issuer.example","credential_configuration_ids":["pid"],"grants":{"a":1,"\u0061":2}}""",
        )

        cases.forEach { offer ->
            assertEquals(
                offer,
                WalletIngressRequest.Unrecognized,
                parser.parse(walletUrl("openid-credential-offer", "credential_offer" to offer)),
            )
        }

        val tooDeep = "[".repeat(33) + "0" + "]".repeat(33)
        val deepOffer =
            """{"credential_issuer":"https://issuer.example","credential_configuration_ids":["pid"],"grants":$tooDeep}"""
        assertEquals(
            WalletIngressRequest.Unrecognized,
            parser.parse(walletUrl("openid-credential-offer", "credential_offer" to deepOffer)),
        )
    }

    @Test
    fun rejectsInvalidOrAmbiguousUniversalLinkConfiguration() {
        listOf(
            setOf("http://wallet.example"),
            setOf("https://wallet.example/path"),
            setOf("https://wallet.example?tenant=one"),
            setOf("https://wallet.example:443"),
            setOf("https://LOCALHOST"),
            setOf("https://wallet.example", "https://wallet.example/"),
        ).forEach { origins ->
            assertThrows(IllegalArgumentException::class.java) {
                WalletIngressParser(origins)
            }
        }

        val tooMany = (0..WalletIngressParser.MAXIMUM_UNIVERSAL_LINK_ORIGINS).map {
            "https://wallet$it.example"
        }.toSet()
        assertThrows(IllegalArgumentException::class.java) {
            WalletIngressParser(tooMany)
        }
    }

    @Test
    fun canonicalIngressUrlValidationDoesNotResolveDns() {
        val policy = ProductionUrlPolicy {
            throw AssertionError("QR classification attempted DNS")
        }
        assertEquals(
            "https://wallet.example/request",
            policy.validateForIngress("https://wallet.example/request").toString(),
        )
        assertThrows(WalletHttpClientException.UnsafeDestination::class.java) {
            policy.validateForIngress("https://127.0.0.1/request")
        }
    }

    @Test
    fun intentAdapterAcceptsOnlyUnambiguousBrowsableViewData() {
        val parser = WalletIngressParser()
        val adapter = AndroidWalletIngress(parser)
        val data = walletUrl("openid4vp", "request_uri" to "https://verifier.example/request")
        val expected = WalletIngressRequest.PresentationByReference(
            "https://verifier.example/request",
            null,
        )
        assertEquals(
            expected,
            adapter.parseViewIntent(
                action = Intent.ACTION_VIEW,
                categories = setOf(Intent.CATEGORY_BROWSABLE, Intent.CATEGORY_DEFAULT),
                dataString = data,
                hasClipData = false,
                hasSelector = false,
                mimeType = null,
            ),
        )

        val hostile = listOf(
            IntentCase(Intent.ACTION_SEND, setOf(Intent.CATEGORY_BROWSABLE), data),
            IntentCase(Intent.ACTION_VIEW, emptySet(), data),
            IntentCase(Intent.ACTION_VIEW, setOf(Intent.CATEGORY_BROWSABLE), null),
            IntentCase(
                Intent.ACTION_VIEW,
                setOf(Intent.CATEGORY_BROWSABLE),
                data,
                hasClipData = true,
            ),
            IntentCase(
                Intent.ACTION_VIEW,
                setOf(Intent.CATEGORY_BROWSABLE),
                data,
                hasSelector = true,
            ),
            IntentCase(
                Intent.ACTION_VIEW,
                setOf(Intent.CATEGORY_BROWSABLE),
                data,
                mimeType = "text/plain",
            ),
            IntentCase(
                Intent.ACTION_VIEW,
                setOf(Intent.CATEGORY_BROWSABLE) + (0..8).map { "category-$it" },
                data,
            ),
            IntentCase(
                Intent.ACTION_VIEW,
                setOf(Intent.CATEGORY_BROWSABLE, "x".repeat(257)),
                data,
            ),
        )
        hostile.forEach { case ->
            assertEquals(
                case.toString(),
                WalletIngressRequest.Unrecognized,
                adapter.parseViewIntent(
                    action = case.action,
                    categories = case.categories,
                    dataString = case.dataString,
                    hasClipData = case.hasClipData,
                    hasSelector = case.hasSelector,
                    mimeType = case.mimeType,
                ),
            )
        }
    }

    private data class IntentCase(
        val action: String?,
        val categories: Set<String>,
        val dataString: String?,
        val hasClipData: Boolean = false,
        val hasSelector: Boolean = false,
        val mimeType: String? = null,
    )

    private fun walletUrl(scheme: String, vararg parameters: Pair<String, String>): String =
        "$scheme://?${query(*parameters)}"

    private fun query(vararg parameters: Pair<String, String>): String = parameters.joinToString("&") {
        "${encode(it.first)}=${encode(it.second)}"
    }

    private fun encode(value: String): String = buildString {
        value.toByteArray(Charsets.UTF_8).forEach { signed ->
            val byte = signed.toInt() and 0xff
            val isUnreserved =
                byte in 'a'.code..'z'.code ||
                    byte in 'A'.code..'Z'.code ||
                    byte in '0'.code..'9'.code ||
                    byte == '-'.code ||
                    byte == '.'.code ||
                    byte == '_'.code ||
                    byte == '~'.code
            if (isUnreserved) {
                append(byte.toChar())
            } else {
                append('%')
                append(HEX[byte ushr 4])
                append(HEX[byte and 0x0f])
            }
        }
    }

    companion object {
        private const val HEX = "0123456789ABCDEF"
    }
}
