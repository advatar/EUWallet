import XCTest
@testable import WalletShell

/// Unit tests for the QR/deep-link classifier that routes a scanned payload to the right wallet
/// flow (add-a-credential vs. present-to-a-verifier). Pure parsing — no camera, no network.
final class ScannedRequestTests: XCTestCase {
    private func url(scheme: String, items: [String: String]) -> String {
        var c = URLComponents()
        c.scheme = scheme
        c.host = ""
        c.queryItems = items.map { URLQueryItem(name: $0.key, value: $0.value) }
        return c.string!
    }

    private func url(scheme: String, queryItems: [URLQueryItem]) -> String {
        var c = URLComponents()
        c.scheme = scheme
        c.host = ""
        c.queryItems = queryItems
        return c.string!
    }

    func testInlineCredentialOffer() {
        let json = #"{"credential_issuer":"https://issuer.eudiw.dev","credential_configuration_ids":["eu.europa.ec.eudi.pid_mdoc","eu.europa.ec.eudi.mdl_mdoc"]}"#
        let text = url(scheme: "openid-credential-offer", items: ["credential_offer": json])
        guard case let .credentialOffer(issuer, ids) = ScannedRequest.parse(text) else {
            return XCTFail("expected .credentialOffer, got \(ScannedRequest.parse(text))")
        }
        XCTAssertEqual(issuer, "https://issuer.eudiw.dev")
        XCTAssertEqual(ids, ["eu.europa.ec.eudi.pid_mdoc", "eu.europa.ec.eudi.mdl_mdoc"])
    }

    func testCredentialOfferByReference() {
        let text = url(scheme: "openid-credential-offer",
                       items: ["credential_offer_uri": "https://issuer.eudiw.dev/offer/abc123"])
        XCTAssertEqual(
            ScannedRequest.parse(text),
            .credentialOfferByReference(uri: "https://issuer.eudiw.dev/offer/abc123"))
    }

    func testPresentationByRequestUri() {
        let text = url(scheme: "openid4vp",
                       items: ["client_id": "verifier.eudiw.dev",
                               "request_uri": "https://verifier.eudiw.dev/request/xyz"])
        guard case let .presentation(requestUri, clientId) = ScannedRequest.parse(text) else {
            return XCTFail("expected .presentation")
        }
        XCTAssertEqual(requestUri, "https://verifier.eudiw.dev/request/xyz")
        XCTAssertEqual(clientId, "verifier.eudiw.dev")
    }

    func testHaipSchemePresentation() {
        let text = url(scheme: "haip", items: ["request_uri": "https://verifier.eudiw.dev/r/1"])
        guard case .presentation = ScannedRequest.parse(text) else {
            return XCTFail("haip:// should classify as a presentation request")
        }
    }

    func testUnknownLink() {
        guard case .unknown = ScannedRequest.parse("https://example.com/not-a-wallet-link") else {
            return XCTFail("a plain web URL is not a wallet link")
        }
    }

    func testOnlyWalletSchemesOrAllowlistedUniversalLinkOriginsCanTriggerFlows() {
        let query = "request_uri=https%3A%2F%2Fverifier.example%2Frequest%2F1"
        let universalLink = "https://wallet.bund.de/open?\(query)"
        let attackerLink = "https://attacker.example/open?\(query)"

        guard case .unknown = ScannedRequest.parse(universalLink) else {
            return XCTFail("an unconfigured universal-link origin triggered a wallet flow")
        }
        guard case let .presentation(requestUri, _) = ScannedRequest.parse(
            universalLink,
            allowedUniversalLinkOrigins: ["https://wallet.bund.de/"])
        else { return XCTFail("the allowlisted universal-link origin was not recognised") }
        XCTAssertEqual(requestUri, "https://verifier.example/request/1")

        guard case .unknown = ScannedRequest.parse(
            attackerLink,
            allowedUniversalLinkOrigins: ["https://wallet.bund.de"])
        else { return XCTFail("an attacker origin bypassed the universal-link allowlist") }

        let inlineOffer = #"{"credential_issuer":"https://issuer.example","credential_configuration_ids":["pid"]}"#
        for request in [
            url(scheme: "openid4vp-evil", items: ["request_uri": "https://verifier.example/r"]),
            url(scheme: "openid4vp", items: ["credential_offer": inlineOffer]),
            url(
                scheme: "openid-credential-offer",
                items: ["request_uri": "https://verifier.example/r"]),
        ] {
            guard case .unknown = ScannedRequest.parse(request) else {
                return XCTFail("an unregistered or mismatched outer scheme triggered a flow")
            }
        }
    }

    func testGarbageIsUnknownNotCrash() {
        XCTAssertEqual(ScannedRequest.parse("not a url at all"), .unknown("not a url at all"))
    }

    func testUnsafeByReferenceUrlsAndIssuerAreRejectedDuringClassification() {
        for target in [
            "http://issuer.example/offer",
            "https://localhost/offer",
            "https://127.0.0.1/offer",
            "https://169.254.169.254/offer",
            "https://user@example.com/offer",
            "https://issuer.example/offer#fragment",
            "https://issuer.example:443/offer",
            "https://issuer/offer",
            "https://ISSUER.example/offer",
        ] {
            let offer = url(
                scheme: "openid-credential-offer",
                items: ["credential_offer_uri": target])
            guard case .unknown = ScannedRequest.parse(offer) else {
                return XCTFail("unsafe credential_offer_uri was accepted: \(target)")
            }

            let presentation = url(scheme: "openid4vp", items: ["request_uri": target])
            guard case .unknown = ScannedRequest.parse(presentation) else {
                return XCTFail("unsafe request_uri was accepted: \(target)")
            }
        }

        let inline = #"{"credential_issuer":"http://issuer.example","credential_configuration_ids":["pid"]}"#
        let offer = url(scheme: "openid-credential-offer", items: ["credential_offer": inline])
        guard case .unknown = ScannedRequest.parse(offer) else {
            return XCTFail("HTTP credential issuer was accepted")
        }
    }

    func testDuplicateSecurityParametersAreRejected() {
        var components = URLComponents()
        components.scheme = "openid4vp"
        components.host = ""
        components.queryItems = [
            URLQueryItem(name: "request_uri", value: "https://one.example/request"),
            URLQueryItem(name: "request_uri", value: "https://two.example/request"),
        ]
        guard case .unknown = ScannedRequest.parse(components.string!) else {
            return XCTFail("duplicate request_uri was accepted")
        }

        components.queryItems = [
            URLQueryItem(name: "request_uri", value: "https://one.example/request"),
            URLQueryItem(name: "client_id", value: "one.example"),
            URLQueryItem(name: "client_id", value: "two.example"),
        ]
        guard case .unknown = ScannedRequest.parse(components.string!) else {
            return XCTFail("duplicate client_id was accepted")
        }
    }

    func testConflictingFlowAndPresentationParametersAreRejected() {
        let inlineOffer = #"{"credential_issuer":"https://issuer.example","credential_configuration_ids":["pid"]}"#
        let cases: [[URLQueryItem]] = [
            [
                URLQueryItem(name: "credential_offer", value: inlineOffer),
                URLQueryItem(name: "credential_offer_uri", value: "https://issuer.example/o/1"),
            ],
            [
                URLQueryItem(name: "credential_offer", value: inlineOffer),
                URLQueryItem(name: "request_uri", value: "https://verifier.example/r/1"),
            ],
            [
                URLQueryItem(name: "credential_offer", value: inlineOffer),
                URLQueryItem(name: "client_id", value: "verifier.example"),
            ],
            [
                URLQueryItem(name: "request", value: "signed-request"),
                URLQueryItem(name: "request_uri", value: "https://verifier.example/r/1"),
            ],
            [
                URLQueryItem(name: "presentation_definition", value: "{}"),
                URLQueryItem(
                    name: "presentation_definition_uri",
                    value: "https://verifier.example/pd/1"),
            ],
            [
                URLQueryItem(name: "presentation_definition", value: "{}"),
                URLQueryItem(name: "dcql_query", value: "{}"),
            ],
            [
                URLQueryItem(name: "request_uri", value: "https://verifier.example/r/1"),
                URLQueryItem(name: "dcql_query", value: "{}"),
            ],
        ]

        for queryItems in cases {
            let request = url(scheme: "openid4vp", queryItems: queryItems)
            guard case .unknown = ScannedRequest.parse(request) else {
                return XCTFail("conflicting security parameters were accepted: \(request)")
            }
        }
    }

    func testEmptyMissingAndOversizedSecurityParametersAreRejected() {
        let cases: [[URLQueryItem]] = [
            [URLQueryItem(name: "request_uri", value: nil)],
            [URLQueryItem(name: "request_uri", value: "")],
            [URLQueryItem(name: "request", value: "")],
            [
                URLQueryItem(name: "request", value: "signed-request"),
                URLQueryItem(name: "client_id", value: ""),
            ],
            [URLQueryItem(name: "credential_offer", value: nil)],
            [URLQueryItem(name: "credential_offer_uri", value: "")],
            [URLQueryItem(name: "request", value: String(repeating: "a", count: 16 * 1024 + 1))],
        ]
        for queryItems in cases {
            let request = url(scheme: "openid4vp", queryItems: queryItems)
            guard case .unknown = ScannedRequest.parse(request) else {
                return XCTFail("empty/missing/oversized input was accepted")
            }
        }

        let tooMany = (0...64).map { URLQueryItem(name: "field\($0)", value: "value") }
        guard case .unknown = ScannedRequest.parse(url(scheme: "openid4vp", queryItems: tooMany))
        else { return XCTFail("too many query parameters were accepted") }

        guard case .unknown = ScannedRequest.parse(
            " openid4vp://?request_uri=https%3A%2F%2Fverifier.example%2Fr%2F1")
        else { return XCTFail("non-canonical surrounding whitespace was accepted") }
    }

    func testAmbiguousCredentialOfferJsonAndIssuerIdentifierAreRejected() {
        let duplicateKey = #"{"credential_issuer":"https://issuer.example","credential_\u0069ssuer":"https://attacker.example","credential_configuration_ids":["pid"]}"#
        let duplicateIds = #"{"credential_issuer":"https://issuer.example","credential_configuration_ids":["pid","pid"]}"#
        let emptyId = #"{"credential_issuer":"https://issuer.example","credential_configuration_ids":[""]}"#
        let issuerWithQuery = #"{"credential_issuer":"https://issuer.example?tenant=1","credential_configuration_ids":["pid"]}"#

        for json in [duplicateKey, duplicateIds, emptyId, issuerWithQuery] {
            let request = url(scheme: "openid-credential-offer", items: ["credential_offer": json])
            guard case .unknown = ScannedRequest.parse(request) else {
                return XCTFail("ambiguous credential offer was accepted: \(json)")
            }
        }

        for json in [#"{"id":"one","\u0069d":"two"}"#, #"{"unterminated": [}"#] {
            let request = url(
                scheme: "openid4vp",
                items: ["presentation_definition": json])
            guard case .unknown = ScannedRequest.parse(request) else {
                return XCTFail("ambiguous presentation JSON was accepted: \(json)")
            }
        }
    }

    func testOuterFragmentAndUserInfoAreRejected() {
        let safeRequest = "request_uri=https%3A%2F%2Fverifier.example%2Fr%2F1"
        for request in [
            "openid4vp://?\(safeRequest)#ignored",
            "openid4vp://user@verifier.example?\(safeRequest)",
            "openid4vp://user:password@verifier.example?\(safeRequest)",
        ] {
            guard case .unknown = ScannedRequest.parse(request) else {
                return XCTFail("fragment/userinfo-bearing deep link was accepted")
            }
        }
    }

    func testUnsupportedPresentationSourcesAndRequestUriMethodsAreRejected() {
        let cases: [[String: String]] = [
            ["request": "signed-request-object"],
            ["presentation_definition": "{}"],
            ["presentation_definition_uri": "https://verifier.example/pd/1"],
            ["dcql_query": "{}"],
            [
                "request_uri": "https://verifier.example/request/1",
                "request_uri_method": "get",
            ],
            [
                "request_uri": "https://verifier.example/request/1",
                "request_uri_method": "post",
            ],
            [
                "request_uri": "https://verifier.example/request/1",
                "response_uri": "https://verifier.example/response",
            ],
        ]
        for items in cases {
            guard case .unknown = ScannedRequest.parse(url(scheme: "openid4vp", items: items))
            else { return XCTFail("an unsupported presentation source/method was discarded") }
        }
    }

    func testCustomSchemeAuthorityPortAndPathVariantsAreRejected() {
        let query = "request_uri=https%3A%2F%2Fverifier.example%2Frequest%2F1"
        for request in [
            "openid4vp://verifier.example?\(query)",
            "openid4vp://:8443?\(query)",
            "openid4vp:///?\(query)",
            "openid4vp:?\(query)",
        ] {
            guard case .unknown = ScannedRequest.parse(request) else {
                return XCTFail("a non-canonical custom-scheme shape was accepted: \(request)")
            }
        }
    }

    func testOversizedScanAndCredentialConfigurationSetAreRejected() {
        guard case .unknown = ScannedRequest.parse(String(repeating: "a", count: 32 * 1024 + 1))
        else { return XCTFail("oversized scan was accepted") }

        let ids = (0...32).map { "credential-\($0)" }
        let object: [String: Any] = [
            "credential_issuer": "https://issuer.example",
            "credential_configuration_ids": ids,
        ]
        let data = try! JSONSerialization.data(withJSONObject: object)
        let json = String(decoding: data, as: UTF8.self)
        let offer = url(scheme: "openid-credential-offer", items: ["credential_offer": json])
        guard case .unknown = ScannedRequest.parse(offer) else {
            return XCTFail("oversized configuration set was accepted")
        }
    }
}
