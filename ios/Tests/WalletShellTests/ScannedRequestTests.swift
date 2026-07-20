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
