import XCTest
@testable import WalletShell

/// A scripted engine standing in for the Rust WalletEngine over the JSON contract. It returns the
/// same effect sequence the real core does, so we can test the SHELL's effect dispatch (signer,
/// http, renderer, trust) on the host without linking the xcframework. The core's own logic is
/// tested in Rust (wallet-core/tests/e2e_flow.rs).
final class MockEngine: WalletEngineDriving {
    func loadCredential(issuerJwt: String, disclosuresByClaimJson: String, statusIndex: UInt64?) {}
    func handleEventJson(eventJson: String) -> String {
        if eventJson.contains("\"authorizationRequestReceived\"") {
            return #"[{"type":"resolveRpTrust","clientId":"rp.example"}]"#
        }
        if eventJson.contains("\"rpCertChainResolved\"") {
            return #"[{"type":"persistNonce","nonce":42},{"type":"render","screen":{"screen":"consent","rpDisplayName":"Example RP","purpose":"Prove age","requestedClaims":["age_over_18"]}}]"#
        }
        if eventJson.contains("\"userConsented\"") {
            return #"[{"type":"sign","keyRef":"device-key","payload":[1,2,3]}]"#
        }
        if eventJson.contains("\"deviceSignatureProduced\"") {
            return #"[{"type":"http","url":"https://rp.example/response","body":[9,9,9]}]"#
        }
        if eventJson.contains("\"presentationDelivered\"") {
            return #"[{"type":"close"}]"#
        }
        if eventJson.contains("\"paymentAuthorizationRequestReceived\"") {
            return #"[{"type":"render","screen":{"screen":"paymentConfirmation","creditorName":"Acme Store","creditorAccount":"DE89","amountMinor":1299,"currency":"EUR"}}]"#
        }
        if eventJson.contains("\"paymentApproved\"") {
            return #"[{"type":"sign","keyRef":"device-key","payload":[7,7,7]},{"type":"http","url":"https://psp.example/authorize","body":[8,8,8]}]"#
        }
        return "[]"
    }
}

final class EffectExecutorTests: XCTestCase {
    private func makeExecutor(
        signer: Signer, http: StubHttpClient, render: @escaping (ScreenDescription) -> Void
    ) -> EffectExecutor {
        EffectExecutor(
            engine: MockEngine(),
            signer: signer,
            http: http,
            storage: InMemoryStorage(),
            trust: StubTrustResolver(certChain: [Data([1, 2, 3])]),
            render: render)
    }

    func testRequestRendersConsentScreen() async {
        var rendered: [ScreenDescription] = []
        let executor = makeExecutor(signer: StubSigner(), http: StubHttpClient()) { rendered.append($0) }

        await executor.send(eventJson: WalletEventJSON.authorizationRequestReceived(Data([1, 2, 3])))

        guard case .consent(let rp, _, let claims)? = rendered.last else {
            return XCTFail("expected a consent screen, got \(String(describing: rendered.last))")
        }
        XCTAssertEqual(rp, "Example RP")
        XCTAssertEqual(claims, ["age_over_18"]) // data minimisation surfaced to the UI
    }

    func testConsentTriggersSecureEnclaveSignThenHttpPost() async {
        let signer = StubSigner()
        let http = StubHttpClient()
        let executor = makeExecutor(signer: signer, http: http) { _ in }

        await executor.send(eventJson: WalletEventJSON.userConsented())

        // The device signer was invoked for the key-binding JWT...
        XCTAssertEqual(signer.signedPayloads.count, 1)
        XCTAssertEqual(signer.signedPayloads.first, Data([1, 2, 3]))
        // ...and the resulting vp_token was posted to the RP.
        XCTAssertEqual(http.posted.count, 1)
        XCTAssertEqual(http.posted.first?.0, "https://rp.example/response")
        XCTAssertEqual(http.posted.first?.1, Data([9, 9, 9]))
    }

    func testDeclineRendersNothingUnexpected() async {
        var rendered: [ScreenDescription] = []
        let executor = makeExecutor(signer: StubSigner(), http: StubHttpClient()) { rendered.append($0) }
        await executor.send(eventJson: WalletEventJSON.userDeclined())
        XCTAssertTrue(rendered.isEmpty)
    }

    func testPaymentRendersConfirmationThenSignsAuthCode() async {
        var rendered: [ScreenDescription] = []
        let signer = StubSigner()
        let http = StubHttpClient()
        let executor = makeExecutor(signer: signer, http: http) { rendered.append($0) }

        await executor.send(eventJson: WalletEventJSON.paymentAuthorizationRequestReceived(Data([1])))
        guard case .paymentConfirmation(let payee, _, let amount, let currency)? = rendered.last else {
            return XCTFail("expected a payment confirmation screen, got \(String(describing: rendered.last))")
        }
        XCTAssertEqual(payee, "Acme Store")
        XCTAssertEqual(amount, 1299)
        XCTAssertEqual(currency, "EUR")

        await executor.send(eventJson: WalletEventJSON.paymentApproved())
        XCTAssertEqual(signer.signedPayloads.first, Data([7, 7, 7])) // SCA auth code signed
        XCTAssertEqual(http.posted.first?.0, "https://psp.example/authorize")
    }
}
