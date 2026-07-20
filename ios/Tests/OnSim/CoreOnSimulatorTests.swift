import XCTest

/// Drives the REAL Rust wallet core — `WalletEngine` + `DemoWallet`, backed by aws-lc-rs compiled
/// for `aarch64-apple-ios-sim` — end to end ON THE SIMULATOR. If these pass in `xcodebuild test`,
/// the core's crypto, trust, data-minimisation and SCA logic execute correctly on the iOS runtime,
/// not just on the host. The screens asserted are the core's own `ScreenDescription`s over the FFI.
final class CoreOnSimulatorTests: XCTestCase {
    private func makeExecutor(
        _ engine: WalletEngine, _ demo: DemoWallet, _ s: DemoScenario,
        issuer: IssuerResponder? = nil,
        render: @escaping (ScreenDescription) -> Void
    ) -> EffectExecutor {
        EffectExecutor(
            engine: engine,
            signer: DemoSigner(demo: demo),
            http: StubHttpClient(),
            storage: InMemoryStorage(),
            trust: DemoTrustResolver(certChain: s.rpCertChain, redirectUris: s.registeredRedirectUris),
            issuer: issuer,
            render: render)
    }

    func testPresentationRunsOnSimulator() async throws {
        let engine = WalletEngine(walletClientId: "wallet.example", deviceKeyRef: "device-key")
        let demo = DemoWallet()
        let s = demo.scenario()
        let issuance = demo.issuanceScenario()
        engine.loadDeviceKey(devicePublicKey: issuance.devicePublicKey)
        // The clock MUST be set before loading the trusted list: the core verifies the list (and
        // the RP/CA certificate validity windows) against `now_epoch`, which defaults to 0 (1970)
        // when unset — at which point the real certs are not yet valid and the list is rejected.
        _ = engine.handleEventJson(eventJson: WalletEventJSON.setClock(epoch: issuance.epoch))
        _ = engine.loadTrustList(
            signedList: issuance.trustList,
            operatorPublicKey: issuance.operatorPublicKey)
        _ = engine.loadWua(
            wuaJwt: issuance.wuaJwt,
            providerPublicKey: issuance.walletProviderPublicKey)

        // Seed through the same issuance event path as the app. No direct credential loader is part
        // of WalletEngineDriving, so this test cannot bypass issuer trust or proof-of-possession.
        let issuer = DemoIssuer(
            credentialCompact: Data(issuance.pidCredentialCompact.utf8),
            cNonce: 43)
        let issuanceExecutor = makeExecutor(engine, demo, s, issuer: issuer) { _ in }
        try await issuanceExecutor.send(
            eventJson: WalletEventJSON.credentialOfferReceived(
                offer: issuance.offer,
                issuerCertChain: issuance.issuerCertChain,
                issuerId: issuance.issuerId))

        var screens: [ScreenDescription] = []
        let exec = makeExecutor(engine, demo, s) { screens.append($0) }

        try await exec.send(
            eventJson: WalletEventJSON.authorizationRequestReceived(s.presentationRequest))

        // The core validated the RP against the trusted list and computed the minimised consent
        // screen — surfacing ONLY the requested-and-held claim.
        guard case .consent(_, _, let claims)? = screens.last else {
            return XCTFail("expected a consent screen, got \(String(describing: screens.last))")
        }
        XCTAssertEqual(claims, ["age_over_18"])

        // Consent → device signs (demo key) → vp_token assembled + delivered. No throw/crash means
        // the sign + key-binding path ran with the simulator's real crypto.
        try await exec.send(eventJson: WalletEventJSON.userConsented())
    }

    func testPaymentRunsOnSimulator() async throws {
        let engine = WalletEngine(walletClientId: "wallet.example", deviceKeyRef: "device-key")
        let demo = DemoWallet()
        let s = demo.scenario()

        var screens: [ScreenDescription] = []
        let exec = makeExecutor(engine, demo, s) { screens.append($0) }

        try await exec.send(eventJson: WalletEventJSON.setClock(epoch: s.epoch))
        try await exec.send(
            eventJson: WalletEventJSON.paymentAuthorizationRequestReceived(s.paymentRequest))

        guard case .paymentConfirmation(let payee, _, let amount, let currency)? = screens.last else {
            return XCTFail("expected a payment confirmation, got \(String(describing: screens.last))")
        }
        XCTAssertEqual(payee, "Acme Store")
        XCTAssertEqual(amount, 1299)
        XCTAssertEqual(currency, "EUR")

        // Approve → device signs the dynamic-linking binding (SCA) → auth code posted.
        try await exec.send(eventJson: WalletEventJSON.paymentApproved())
    }
}
