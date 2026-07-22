import XCTest

private final class SimulatorDurableStore: DurableStateStore {
    private var record: DurableStateRecord?

    func load(context: DurableStateContext) -> DurableStateLoadResult {
        record.map(DurableStateLoadResult.record) ?? .empty
    }

    func commit(
        expectedGeneration: UInt64,
        nextGeneration: UInt64,
        plaintext: Data,
        context: DurableStateContext
    ) throws -> DurableStateRecord {
        let actual = record?.generation ?? 0
        guard actual == expectedGeneration else {
            throw DurableStateStoreError.generationConflict(
                expected: expectedGeneration,
                actual: actual)
        }
        let committed = DurableStateRecord(generation: nextGeneration, plaintext: plaintext)
        record = committed
        return committed
    }
}

/// Drives the REAL Rust wallet core — `WalletEngine` + `DemoWallet`, backed by aws-lc-rs compiled
/// for `aarch64-apple-ios-sim` — end to end ON THE SIMULATOR. If these pass in `xcodebuild test`,
/// the core's crypto, trust, data-minimisation and SCA logic execute correctly on the iOS runtime,
/// not just on the host. The screens asserted are the core's own `ScreenDescription`s over the FFI.
final class CoreOnSimulatorTests: XCTestCase {
    private func makeExecutor(
        _ lifecycle: DurableLifecycleCoordinator, _ demo: DemoWallet, _ s: DemoScenario,
        issuer: IssuerResponder? = nil,
        render: @escaping (UInt64?, Data?, ScreenDescription) -> Void
    ) -> EffectExecutor {
        EffectExecutor(
            lifecycle: lifecycle,
            signer: DemoSigner(demo: demo),
            http: StubHttpClient(),
            storage: InMemoryStorage(),
            trust: DemoTrustResolver(certChain: s.rpCertChain, redirectUris: s.registeredRedirectUris),
            issuer: issuer,
            render: render)
    }

    private func makeRuntime(
        issuance: IssuanceScenario
    ) throws -> FfiWalletRuntime {
        try FfiWalletRuntime.ephemeralDemo(
            applicationIdentifier: "eu.advatar.wallet.demo.tests",
            walletClientId: "wallet.example",
            deviceKeyReference: "device-key",
            environment: CoreDurableEnvironment(
                clockEpoch: issuance.epoch,
                signedTrustList: issuance.trustList,
                operatorPublicKey: issuance.operatorPublicKey,
                devicePublicKey: issuance.devicePublicKey,
                wuaJwt: issuance.wuaJwt,
                wuaProviderPublicKey: issuance.walletProviderPublicKey))
    }

    private func makeRuntime(
        issuance: IssuanceScenario,
        store: any DurableStateStore
    ) throws -> FfiWalletRuntime {
        try FfiWalletRuntime.durable(
            applicationIdentifier: "eu.advatar.wallet.demo.tests",
            walletClientId: "wallet.example",
            deviceKeyReference: "device-key",
            environment: CoreDurableEnvironment(
                clockEpoch: issuance.epoch,
                signedTrustList: issuance.trustList,
                operatorPublicKey: issuance.operatorPublicKey,
                devicePublicKey: issuance.devicePublicKey,
                wuaJwt: issuance.wuaJwt,
                wuaProviderPublicKey: issuance.walletProviderPublicKey),
            store: store)
    }

    func testPresentationRunsOnSimulator() async throws {
        let demo = DemoWallet()
        let s = demo.scenario()
        let issuance = demo.issuanceScenario()
        let runtime = try makeRuntime(issuance: issuance)

        // Seed through the same issuance event path as the app. No direct credential loader is part
        // of the lifecycle surface, so this test cannot bypass durability, issuer trust or proof
        // of possession.
        let issuer = DemoIssuer(
            credentialCompact: Data(issuance.pidCredentialCompact.utf8),
            cNonce: 43)
        let issuanceExecutor = makeExecutor(runtime.lifecycle, demo, s, issuer: issuer) { _, _, _ in }
        try await issuanceExecutor.send(
            eventJson: WalletEventJSON.credentialOfferReceived(
                offer: issuance.offer,
                issuerCertChain: issuance.issuerCertChain,
                issuerId: issuance.issuerId))

        var screens: [ScreenDescription] = []
        var decisionOperationId: UInt64?
        var decisionAuthorizationHash: Data?
        let exec = makeExecutor(runtime.lifecycle, demo, s) { operationId, authorizationHash, screen in
            decisionOperationId = operationId
            decisionAuthorizationHash = authorizationHash
            screens.append(screen)
        }

        try await exec.send(
            eventJson: WalletEventJSON.authorizationRequestReceived(s.presentationRequest))

        // The core validated the RP against the trusted list and computed the minimised consent
        // screen — surfacing ONLY the requested-and-held claim.
        guard case .consent(_, _, let claims, _)? = screens.last else {
            return XCTFail("expected a consent screen, got \(String(describing: screens.last))")
        }
        XCTAssertEqual(claims, ["age_over_18"])

        // Consent → device signs (demo key) → vp_token assembled + delivered. No throw/crash means
        // the sign + key-binding path ran with the simulator's real crypto.
        try await exec.send(eventJson: WalletEventJSON.userConsented(
            operationId: try XCTUnwrap(decisionOperationId),
            authorizationHash: try XCTUnwrap(decisionAuthorizationHash)))
    }

    func testPaymentRunsOnSimulator() async throws {
        let demo = DemoWallet()
        let s = demo.scenario()
        let runtime = try makeRuntime(issuance: demo.issuanceScenario())

        var screens: [ScreenDescription] = []
        var decisionOperationId: UInt64?
        var decisionAuthorizationHash: Data?
        let exec = makeExecutor(runtime.lifecycle, demo, s) { operationId, authorizationHash, screen in
            decisionOperationId = operationId
            decisionAuthorizationHash = authorizationHash
            screens.append(screen)
        }

        try await exec.send(
            eventJson: WalletEventJSON.paymentAuthorizationRequestReceived(s.paymentRequest))

        guard case .paymentConfirmation(let payee, _, let amount, let currency)? = screens.last else {
            return XCTFail("expected a payment confirmation, got \(String(describing: screens.last))")
        }
        XCTAssertEqual(payee, "Acme Store")
        XCTAssertEqual(amount, 1299)
        XCTAssertEqual(currency, "EUR")

        // Approve → device signs the dynamic-linking binding (SCA) → auth code posted.
        try await exec.send(eventJson: WalletEventJSON.paymentApproved(
            operationId: try XCTUnwrap(decisionOperationId),
            authorizationHash: try XCTUnwrap(decisionAuthorizationHash)))
    }

    func testGeneratedAdapterRestoresIssuedAndRedactedStateAfterRestart() async throws {
        let demo = DemoWallet()
        let scenario = demo.scenario()
        let issuance = demo.issuanceScenario()
        let store = SimulatorDurableStore()
        var firstRuntime: FfiWalletRuntime? = try makeRuntime(
            issuance: issuance,
            store: store)
        var executor: EffectExecutor? = makeExecutor(
            try XCTUnwrap(firstRuntime).lifecycle,
            demo,
            scenario,
            issuer: DemoIssuer(
                credentialCompact: Data(issuance.pidCredentialCompact.utf8),
                cNonce: 91)
        ) { _, _, _ in }

        let issuanceOutcome = try await XCTUnwrap(executor).send(
            eventJson: WalletEventJSON.credentialOfferReceived(
                offer: issuance.offer,
                issuerCertChain: issuance.issuerCertChain,
                issuerId: issuance.issuerId))
        XCTAssertEqual(issuanceOutcome, .succeeded)

        let logBefore = try XCTUnwrap(
            JSONSerialization.jsonObject(
                with: Data(try XCTUnwrap(firstRuntime).transactionLogJSON().utf8))
                as? [[String: Any]])
        let firstSeq = try XCTUnwrap((logBefore.first?["seq"] as? NSNumber)?.uint64Value)
        let redactionOutcome = try await XCTUnwrap(executor).send(
            eventJson: WalletEventJSON.historyRedaction(seq: firstSeq))
        XCTAssertEqual(redactionOutcome, .idle)

        let heldAfterRedaction = try XCTUnwrap(firstRuntime).heldCredentialsJSON()
        let logAfterRedaction = try XCTUnwrap(firstRuntime).transactionLogJSON()
        let reportAfterRedaction = try XCTUnwrap(firstRuntime).transactionReportJSON()
        let redactedLog = try XCTUnwrap(
            JSONSerialization.jsonObject(with: Data(logAfterRedaction.utf8))
                as? [[String: Any]])
        XCTAssertEqual(redactedLog.first?["redacted"] as? Bool, true)

        executor = nil
        firstRuntime = nil
        let restored = try makeRuntime(issuance: issuance, store: store)

        XCTAssertEqual(restored.heldCredentialsJSON(), heldAfterRedaction)
        XCTAssertEqual(restored.transactionLogJSON(), logAfterRedaction)
        XCTAssertEqual(restored.transactionReportJSON(), reportAfterRedaction)
    }
}
