import XCTest
@testable import WalletShell

/// A scripted engine standing in for the Rust WalletEngine over the JSON contract. It returns the
/// same effect sequence the real core does, so the shell's dispatch and fail-closed boundaries can
/// be tested on the host without linking the xcframework.
final class MockEngine: DurableWalletEngineDriving {
    private let response: (String) -> String
    private(set) var receivedEvents: [String] = []
    private(set) var exportedGenerations: [UInt64] = []
    private(set) var preparationCount = 0

    init(response: @escaping (String) -> String = MockEngine.happyPathResponse) {
        self.response = response
    }

    func handleEventJson(eventJson: String) -> String {
        receivedEvents.append(eventJson)
        return response(eventJson)
    }

    func prepareForDurableRestore(environment: CoreDurableEnvironment) {
        preparationCount += 1
    }

    func makeDurableCheckpoint(generation: UInt64) -> CoreDurableCheckpoint {
        exportedGenerations.append(generation)
        var encodedGeneration = generation.bigEndian
        let bytes = withUnsafeBytes(of: &encodedGeneration) { Data($0) }
        return CoreDurableCheckpoint(generation: generation, bytes: bytes)
    }

    func restoreDurableCheckpointRecord(_ checkpoint: CoreDurableCheckpoint) {}

    private static func happyPathResponse(_ eventJson: String) -> String {
        if eventJson.contains("\"authorizationRequestReceived\"") {
            return #"[{"type":"resolveRpTrust","operationId":1,"resultType":"rpCertChainResolved","clientId":"rp.example"}]"#
        }
        if eventJson.contains("\"rpCertChainResolved\"") {
            return #"[{"type":"persistNonce","operationId":2,"resultType":"operationSucceeded","nonce":"opaque-nonce"},{"type":"render","operationId":3,"resultType":"presentationDecision","authorizationHash":[0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0],"screen":{"screen":"consent","rpDisplayName":"Example RP","purpose":"Prove age","requestedClaims":["age_over_18"],"notSharedClaims":["family_name"],"verifierRegistration":"registered","trustMark":"eudiWallet","retention":{"policy":"notStored"},"overAsk":{"result":"withinRegisteredScope"}}}]"#
        }
        if eventJson.contains("\"userConsented\"") {
            return #"[{"type":"sign","operationId":4,"resultType":"deviceSignatureProduced","keyRef":"device-key","payload":[1,2,3]}]"#
        }
        if eventJson.contains("\"deviceSignatureProduced\"") {
            return #"[{"type":"http","operationId":5,"resultType":"presentationDelivered","profile":"openid4vpDirectPost","url":"https://rp.example/response","body":[9,9,9]}]"#
        }
        if eventJson.contains("\"presentationDelivered\"") {
            return #"[{"type":"close"}]"#
        }
        if eventJson.contains("\"userDeclined\"") {
            return #"[{"type":"close"}]"#
        }
        if eventJson.contains("\"paymentAuthorizationRequestReceived\"") {
            return #"[{"type":"render","operationId":6,"resultType":"paymentDecision","authorizationHash":[0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0],"screen":{"screen":"paymentConfirmation","creditorName":"Acme Store","creditorAccount":"DE89","amountMinor":1299,"currency":"EUR"}}]"#
        }
        if eventJson.contains("\"paymentApproved\"") {
            return #"[{"type":"sign","operationId":7,"resultType":"deviceSignatureProduced","keyRef":"device-key","payload":[7,7,7]}]"#
        }
        if eventJson.contains("\"paymentAuthorizationDelivered\"") {
            return #"[{"type":"close"}]"#
        }
        if eventJson.contains("\"operationFailed\"") || eventJson.contains("\"operationCancelled\"") {
            return #"[{"type":"render","screen":{"screen":"error","code":"operation_failed","message":"Operation failed"}},{"type":"close"}]"#
        }
        return "[]"
    }
}

private final class ExecutorTestDurableStore: DurableStateStore {
    private(set) var record: DurableStateRecord?

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

private enum ExpectedFailure: Error { case failure }

private final class FailingSigner: Signer {
    func sign(keyRef: String, payload: Data) throws -> Data { throw ExpectedFailure.failure }
}

private final class CancellingSigner: Signer {
    func sign(keyRef: String, payload: Data) throws -> Data { throw CancellationError() }
}

private final class FailingStorage: SecureStorage {
    func put(key: String, value: Data) throws { throw ExpectedFailure.failure }
    func get(key: String) throws -> Data? { throw ExpectedFailure.failure }
}

private final class FailingIssuer: IssuerResponder {
    func token() async throws -> (bound: Bool, cNonce: UInt64) {
        throw ExpectedFailure.failure
    }

    func credential(proofJwt: Data) async throws -> (format: String, bytes: Data) {
        throw ExpectedFailure.failure
    }
}

private final class FixedCredentialIssuer: IssuerResponder {
    func token() async -> (bound: Bool, cNonce: UInt64) {
        (true, 1)
    }

    func credential(proofJwt: Data) async -> (format: String, bytes: Data) {
        ("dc+sd-jwt", Data("issuer-credential".utf8))
    }
}

private final class FixedHttpClient: HttpClient {
    enum Outcome {
        case response(HttpResponse)
        case failure(HttpClientError)
    }

    private let outcome: Outcome
    init(_ outcome: Outcome) { self.outcome = outcome }

    private(set) var postedProfiles: [HttpDeliveryProfile] = []

    func post(
        url: String,
        body: Data,
        profile: HttpDeliveryProfile
    ) async throws -> HttpResponse {
        postedProfiles.append(profile)
        switch outcome {
        case .response(let response): return response
        case .failure(let error): throw error
        }
    }
}

private final class FixedStatusListResolver: StatusListResolver {
    enum Outcome {
        case resolution(StatusListResolution)
        case failure
    }

    private let outcome: Outcome
    init(_ outcome: Outcome) { self.outcome = outcome }

    func fetch(uri: String) async throws -> StatusListResolution {
        switch outcome {
        case .resolution(let resolution): return resolution
        case .failure: throw ExpectedFailure.failure
        }
    }
}

private final class RecordingTransferOfferPublisher: TransferOfferPublisher {
    private(set) var offeredKeys: [Data] = []

    func publish(offeredKey: Data) async throws {
        offeredKeys.append(offeredKey)
    }
}

private final class RecordingRedirectHandler: OpenID4VPRedirectHandler {
    private let shouldFail: Bool
    private let onHandle: () -> Void
    private(set) var redirects: [URL] = []

    init(shouldFail: Bool = false, onHandle: @escaping () -> Void = {}) {
        self.shouldFail = shouldFail
        self.onHandle = onHandle
    }

    func handle(redirectUri: URL) async throws {
        onHandle()
        if shouldFail { throw ExpectedFailure.failure }
        redirects.append(redirectUri)
    }
}

final class EffectExecutorTests: XCTestCase {
    private static let authorizationHash = Data(repeating: 0, count: 32)

    private func makeExecutor(
        engine: MockEngine = MockEngine(),
        durableStore: ExecutorTestDurableStore = ExecutorTestDurableStore(),
        signer: Signer = StubSigner(),
        http: HttpClient = StubHttpClient(),
        storage: SecureStorage = InMemoryStorage(),
        statusLists: StatusListResolver? = nil,
        issuer: IssuerResponder? = nil,
        transferOffers: TransferOfferPublisher? = nil,
        presentationRedirectHandler: OpenID4VPRedirectHandler? = nil,
        render: @escaping (UInt64?, Data?, ScreenDescription) throws -> Void = { _, _, _ in }
    ) -> EffectExecutor {
        let context = try! DurableLifecycleContextFactory.make(
            applicationIdentifier: "eu.advatar.wallet.tests",
            walletClientId: "wallet.test",
            deviceKeyReference: "device-test-key")
        let lifecycle = DurableLifecycleCoordinator(
            engine: engine,
            store: durableStore,
            context: context)
        try! lifecycle.bootstrap(environment: CoreDurableEnvironment(
            clockEpoch: 1_790_000_000,
            signedTrustList: Data([1]),
            operatorPublicKey: Data([2]),
            devicePublicKey: Data([3]),
            wuaJwt: Data([4]),
            wuaProviderPublicKey: Data([5])))
        return EffectExecutor(
            lifecycle: lifecycle,
            signer: signer,
            http: http,
            storage: storage,
            trust: StubTrustResolver(certChain: [Data([1, 2, 3])]),
            statusLists: statusLists,
            issuer: issuer,
            transferOffers: transferOffers,
            presentationRedirectHandler: presentationRedirectHandler,
            render: render)
    }

    private func assertNoSemanticSuccessOrDecline(
        _ events: [String], file: StaticString = #filePath, line: UInt = #line
    ) {
        XCTAssertFalse(
            events.contains { $0.contains("\"userDeclined\"") },
            "Infrastructure failure became userDeclined",
            file: file,
            line: line)
        XCTAssertFalse(
            events.contains { $0.contains("\"presentationDelivered\"") },
            "Infrastructure failure became presentationDelivered",
            file: file,
            line: line)
    }

    func testExecutorCommitsThroughConcreteLifecycleBeforeRendering() async throws {
        let engine = MockEngine { _ in
            #"[{"type":"render","screen":{"screen":"loading"}}]"#
        }
        let store = ExecutorTestDurableStore()
        var rendered = false
        let executor = makeExecutor(engine: engine, durableStore: store) { _, _, _ in
            rendered = true
        }

        let outcome = try await executor.send(eventJson: #"{"type":"start"}"#)

        XCTAssertEqual(outcome, .awaitingInput)
        XCTAssertTrue(rendered)
        XCTAssertEqual(engine.preparationCount, 1)
        XCTAssertEqual(engine.exportedGenerations, [1])
        XCTAssertEqual(store.record?.generation, 1)
    }

    func testRestoredIssuanceInterruptionRendersWithoutInvokingCore() throws {
        let engine = MockEngine()
        var rendered: ScreenDescription?
        let executor = makeExecutor(engine: engine) { operationId, hash, screen in
            XCTAssertNil(operationId)
            XCTAssertNil(hash)
            rendered = screen
        }

        try executor.presentRestoredState(
            coreOutput: #"[{"type":"render","screen":{"screen":"issuanceRecovery","reason":"sessionInterrupted","documentName":"Digital identity document","attemptsRemaining":null,"canResume":false}}]"#)

        XCTAssertTrue(engine.receivedEvents.isEmpty)
        guard case .issuanceRecovery(let recovery) = rendered else {
            return XCTFail("expected issuance recovery")
        }
        XCTAssertEqual(recovery.reason, .sessionInterrupted)
        XCTAssertFalse(recovery.canResume)
    }

    func testRestoredStateRejectsInteractiveOrResumableEffects() {
        let executor = makeExecutor()
        for output in [
            #"[{"type":"render","operationId":9,"screen":{"screen":"issuanceRecovery","reason":"sessionInterrupted","documentName":"ID","attemptsRemaining":null,"canResume":false}}]"#,
            #"[{"type":"render","screen":{"screen":"issuanceRecovery","reason":"sessionInterrupted","documentName":"ID","attemptsRemaining":null,"canResume":true}}]"#,
            #"[{"type":"requestToken"}]"#,
        ] {
            XCTAssertThrowsError(try executor.presentRestoredState(coreOutput: output))
        }
    }

    func testHistoryMaintenanceEventsAreDurablyCommittedIdleTransitions() async throws {
        let engine = MockEngine { _ in "[]" }
        let store = ExecutorTestDurableStore()
        let executor = makeExecutor(engine: engine, durableStore: store)

        let redactionOutcome = try await executor.send(
            eventJson: WalletEventJSON.historyRedaction(seq: 7))
        let wipeOutcome = try await executor.send(eventJson: WalletEventJSON.historyWipe())

        XCTAssertEqual(redactionOutcome, .idle)
        XCTAssertEqual(wipeOutcome, .idle)

        XCTAssertEqual(
            engine.receivedEvents,
            [
                #"{"type":"redactTransaction","seq":7}"#,
                #"{"type":"wipeTransactionLog"}"#,
            ])
        XCTAssertEqual(engine.exportedGenerations, [1, 2])
        XCTAssertEqual(store.record?.generation, 2)
    }

    func testRequestRendersConsentScreen() async throws {
        var rendered: [ScreenDescription] = []
        var renderedOperationId: UInt64?
        var renderedAuthorizationHash: Data?
        let executor = makeExecutor { operationId, authorizationHash, screen in
            renderedOperationId = operationId
            renderedAuthorizationHash = authorizationHash
            rendered.append(screen)
        }

        let outcome = try await executor.send(
            eventJson: WalletEventJSON.authorizationRequestReceived(Data([1, 2, 3])))

        guard case .consent(
            let rp,
            _,
            let claims,
            let notShared,
            let registration,
            let trustMark,
            let retention,
            let overAsk)? = rendered.last else {
            return XCTFail("expected a consent screen, got \(String(describing: rendered.last))")
        }
        XCTAssertEqual(rp, "Example RP")
        XCTAssertEqual(claims, ["age_over_18"])
        XCTAssertEqual(notShared, ["family_name"])
        XCTAssertEqual(registration, .registered)
        XCTAssertEqual(trustMark, .eudiWallet)
        XCTAssertEqual(retention.policy, .notStored)
        XCTAssertEqual(overAsk.result, .withinRegisteredScope)
        XCTAssertEqual(renderedOperationId, 3)
        XCTAssertEqual(renderedAuthorizationHash, Self.authorizationHash)
        XCTAssertEqual(outcome, .awaitingInput)
    }

    func testConsentTriggersSignThenSuccessfulHttpPost() async throws {
        let signer = StubSigner()
        let http = StubHttpClient()
        let executor = makeExecutor(signer: signer, http: http)

        let outcome = try await executor.send(
            eventJson: WalletEventJSON.userConsented(
                operationId: 3,
                authorizationHash: Self.authorizationHash))

        XCTAssertEqual(signer.signedPayloads.count, 1)
        XCTAssertEqual(signer.signedPayloads.first, Data([1, 2, 3]))
        XCTAssertEqual(http.posted.count, 1)
        XCTAssertEqual(http.posted.first?.0, "https://rp.example/response")
        XCTAssertEqual(http.posted.first?.1, Data([9, 9, 9]))
        XCTAssertEqual(http.posted.first?.2, .openid4vpDirectPost)
        XCTAssertEqual(outcome, .succeeded)
    }

    func testExplicitDeclineRendersNothingUnexpected() async throws {
        var rendered: [ScreenDescription] = []
        let executor = makeExecutor { _, _, screen in rendered.append(screen) }
        let outcome = try await executor.send(
            eventJson: WalletEventJSON.userDeclined(operationId: 3))
        XCTAssertTrue(rendered.isEmpty)
        XCTAssertEqual(outcome, .declined)
    }

    func testPaymentRendersConfirmationThenSignsAuthCode() async throws {
        var rendered: [ScreenDescription] = []
        let signer = StubSigner()
        let http = StubHttpClient()
        let engine = MockEngine { event in
            if event.contains("\"paymentAuthorizationRequestReceived\"") {
                return #"[{"type":"render","operationId":10,"resultType":"paymentDecision","authorizationHash":[0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0],"screen":{"screen":"paymentConfirmation","creditorName":"Acme Store","creditorAccount":"DE89","amountMinor":1299,"currency":"EUR"}}]"#
            }
            if event.contains("\"paymentApproved\"") {
                return #"[{"type":"sign","operationId":11,"resultType":"deviceSignatureProduced","keyRef":"device-key","payload":[7,7,7]}]"#
            }
            if event.contains("\"deviceSignatureProduced\"") {
                return #"[{"type":"http","operationId":12,"resultType":"paymentAuthorizationDelivered","profile":"paymentAuthorization","url":"https://psp.example/authorize","body":[8,8,8]}]"#
            }
            if event.contains("\"paymentAuthorizationDelivered\"") {
                return #"[{"type":"close"}]"#
            }
            return "[]"
        }
        let executor = makeExecutor(engine: engine, signer: signer, http: http) { _, _, screen in
            rendered.append(screen)
        }

        let requestOutcome = try await executor.send(
            eventJson: WalletEventJSON.paymentAuthorizationRequestReceived(Data([1])))
        guard case .paymentConfirmation(let payee, _, let amount, let currency)? = rendered.last else {
            return XCTFail("expected a payment confirmation screen, got \(String(describing: rendered.last))")
        }
        XCTAssertEqual(payee, "Acme Store")
        XCTAssertEqual(amount, 1299)
        XCTAssertEqual(currency, "EUR")
        XCTAssertEqual(requestOutcome, .awaitingInput)

        let approvalOutcome = try await executor.send(
            eventJson: WalletEventJSON.paymentApproved(
                operationId: 10,
                authorizationHash: Self.authorizationHash))
        XCTAssertEqual(signer.signedPayloads.first, Data([7, 7, 7]))
        XCTAssertEqual(http.posted.first?.0, "https://psp.example/authorize")
        XCTAssertEqual(http.posted.first?.2, .paymentAuthorization)
        XCTAssertTrue(engine.receivedEvents.contains {
            $0.contains("\"type\":\"paymentAuthorizationDelivered\"")
                && $0.contains("\"operationId\":12")
        })
        XCTAssertFalse(engine.receivedEvents.contains { $0.contains("presentationDelivered") })
        XCTAssertEqual(approvalOutcome, .succeeded)
    }

    func testInteractiveRenderRequiresOperationIdAndAuthorizationHash() {
        let missingId = #"[{"type":"render","authorizationHash":[0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0],"screen":{"screen":"consent","rpDisplayName":"RP","purpose":"Age","requestedClaims":[],"notSharedClaims":[],"verifierRegistration":"certificateValidated","trustMark":null,"retention":{"policy":"unspecified"},"overAsk":{"result":"registrationScopeUnavailable"}}}]"#
        let shortHash = #"[{"type":"render","operationId":1,"authorizationHash":[0],"screen":{"screen":"consent","rpDisplayName":"RP","purpose":"Age","requestedClaims":[],"notSharedClaims":[],"verifierRegistration":"certificateValidated","trustMark":null,"retention":{"policy":"unspecified"},"overAsk":{"result":"registrationScopeUnavailable"}}}]"#
        for output in [missingId, shortHash] {
            XCTAssertThrowsError(try WalletEffect.decodeCoreOutput(output))
        }
    }

    func testHttpDecoderRejectsUnknownOrMismatchedDeliveryProfiles() {
        let outputs = [
            #"[{"type":"http","operationId":1,"resultType":"presentationDelivered","url":"https://rp.example","body":[]}]"#,
            #"[{"type":"http","operationId":1,"resultType":"presentationDelivered","profile":"futureProfile","url":"https://rp.example","body":[]}]"#,
            #"[{"type":"http","operationId":1,"resultType":"presentationDelivered","profile":"paymentAuthorization","url":"https://rp.example","body":[]}]"#,
            #"[{"type":"http","operationId":1,"resultType":"qesAuthorizationDelivered","profile":"openid4vpDirectPost","url":"https://rp.example","body":[]}]"#,
        ]
        for output in outputs {
            XCTAssertThrowsError(try WalletEffect.decodeCoreOutput(output), output)
        }
    }

    func testTypedQesConfirmationCarriesTheExactAuthorizationFields() throws {
        let output = #"[{"type":"render","operationId":9,"authorizationHash":[0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0],"screen":{"screen":"signConfirmation","documentName":"Contract.pdf","qtspId":"qtsp.de","documentHashHex":"abcdef"}}]"#
        let effects = try WalletEffect.decodeCoreOutput(output)

        guard case .render(let operationId, let hash, .signConfirmation(
            let documentName, let qtspId, let documentHashHex
        )) = effects.first else {
            return XCTFail("expected typed QES confirmation")
        }
        XCTAssertEqual(operationId, 9)
        XCTAssertEqual(hash, [UInt8](repeating: 0, count: 32))
        XCTAssertEqual(documentName, "Contract.pdf")
        XCTAssertEqual(qtspId, "qtsp.de")
        XCTAssertEqual(documentHashHex, "abcdef")
    }

    func testCompleteIssuanceScreenVocabularyDecodesWithoutFallback() throws {
        let document = #"{"documentId":"pid-1","documentName":"National ID","issuerName":"Federal identity authority","format":"dcSdJwt","status":"ready","portraitRequired":true}"#
        let outputs = [
            #"[{"type":"render","operationId":40,"authorizationHash":[0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0],"screen":{"screen":"issuanceOffer","issuerName":"Federal identity authority","documentName":"National ID","format":"dcSdJwt","attributes":["family_name"],"portraitRequired":true}}]"#,
            #"[{"type":"render","screen":{"screen":"pinPreparation","documentName":"National ID"}}]"#,
            #"[{"type":"render","screen":{"screen":"pinHelp"}}]"#,
            #"[{"type":"render","screen":{"screen":"nfcReady","documentName":"National ID"}}]"#,
            #"[{"type":"render","screen":{"screen":"nfcReading","state":"connectionLost"}}]"#,
            "[{\"type\":\"render\",\"screen\":{\"screen\":\"issuanceReady\",\"document\":\(document)}}]",
            #"[{"type":"render","screen":{"screen":"issuanceRecovery","reason":"wrongPin","documentName":"National ID","attemptsRemaining":2,"canResume":true}}]"#,
        ]

        for output in outputs {
            let effects = try WalletEffect.decodeCoreOutput(output)
            guard case .render(_, _, let screen) = effects.first else {
                return XCTFail("expected render")
            }
            if case .other(let name) = screen {
                XCTFail("issuance screen fell back to other: \(name)")
            }
        }
    }

    func testInteractiveDecisionRoutingUsesTheProtocolSpecificEvents() throws {
        let screens: [(ScreenDescription, WalletDecisionKind, String, String)] = [
            (
                .consent(
                    relyingPartyName: "RP",
                    purpose: "Age",
                    requestedClaims: [],
                    notSharedClaims: [],
                    verifierRegistration: .registered,
                    trustMark: .eudiWallet,
                    retention: RetentionDisclosure(policy: .notStored),
                    overAsk: OverAskResult(result: .withinRegisteredScope)),
                .presentation,
                "userConsented",
                "userDeclined"),
            (
                .paymentConfirmation(
                    creditorName: "Shop",
                    creditorAccount: "DE89",
                    amountMinor: 1,
                    currency: "EUR"),
                .payment,
                "paymentApproved",
                "paymentDeclined"),
            (
                .signConfirmation(
                    documentName: "Contract.pdf",
                    qtspId: "qtsp.de",
                    documentHashHex: "ab"),
                .qes,
                "qesAuthorized",
                "qesDeclined"),
        ]

        for (screen, expectedKind, approvalType, declineType) in screens {
            let kind = try XCTUnwrap(WalletDecisionKind(screen: screen))
            XCTAssertEqual(kind, expectedKind)
            XCTAssertEqual(
                Self.eventType(kind.approvalEvent(
                    operationId: 77,
                    authorizationHash: Self.authorizationHash)),
                approvalType)
            XCTAssertEqual(Self.eventType(kind.declineEvent(operationId: 77)), declineType)
        }
        XCTAssertNil(WalletDecisionKind(screen: .loading))
        XCTAssertNil(WalletDecisionKind(screen: .error(code: "x", message: "y")))
    }

#if canImport(SwiftUI)
    func testPaymentAmountFormattingDoesNotLoseUInt64Precision() {
        XCTAssertEqual(
            PaymentConfirmationView.exactAmountText(
                amountMinor: UInt64.max,
                currency: "EUR"),
            "184467440737095516.15 EUR")
    }
#endif

    func testInteractiveRendererFailureIsCorrelatedAndResetsCascade() async throws {
        let engine = MockEngine { event in
            if event.contains("\"operationFailed\"") {
                return #"[{"type":"render","screen":{"screen":"error","code":"rendering_failed","message":"Rendering failed"}},{"type":"close"}]"#
            }
            return #"[{"type":"render","operationId":31,"authorizationHash":[0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0],"screen":{"screen":"consent","rpDisplayName":"RP","purpose":"Age","requestedClaims":[],"notSharedClaims":[],"verifierRegistration":"certificateValidated","trustMark":null,"retention":{"policy":"unspecified"},"overAsk":{"result":"registrationScopeUnavailable"}}}]"#
        }
        let executor = makeExecutor(engine: engine) { _, _, screen in
            if case .consent = screen {
                throw ExpectedFailure.failure
            }
        }

        let outcome = try await executor.send(eventJson: "{}")

        XCTAssertEqual(
            outcome,
            .aborted(.coreError(code: "rendering_failed", message: "Rendering failed")))
        XCTAssertTrue(engine.receivedEvents.contains {
            $0.contains("\"type\":\"operationFailed\"")
                && $0.contains("\"operationId\":31")
                && $0.contains("\"failure\":\"rendering\"")
        })
    }

    func testPublishedTransferOfferWaitsForPeerInput() async throws {
        let publisher = RecordingTransferOfferPublisher()
        let engine = MockEngine { event in
            if event.contains("\"operationSucceeded\"") { return "[]" }
            return #"[{"type":"publishTransferOffer","operationId":41,"offeredKey":[1,2,3]}]"#
        }
        let executor = makeExecutor(
            engine: engine,
            transferOffers: publisher)

        let outcome = try await executor.send(eventJson: "{}")

        XCTAssertEqual(publisher.offeredKeys, [Data([1, 2, 3])])
        XCTAssertTrue(engine.receivedEvents.contains {
            $0.contains("\"type\":\"operationSucceeded\"")
                && $0.contains("\"operationId\":41")
        })
        XCTAssertEqual(outcome, .awaitingInput)
    }

    func testStaleDecisionCoreRejectionCannotBecomeSuccess() async {
        let engine = MockEngine { _ in #"{"error":"stale or unknown operationId 7"}"# }
        let executor = makeExecutor(engine: engine)
        do {
            _ = try await executor.send(eventJson: WalletEventJSON.userConsented(
                operationId: 7,
                authorizationHash: Self.authorizationHash))
            XCTFail("expected stale decision rejection")
        } catch let error as EffectExecutorError {
            XCTAssertEqual(error, .ffi(.coreRejected("stale or unknown operationId 7")))
        } catch {
            XCTFail("unexpected error: \(error)")
        }
    }

    func testEmptyQueueAndCloseOnlyAreNeverSuccess() async throws {
        let empty = makeExecutor(engine: MockEngine { _ in "[]" })
        let emptyOutcome = try await empty.send(
            eventJson: WalletEventJSON.userConsented(
                operationId: 1,
                authorizationHash: Self.authorizationHash))
        XCTAssertEqual(emptyOutcome, .aborted(.missingTerminalOutcome))

        let closeOnly = makeExecutor(engine: MockEngine { _ in #"[{"type":"close"}]"# })
        let closeOutcome = try await closeOnly.send(
            eventJson: WalletEventJSON.userConsented(
                operationId: 1,
                authorizationHash: Self.authorizationHash))
        XCTAssertEqual(closeOutcome, .aborted(.closedWithoutSuccess))
    }

    func testErrorScreenAndEffectsAfterCloseAbort() async throws {
        let coreError = makeExecutor(engine: MockEngine { _ in
            #"[{"type":"render","screen":{"screen":"error","code":"STATUS_UNAVAILABLE","message":"Status unavailable"}},{"type":"close"}]"#
        })
        let errorOutcome = try await coreError.send(
            eventJson: WalletEventJSON.userConsented(
                operationId: 1,
                authorizationHash: Self.authorizationHash))
        XCTAssertEqual(
            errorOutcome,
            .aborted(.coreError(code: "STATUS_UNAVAILABLE", message: "Status unavailable")))

        let afterClose = makeExecutor(engine: MockEngine { _ in
            #"[{"type":"close"},{"type":"render","screen":{"screen":"loading"}}]"#
        })
        let afterCloseOutcome = try await afterClose.send(
            eventJson: WalletEventJSON.userConsented(
                operationId: 1,
                authorizationHash: Self.authorizationHash))
        XCTAssertEqual(afterCloseOutcome, .aborted(.effectAfterClose))
    }

    func testMalformedCoreOutputIsRejectedByLifecycleBeforeCommit() async {
        let engine = MockEngine { _ in "not-json" }
        let executor = makeExecutor(engine: engine)

        do {
            try await executor.send(
                eventJson: WalletEventJSON.userConsented(
                    operationId: 1,
                    authorizationHash: Self.authorizationHash))
            XCTFail("expected malformed core output to fail")
        } catch {
            XCTAssertEqual(error as? DurableLifecycleError, .malformedCoreOutput)
        }
        XCTAssertTrue(engine.exportedGenerations.isEmpty)
        assertNoSemanticSuccessOrDecline(engine.receivedEvents)
    }

    func testStorageFailureIsReportedToCoreAndResetsCascade() async throws {
        let engine = MockEngine()
        let executor = makeExecutor(engine: engine, storage: FailingStorage())

        let outcome = try await executor.send(
            eventJson: WalletEventJSON.authorizationRequestReceived(Data([1])))
        XCTAssertEqual(
            outcome,
            .aborted(.coreError(code: "operation_failed", message: "Operation failed")))
        XCTAssertTrue(engine.receivedEvents.contains { event in
            event.contains("\"type\":\"operationFailed\"")
                && event.contains("\"failure\":\"storage\"")
        })
        assertNoSemanticSuccessOrDecline(engine.receivedEvents)
    }

    func testSigningFailureDoesNotBecomeUserDecline() async throws {
        let engine = MockEngine()
        let executor = makeExecutor(engine: engine, signer: FailingSigner())

        let outcome = try await executor.send(
            eventJson: WalletEventJSON.userConsented(
                operationId: 3,
                authorizationHash: Self.authorizationHash))
        XCTAssertEqual(
            outcome,
            .aborted(.coreError(code: "operation_failed", message: "Operation failed")))
        XCTAssertTrue(engine.receivedEvents.contains { $0.contains("\"failure\":\"signing\"") })
        assertNoSemanticSuccessOrDecline(engine.receivedEvents)
    }

    func testSigningCancellationUsesTheTypedCorrelatedCancellationEvent() async throws {
        let engine = MockEngine()
        let executor = makeExecutor(engine: engine, signer: CancellingSigner())

        let outcome = try await executor.send(
            eventJson: WalletEventJSON.userConsented(
                operationId: 3,
                authorizationHash: Self.authorizationHash))

        XCTAssertEqual(
            outcome,
            .aborted(.coreError(code: "operation_failed", message: "Operation failed")))
        XCTAssertTrue(engine.receivedEvents.contains {
            $0.contains("\"type\":\"operationCancelled\"")
                && $0.contains("\"operationId\":4")
        })
        assertNoSemanticSuccessOrDecline(engine.receivedEvents)
    }

    func testNon2xxResponseDoesNotBecomePresentationDelivered() async throws {
        let engine = MockEngine()
        let http = FixedHttpClient(.response(HttpResponse(
            statusCode: 503,
            body: Data("unavailable".utf8))))
        let executor = makeExecutor(engine: engine, http: http)

        let outcome = try await executor.send(
            eventJson: WalletEventJSON.userConsented(
                operationId: 3,
                authorizationHash: Self.authorizationHash))
        XCTAssertEqual(
            outcome,
            .aborted(.coreError(code: "operation_failed", message: "Operation failed")))
        XCTAssertTrue(engine.receivedEvents.contains { $0.contains("\"failure\":\"httpStatus\"") })
        assertNoSemanticSuccessOrDecline(engine.receivedEvents)
    }

    func testOpenId4VpResponseRequiresExactStatusMimeObjectUtf8AndBounds() async throws {
        let invalidResponses: [(String, HttpResponse)] = [
            ("201", HttpResponse(
                statusCode: 201,
                body: Data("{}".utf8),
                contentType: "application/json")),
            ("204", HttpResponse(
                statusCode: 204,
                body: Data("{}".utf8),
                contentType: "application/json")),
            ("missing MIME", HttpResponse(statusCode: 200, body: Data("{}".utf8))),
            ("wrong MIME", HttpResponse(
                statusCode: 200,
                body: Data("{}".utf8),
                contentType: "text/html")),
            ("ambiguous MIME", HttpResponse(
                statusCode: 200,
                body: Data("{}".utf8),
                contentType: "application/json, text/html")),
            ("array", HttpResponse(
                statusCode: 200,
                body: Data("[]".utf8),
                contentType: "application/json")),
            ("scalar", HttpResponse(
                statusCode: 200,
                body: Data("true".utf8),
                contentType: "application/json")),
            ("invalid JSON", HttpResponse(
                statusCode: 200,
                body: Data("{".utf8),
                contentType: "application/json")),
            ("non-UTF8", HttpResponse(
                statusCode: 200,
                body: Data([0xff]),
                contentType: "application/json")),
            ("oversize", HttpResponse(
                statusCode: 200,
                body: Data(
                    repeating: UInt8(ascii: " "),
                    count: OpenID4VPDirectPostResponse.maximumResponseBytes + 1),
                contentType: "application/json")),
        ]

        for (name, response) in invalidResponses {
            let engine = MockEngine()
            let executor = makeExecutor(
                engine: engine,
                http: FixedHttpClient(.response(response)))
            let outcome = try await executor.send(
                eventJson: WalletEventJSON.userConsented(
                    operationId: 3,
                    authorizationHash: Self.authorizationHash))

            XCTAssertEqual(
                outcome,
                .aborted(.coreError(code: "operation_failed", message: "Operation failed")),
                name)
            assertNoSemanticSuccessOrDecline(engine.receivedEvents)
        }
    }

    func testOpenId4VpRedirectUriRejectsAmbiguousAndMalformedValues() async throws {
        let oversized = "wallet:" + String(
            repeating: "a",
            count: OpenID4VPDirectPostResponse.maximumRedirectUriBytes)
        let invalidBodies = [
            #"{"redirect_uri":7}"#,
            #"{"redirect_uri":"relative/path"}"#,
            #"{"redirect_uri":"https://client.example/%zz"}"#,
            try XCTUnwrap(
                String(data: try JSONEncoder().encode(["redirect_uri": oversized]), encoding: .utf8)),
            #"{"redirect_uri":"https://one.example","redirect_uri":"https://two.example"}"#,
            #"{"redirect_uri":"https://one.example","\u0072edirect_uri":"https://two.example"}"#,
        ]

        for body in invalidBodies {
            let engine = MockEngine()
            let response = HttpResponse(
                statusCode: 200,
                body: Data(body.utf8),
                contentType: "application/json")
            let executor = makeExecutor(
                engine: engine,
                http: FixedHttpClient(.response(response)),
                presentationRedirectHandler: RecordingRedirectHandler())

            _ = try await executor.send(
                eventJson: WalletEventJSON.userConsented(
                    operationId: 3,
                    authorizationHash: Self.authorizationHash))
            assertNoSemanticSuccessOrDecline(engine.receivedEvents)
        }
    }

    func testOpenId4VpUnknownMembersAreIgnoredAndOpaqueRedirectUsesOnlyInjectedHandler() async throws {
        let engine = MockEngine()
        var acknowledgedBeforeHandler = false
        let redirectHandler = RecordingRedirectHandler {
            acknowledgedBeforeHandler = engine.receivedEvents.contains {
                $0.contains("presentationDelivered")
            }
        }
        let response = HttpResponse(
            statusCode: 200,
            body: Data(
                #"{"future":{"nested":[1,2,3]},"redirect_uri":"wallet:continue?response_code=abc"}"#.utf8),
            contentType: "Application/JSON; charset=UTF-8")
        let executor = makeExecutor(
            engine: engine,
            http: FixedHttpClient(.response(response)),
            presentationRedirectHandler: redirectHandler)

        let outcome = try await executor.send(
            eventJson: WalletEventJSON.userConsented(
                operationId: 3,
                authorizationHash: Self.authorizationHash))

        XCTAssertEqual(outcome, .succeeded)
        XCTAssertFalse(acknowledgedBeforeHandler)
        XCTAssertEqual(redirectHandler.redirects.map(\.absoluteString), [
            "wallet:continue?response_code=abc",
        ])
    }

    func testOpenId4VpRedirectRequiresAHandlerAndRefusalNeverAcknowledges() async throws {
        let response = HttpResponse(
            statusCode: 200,
            body: Data(#"{"redirect_uri":"https://client.example/cb#code=abc"}"#.utf8),
            contentType: "application/json")
        for handler in [nil, RecordingRedirectHandler(shouldFail: true)] as [
            OpenID4VPRedirectHandler?
        ] {
            let engine = MockEngine()
            let executor = makeExecutor(
                engine: engine,
                http: FixedHttpClient(.response(response)),
                presentationRedirectHandler: handler)

            _ = try await executor.send(
                eventJson: WalletEventJSON.userConsented(
                    operationId: 3,
                    authorizationHash: Self.authorizationHash))
            assertNoSemanticSuccessOrDecline(engine.receivedEvents)
        }
    }

    func testOpenId4VpRequestBodyMustBeUtf8BeforeTransport() async throws {
        let engine = MockEngine { event in
            if event.contains("operationFailed") {
                return #"[{"type":"render","screen":{"screen":"error","code":"operation_failed","message":"Operation failed"}},{"type":"close"}]"#
            }
            return #"[{"type":"http","operationId":31,"resultType":"presentationDelivered","profile":"openid4vpDirectPost","url":"https://rp.example/response","body":[255]}]"#
        }
        let http = FixedHttpClient(.response(HttpResponse(
            statusCode: 200,
            body: Data("{}".utf8),
            contentType: "application/json")))

        _ = try await makeExecutor(engine: engine, http: http).send(eventJson: "{}")

        XCTAssertTrue(http.postedProfiles.isEmpty)
        assertNoSemanticSuccessOrDecline(engine.receivedEvents)
    }

    func testTransportFailureDoesNotBecomePresentationDelivered() async throws {
        let engine = MockEngine()
        let executor = makeExecutor(
            engine: engine,
            http: FixedHttpClient(.failure(.transport("offline"))))

        let outcome = try await executor.send(
            eventJson: WalletEventJSON.userConsented(
                operationId: 3,
                authorizationHash: Self.authorizationHash))
        XCTAssertEqual(
            outcome,
            .aborted(.coreError(code: "operation_failed", message: "Operation failed")))
        XCTAssertTrue(engine.receivedEvents.contains { $0.contains("\"failure\":\"transport\"") })
        assertNoSemanticSuccessOrDecline(engine.receivedEvents)
    }

    func testMissingIssuerStopsIssuanceInsteadOfSilentlyDraining() async throws {
        let engine = MockEngine { event in
            if event.contains("operationFailed") {
                return #"[{"type":"render","screen":{"screen":"error","code":"operation_failed","message":"Operation failed"}},{"type":"close"}]"#
            }
            return #"[{"type":"requestToken","operationId":20,"resultType":"tokenReceived"}]"#
        }
        let executor = makeExecutor(engine: engine)

        let outcome = try await executor.send(eventJson: "{}")
        XCTAssertEqual(
            outcome,
            .aborted(.coreError(code: "operation_failed", message: "Operation failed")))
        XCTAssertTrue(engine.receivedEvents.contains {
            $0.contains("\"failure\":\"missingDependency\"")
        })
        assertNoSemanticSuccessOrDecline(engine.receivedEvents)
    }

    func testIssuerTransportFailureStopsIssuance() async throws {
        let engine = MockEngine { event in
            if event.contains("operationFailed") {
                return #"[{"type":"render","screen":{"screen":"error","code":"operation_failed","message":"Operation failed"}},{"type":"close"}]"#
            }
            return #"[{"type":"requestToken","operationId":21,"resultType":"tokenReceived"}]"#
        }
        let executor = makeExecutor(engine: engine, issuer: FailingIssuer())

        let outcome = try await executor.send(eventJson: "{}")
        XCTAssertEqual(
            outcome,
            .aborted(.coreError(code: "operation_failed", message: "Operation failed")))
        XCTAssertTrue(engine.receivedEvents.contains { $0.contains("\"failure\":\"issuer\"") })
        assertNoSemanticSuccessOrDecline(engine.receivedEvents)
    }

    func testCredentialCallbackAcknowledgesOnlyCoreAcceptedCompletion() async throws {
        let rejectedEngine = MockEngine { event in
            if event.contains("\"credentialReceived\"") {
                return #"[{"type":"render","screen":{"screen":"error","code":"credential_issuance_rejected","message":"Credential rejected"}},{"type":"close"}]"#
            }
            return #"[{"type":"requestCredential","operationId":25,"proofJwt":[1,2,3]}]"#
        }
        let rejectedExecutor = makeExecutor(
            engine: rejectedEngine,
            issuer: FixedCredentialIssuer())

        let rejectedOutcome = try await rejectedExecutor.send(eventJson: "{}")

        XCTAssertEqual(
            rejectedOutcome,
            .aborted(.coreError(
                code: "credential_issuance_rejected",
                message: "Credential rejected")))

        let acceptedEngine = MockEngine { event in
            if event.contains("\"credentialReceived\"") {
                return #"[{"type":"close"}]"#
            }
            return #"[{"type":"requestCredential","operationId":26,"proofJwt":[4,5,6]}]"#
        }
        let acceptedExecutor = makeExecutor(
            engine: acceptedEngine,
            issuer: FixedCredentialIssuer())

        let acceptedOutcome = try await acceptedExecutor.send(eventJson: "{}")

        XCTAssertEqual(acceptedOutcome, .succeeded)
        XCTAssertTrue(rejectedEngine.receivedEvents.contains {
            $0.contains("\"type\":\"credentialReceived\"")
        })
        XCTAssertTrue(acceptedEngine.receivedEvents.contains {
            $0.contains("\"type\":\"credentialReceived\"")
        })
    }

    func testUnimplementedProtocolEffectFailsExplicitly() async throws {
        let engine = MockEngine { event in
            if event.contains("operationFailed") {
                return #"[{"type":"render","screen":{"screen":"error","code":"operation_failed","message":"Operation failed"}},{"type":"close"}]"#
            }
            return #"[{"type":"pushPar","operationId":22,"resultType":"parPushed"}]"#
        }
        let executor = makeExecutor(engine: engine)

        let outcome = try await executor.send(eventJson: "{}")
        XCTAssertEqual(
            outcome,
            .aborted(.coreError(code: "operation_failed", message: "Operation failed")))
        XCTAssertTrue(engine.receivedEvents.contains {
            $0.contains("\"failure\":\"unsupported\"")
        })
        assertNoSemanticSuccessOrDecline(engine.receivedEvents)
    }

    func testStatusListFetchReturnsBodyStatusAndAuthenticatedSignerChain() async throws {
        let engine = MockEngine { event in
            if event.contains("\"statusListReceived\"") { return #"[{"type":"close"}]"# }
            return #"[{"type":"fetchStatusList","operationId":23,"resultType":"statusListReceived","uri":"https://status.example/list"}]"#
        }
        let resolver = FixedStatusListResolver(.resolution(StatusListResolution(
            response: HttpResponse(statusCode: 200, body: Data([4, 5, 6])),
            providerCertChain: [Data([7, 8, 9])]
        )))
        let executor = makeExecutor(engine: engine, statusLists: resolver)

        try await executor.send(eventJson: "{}")

        let event = try XCTUnwrap(engine.receivedEvents.last)
        let data = try XCTUnwrap(event.data(using: .utf8))
        let json = try XCTUnwrap(JSONSerialization.jsonObject(with: data) as? [String: Any])
        XCTAssertEqual(json["type"] as? String, "statusListReceived")
        XCTAssertEqual(json["operationId"] as? Int, 23)
        XCTAssertEqual(json["uri"] as? String, "https://status.example/list")
        XCTAssertEqual(json["httpStatus"] as? Int, 200)
        XCTAssertEqual(json["token"] as? [Int], [4, 5, 6])
        XCTAssertEqual(json["providerCertChain"] as? [[Int]], [[7, 8, 9]])
    }

    func testMissingStatusTransportFeedsFailureToCoreAndNeverClaimsSuccess() async throws {
        let engine = MockEngine { event in
            if event.contains("\"operationFailed\"") {
                return #"[{"type":"render","screen":{"screen":"error","code":"status_failed","message":"Status failed"}},{"type":"close"}]"#
            }
            return #"[{"type":"fetchStatusList","operationId":24,"resultType":"statusListReceived","uri":"https://status.example/list"}]"#
        }
        let executor = makeExecutor(engine: engine)

        try await executor.send(eventJson: "{}")

        let resultEvent = try XCTUnwrap(engine.receivedEvents.last)
        XCTAssertTrue(resultEvent.contains("\"failure\":\"status\""))
        assertNoSemanticSuccessOrDecline(engine.receivedEvents)
    }

    private static func eventType(_ event: String) -> String? {
        guard let data = event.data(using: .utf8),
              let object = (try? JSONSerialization.jsonObject(with: data)) as? [String: Any]
        else { return nil }
        return object["type"] as? String
    }
}
