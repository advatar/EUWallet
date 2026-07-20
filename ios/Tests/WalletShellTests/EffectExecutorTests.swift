import XCTest
@testable import WalletShell

/// A scripted engine standing in for the Rust WalletEngine over the JSON contract. It returns the
/// same effect sequence the real core does, so the shell's dispatch and fail-closed boundaries can
/// be tested on the host without linking the xcframework.
final class MockEngine: WalletEngineDriving {
    private let response: (String) -> String
    private(set) var receivedEvents: [String] = []

    init(response: @escaping (String) -> String = MockEngine.happyPathResponse) {
        self.response = response
    }

    func handleEventJson(eventJson: String) -> String {
        receivedEvents.append(eventJson)
        return response(eventJson)
    }

    private static func happyPathResponse(_ eventJson: String) -> String {
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

private enum ExpectedFailure: Error { case failure }

private final class FailingSigner: Signer {
    func sign(keyRef: String, payload: Data) throws -> Data { throw ExpectedFailure.failure }
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

private final class FixedHttpClient: HttpClient {
    enum Outcome {
        case response(HttpResponse)
        case failure(HttpClientError)
    }

    private let outcome: Outcome
    init(_ outcome: Outcome) { self.outcome = outcome }

    func post(url: String, body: Data) async throws -> HttpResponse {
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

final class EffectExecutorTests: XCTestCase {
    private func makeExecutor(
        engine: MockEngine = MockEngine(),
        signer: Signer = StubSigner(),
        http: HttpClient = StubHttpClient(),
        storage: SecureStorage = InMemoryStorage(),
        statusLists: StatusListResolver? = nil,
        issuer: IssuerResponder? = nil,
        render: @escaping (ScreenDescription) -> Void = { _ in }
    ) -> EffectExecutor {
        EffectExecutor(
            engine: engine,
            signer: signer,
            http: http,
            storage: storage,
            trust: StubTrustResolver(certChain: [Data([1, 2, 3])]),
            statusLists: statusLists,
            issuer: issuer,
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

    func testRequestRendersConsentScreen() async throws {
        var rendered: [ScreenDescription] = []
        let executor = makeExecutor { rendered.append($0) }

        try await executor.send(
            eventJson: WalletEventJSON.authorizationRequestReceived(Data([1, 2, 3])))

        guard case .consent(let rp, _, let claims)? = rendered.last else {
            return XCTFail("expected a consent screen, got \(String(describing: rendered.last))")
        }
        XCTAssertEqual(rp, "Example RP")
        XCTAssertEqual(claims, ["age_over_18"])
    }

    func testConsentTriggersSignThenSuccessfulHttpPost() async throws {
        let signer = StubSigner()
        let http = StubHttpClient()
        let executor = makeExecutor(signer: signer, http: http)

        try await executor.send(eventJson: WalletEventJSON.userConsented())

        XCTAssertEqual(signer.signedPayloads.count, 1)
        XCTAssertEqual(signer.signedPayloads.first, Data([1, 2, 3]))
        XCTAssertEqual(http.posted.count, 1)
        XCTAssertEqual(http.posted.first?.0, "https://rp.example/response")
        XCTAssertEqual(http.posted.first?.1, Data([9, 9, 9]))
    }

    func testExplicitDeclineRendersNothingUnexpected() async throws {
        var rendered: [ScreenDescription] = []
        let executor = makeExecutor { rendered.append($0) }
        try await executor.send(eventJson: WalletEventJSON.userDeclined())
        XCTAssertTrue(rendered.isEmpty)
    }

    func testPaymentRendersConfirmationThenSignsAuthCode() async throws {
        var rendered: [ScreenDescription] = []
        let signer = StubSigner()
        let http = StubHttpClient()
        let executor = makeExecutor(signer: signer, http: http) { rendered.append($0) }

        try await executor.send(
            eventJson: WalletEventJSON.paymentAuthorizationRequestReceived(Data([1])))
        guard case .paymentConfirmation(let payee, _, let amount, let currency)? = rendered.last else {
            return XCTFail("expected a payment confirmation screen, got \(String(describing: rendered.last))")
        }
        XCTAssertEqual(payee, "Acme Store")
        XCTAssertEqual(amount, 1299)
        XCTAssertEqual(currency, "EUR")

        try await executor.send(eventJson: WalletEventJSON.paymentApproved())
        XCTAssertEqual(signer.signedPayloads.first, Data([7, 7, 7]))
        XCTAssertEqual(http.posted.first?.0, "https://psp.example/authorize")
    }

    func testMalformedCoreOutputThrowsTypedError() async {
        let engine = MockEngine { _ in "not-json" }
        let executor = makeExecutor(engine: engine)

        do {
            try await executor.send(eventJson: WalletEventJSON.userConsented())
            XCTFail("expected malformed core output to fail")
        } catch let error as EffectExecutorError {
            guard case .ffi(.malformedCoreOutput) = error else {
                return XCTFail("unexpected error: \(error)")
            }
        } catch {
            XCTFail("untyped error: \(error)")
        }
        assertNoSemanticSuccessOrDecline(engine.receivedEvents)
    }

    func testStorageFailureThrowsAndStopsCascade() async {
        let engine = MockEngine()
        let executor = makeExecutor(engine: engine, storage: FailingStorage())

        do {
            try await executor.send(
                eventJson: WalletEventJSON.authorizationRequestReceived(Data([1])))
            XCTFail("expected storage failure")
        } catch let error as EffectExecutorError {
            guard case .storageFailed = error else { return XCTFail("unexpected error: \(error)") }
        } catch {
            XCTFail("untyped error: \(error)")
        }
        assertNoSemanticSuccessOrDecline(engine.receivedEvents)
    }

    func testSigningFailureDoesNotBecomeUserDecline() async {
        let engine = MockEngine()
        let executor = makeExecutor(engine: engine, signer: FailingSigner())

        do {
            try await executor.send(eventJson: WalletEventJSON.userConsented())
            XCTFail("expected signing failure")
        } catch let error as EffectExecutorError {
            guard case .signingFailed = error else { return XCTFail("unexpected error: \(error)") }
        } catch {
            XCTFail("untyped error: \(error)")
        }
        assertNoSemanticSuccessOrDecline(engine.receivedEvents)
    }

    func testNon2xxResponseDoesNotBecomePresentationDelivered() async {
        let engine = MockEngine()
        let http = FixedHttpClient(.response(HttpResponse(
            statusCode: 503,
            body: Data("unavailable".utf8))))
        let executor = makeExecutor(engine: engine, http: http)

        do {
            try await executor.send(eventJson: WalletEventJSON.userConsented())
            XCTFail("expected non-2xx failure")
        } catch let error as EffectExecutorError {
            guard case .httpStatusFailed(let status, let body) = error else {
                return XCTFail("unexpected error: \(error)")
            }
            XCTAssertEqual(status, 503)
            XCTAssertEqual(body, Data("unavailable".utf8))
        } catch {
            XCTFail("untyped error: \(error)")
        }
        assertNoSemanticSuccessOrDecline(engine.receivedEvents)
    }

    func testTransportFailureDoesNotBecomePresentationDelivered() async {
        let engine = MockEngine()
        let executor = makeExecutor(
            engine: engine,
            http: FixedHttpClient(.failure(.transport("offline"))))

        do {
            try await executor.send(eventJson: WalletEventJSON.userConsented())
            XCTFail("expected transport failure")
        } catch let error as EffectExecutorError {
            XCTAssertEqual(error, .transportFailed(.transport("offline")))
        } catch {
            XCTFail("untyped error: \(error)")
        }
        assertNoSemanticSuccessOrDecline(engine.receivedEvents)
    }

    func testMissingIssuerStopsIssuanceInsteadOfSilentlyDraining() async {
        let engine = MockEngine { _ in #"[{"type":"requestToken"}]"# }
        let executor = makeExecutor(engine: engine)

        do {
            try await executor.send(eventJson: "{}")
            XCTFail("expected the missing issuer to fail")
        } catch let error as EffectExecutorError {
            XCTAssertEqual(error, .missingDependency("issuer"))
        } catch {
            XCTFail("untyped error: \(error)")
        }
        assertNoSemanticSuccessOrDecline(engine.receivedEvents)
    }

    func testIssuerTransportFailureStopsIssuance() async {
        let engine = MockEngine { _ in #"[{"type":"requestToken"}]"# }
        let executor = makeExecutor(engine: engine, issuer: FailingIssuer())

        do {
            try await executor.send(eventJson: "{}")
            XCTFail("expected issuer failure")
        } catch let error as EffectExecutorError {
            guard case .issuerFailed = error else { return XCTFail("unexpected error: \(error)") }
        } catch {
            XCTFail("untyped error: \(error)")
        }
        assertNoSemanticSuccessOrDecline(engine.receivedEvents)
    }

    func testUnimplementedProtocolEffectFailsExplicitly() async {
        let engine = MockEngine { _ in #"[{"type":"pushPar"}]"# }
        let executor = makeExecutor(engine: engine)

        do {
            try await executor.send(eventJson: "{}")
            XCTFail("expected unsupported effect failure")
        } catch let error as EffectExecutorError {
            XCTAssertEqual(error, .unsupportedEffect("pushPar"))
        } catch {
            XCTFail("untyped error: \(error)")
        }
        assertNoSemanticSuccessOrDecline(engine.receivedEvents)
    }

    func testStatusListFetchReturnsBodyStatusAndAuthenticatedSignerChain() async throws {
        let engine = MockEngine { event in
            if event.contains("\"statusListReceived\"") { return #"[{"type":"close"}]"# }
            return #"[{"type":"fetchStatusList","uri":"https://status.example/list"}]"#
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
        XCTAssertEqual(json["uri"] as? String, "https://status.example/list")
        XCTAssertEqual(json["httpStatus"] as? Int, 200)
        XCTAssertEqual(json["token"] as? [Int], [4, 5, 6])
        XCTAssertEqual(json["providerCertChain"] as? [[Int]], [[7, 8, 9]])
    }

    func testMissingStatusTransportFeedsFailureToCoreAndNeverClaimsSuccess() async throws {
        let engine = MockEngine { event in
            if event.contains("\"statusListReceived\"") { return #"[{"type":"close"}]"# }
            return #"[{"type":"fetchStatusList","uri":"https://status.example/list"}]"#
        }
        let executor = makeExecutor(engine: engine)

        try await executor.send(eventJson: "{}")

        let resultEvent = try XCTUnwrap(engine.receivedEvents.last)
        XCTAssertTrue(resultEvent.contains("\"httpStatus\":0"))
        assertNoSemanticSuccessOrDecline(engine.receivedEvents)
    }
}
