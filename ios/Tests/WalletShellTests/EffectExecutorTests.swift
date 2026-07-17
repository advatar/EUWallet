import XCTest
@testable import WalletShell

final class EffectExecutorTests: XCTestCase {
    func testConsentFlowRendersThenReachesCredentialList() async {
        var rendered: [ScreenDescription] = []
        let executor = EffectExecutor(
            core: WalletCore(),
            signer: StubSigner(),
            http: StubHttpClient(),
            storage: InMemoryStorage(),
            render: { rendered.append($0) }
        )

        // 1) Incoming request → a consent screen is rendered.
        await executor.send(.authorizationRequestReceived(Data([1, 2, 3])))
        guard case .consent(let c)? = rendered.last else {
            return XCTFail("expected a consent screen, got \(String(describing: rendered.last))")
        }
        XCTAssertEqual(c.requestedClaims, ["age_over_18"])   // data minimisation

        // 2) User consents → sign → http → the cascade ends on the credential list.
        await executor.send(.userConsented)
        XCTAssertEqual(rendered.last, .credentialList)
    }

    func testDeclineRendersError() async {
        var rendered: [ScreenDescription] = []
        let executor = EffectExecutor(
            core: WalletCore(), signer: StubSigner(), http: StubHttpClient(),
            storage: InMemoryStorage(), render: { rendered.append($0) }
        )
        await executor.send(.authorizationRequestReceived(Data()))
        await executor.send(.userDeclined)
        if case .error(let code, _)? = rendered.last {
            XCTAssertEqual(code, "user_declined")
        } else {
            XCTFail("expected an error screen")
        }
    }
}
