import Foundation

// WalletShell sources, the generated UniFFI bindings, and these App sources are compiled into one
// app module (see ios/project.yml), so no cross-module import is needed.

/// Orchestrates the real Rust core for the demo app. Each flow gets a FRESH engine (the core is a
/// one-shot state machine that ends in `Done`), wired to the shell's `EffectExecutor`. The device
/// signer and RP trust come from `DemoWallet` (real aws-lc-rs keys) so the on-simulator run is a
/// genuine end-to-end flow — not a scripted mock — even without the Secure Enclave or a live RP.
@MainActor
final class WalletModel: ObservableObject {
    enum Phase: Equatable {
        case home
        case running
        case screen(ScreenDescription)
        case done(String)
        case failed(String)
    }

    @Published private(set) var phase: Phase = .home
    @Published private(set) var log: [String] = []

    private var executor: EffectExecutor?

    /// Build a fresh engine + executor for one flow. Returns the demo scenario to drive it.
    private func freshFlow() -> DemoScenario {
        let engine = WalletEngine(walletClientId: "wallet.example", deviceKeyRef: "device-key")
        let demo = DemoWallet()
        let scenario = demo.scenario()

        // Load the held credential, device key, and trusted list directly (these are FFI calls,
        // not events). RP registration, data minimisation, and key binding are decided in-core.
        engine.loadCredential(
            issuerJwt: scenario.issuerJwt,
            disclosuresByClaimJson: scenario.disclosuresByClaimJson,
            statusIndex: nil)
        engine.loadDeviceKey(devicePublicKey: scenario.devicePublicKey)
        // Set the clock BEFORE loading the trusted list: the core verifies the list and the RP/CA
        // certificate validity windows against `now_epoch` (0/1970 when unset → certs not yet valid).
        _ = engine.handleEventJson(eventJson: WalletEventJSON.setClock(epoch: scenario.epoch))
        _ = engine.loadTrustList(
            signedList: scenario.trustList,
            operatorPublicKey: scenario.operatorPublicKey)

        self.executor = EffectExecutor(
            engine: engine,
            signer: DemoSigner(demo: demo),
            http: StubHttpClient(),
            storage: InMemoryStorage(),
            trust: DemoTrustResolver(
                certChain: scenario.rpCertChain,
                redirectUris: scenario.registeredRedirectUris),
            render: { [weak self] screen in
                Task { @MainActor in self?.phase = .screen(screen) }
            })
        return scenario
    }

    private func note(_ line: String) { log.append(line) }

    // MARK: - Flows

    /// OpenID4VP remote presentation: request → in-core trust + data minimisation → consent.
    func startPresentation() {
        phase = .running
        log = ["Presentation: feeding RP-signed authorization request…"]
        let scenario = freshFlow()
        Task {
            await executor?.send(
                eventJson: WalletEventJSON.authorizationRequestReceived(scenario.presentationRequest))
            note("Core resolved RP trust in-core and computed the minimised consent screen.")
        }
    }

    /// PSD2/TS12 payment SCA: request → what-you-see-is-what-you-authorise confirmation.
    func startPayment() {
        phase = .running
        log = ["Payment: feeding PSD2/TS12 authorization request…"]
        let scenario = freshFlow()
        Task {
            await executor?.send(
                eventJson: WalletEventJSON.paymentAuthorizationRequestReceived(scenario.paymentRequest))
            note("Core produced the payment confirmation screen (amount + payee bound in-core).")
        }
    }

    /// User approved the on-screen consent/payment: device signs (demo key), core assembles and
    /// the shell "delivers" the vp_token / SCA auth code. Drains to `Close`.
    func approve() {
        let wasPayment: Bool
        if case .screen(.paymentConfirmation) = phase { wasPayment = true } else { wasPayment = false }
        phase = .running
        Task {
            if wasPayment {
                await executor?.send(eventJson: WalletEventJSON.paymentApproved())
                note("Device signed the dynamic-linking binding; auth code posted to the PSP.")
                phase = .done("Payment authorised — SCA auth code delivered.")
            } else {
                await executor?.send(eventJson: WalletEventJSON.userConsented())
                note("Device signed the key-binding JWT; vp_token posted to the RP.")
                phase = .done("Presentation delivered — only the requested claim was shared.")
            }
        }
    }

    func decline() {
        phase = .running
        Task {
            await executor?.send(eventJson: WalletEventJSON.userDeclined())
            phase = .done("Declined — nothing was shared.")
        }
    }

    func reset() {
        executor = nil
        phase = .home
        log = []
    }
}
