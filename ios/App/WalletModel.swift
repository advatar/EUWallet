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
    /// Accumulated audit-log entries across flows. Each one-shot flow engine records one entry;
    /// we absorb it here so the History screen shows the running privacy-preserving log (TS06).
    @Published private(set) var history: [HistoryItem] = []

    private var executor: EffectExecutor?
    private var engine: WalletEngine?

    /// Build a fresh engine loaded with the demo credential, device key, and trusted list. The
    /// core is a one-shot state machine, so each flow gets its own engine.
    private func makeEngine() -> (WalletEngine, DemoWallet, DemoScenario) {
        let engine = WalletEngine(walletClientId: "wallet.example", deviceKeyRef: "device-key")
        let demo = DemoWallet()
        let scenario = demo.scenario()
        // These are FFI calls, not events. RP registration, minimisation, key binding: all in-core.
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
        return (engine, demo, scenario)
    }

    /// Build an executor for `engine`; `render` maps the core's screens somewhere (the live UI, or
    /// a no-op for silent seeding).
    private func makeExecutor(
        _ engine: WalletEngine, _ demo: DemoWallet, _ scenario: DemoScenario,
        render: @escaping (ScreenDescription) -> Void
    ) -> EffectExecutor {
        EffectExecutor(
            engine: engine,
            signer: DemoSigner(demo: demo),
            http: StubHttpClient(),
            storage: InMemoryStorage(),
            trust: DemoTrustResolver(
                certChain: scenario.rpCertChain,
                redirectUris: scenario.registeredRedirectUris),
            render: render)
    }

    /// Build the live flow: renders drive the visible UI via `phase`.
    private func freshFlow() -> DemoScenario {
        let (engine, demo, scenario) = makeEngine()
        self.engine = engine
        self.executor = makeExecutor(engine, demo, scenario) { [weak self] screen in
            Task { @MainActor in self?.phase = .screen(screen) }
        }
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
                absorbLog()
                phase = .done("Payment authorised — SCA auth code delivered.")
            } else {
                await executor?.send(eventJson: WalletEventJSON.userConsented())
                note("Device signed the key-binding JWT; vp_token posted to the RP.")
                absorbLog()
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

    /// Demo/screenshot affordance: drive a full presentation AND a full payment to completion
    /// SILENTLY (no-op render, so `phase`/navigation are untouched), populating the history.
    func seedHistoryForDemo() {
        Task {
            let (pe, pd, ps) = makeEngine()
            let pex = makeExecutor(pe, pd, ps, render: { _ in })
            await pex.send(
                eventJson: WalletEventJSON.authorizationRequestReceived(ps.presentationRequest))
            await pex.send(eventJson: WalletEventJSON.userConsented())
            absorb(pe)

            let (ye, yd, ys) = makeEngine()
            let yex = makeExecutor(ye, yd, ys, render: { _ in })
            await yex.send(
                eventJson: WalletEventJSON.paymentAuthorizationRequestReceived(ys.paymentRequest))
            await yex.send(eventJson: WalletEventJSON.paymentApproved())
            absorb(ye)
        }
    }

    /// Read the live flow engine's audit log and append its entries to the running history.
    private func absorbLog() {
        if let engine { absorb(engine) }
    }

    /// Append `engine`'s audit-log entries to the running history. Each one-shot engine holds only
    /// its own flow's entries, so this accumulates across flows.
    private func absorb(_ engine: WalletEngine) {
        guard let data = engine.transactionLogJson().data(using: .utf8),
              let items = try? JSONDecoder().decode([HistoryItem].self, from: data)
        else { return }
        history.append(contentsOf: items)
    }
}

/// One transaction-log entry as decoded from `WalletEngine.transactionLogJson()`. Mirrors the
/// core's privacy-preserving record: claim PATHS + a committing consent hash, never values.
struct HistoryItem: Decodable {
    let kind: String
    let counterparty: String
    let outcome: String
    let consentHash: String
    let claimPaths: [String]
    let payment: PaymentInfo?

    struct PaymentInfo: Decodable {
        let payee: String
        let amountMinor: UInt64
        let currency: String
    }
}
