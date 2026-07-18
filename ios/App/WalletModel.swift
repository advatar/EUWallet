import Foundation

// WalletShell sources, the generated UniFFI bindings, and these App sources are compiled into one
// app module (see ios/project.yml), so no cross-module import is needed.

/// Orchestrates the real Rust core for the demo app. Flows run through a WALLET ENGINE that is
/// kept alive afterwards, so the P1 screens (history, deletion, report, export) operate on the
/// engine's real in-core state over the FFI — redaction, wiping, reporting, and export are the
/// Rust core's own functions, not Swift re-implementations. The device signer and RP trust come
/// from `DemoWallet` (real aws-lc-rs keys), so every run is a genuine end-to-end flow.
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
    /// The wallet engine's transaction log (TS06), decoded straight from the core's JSON. Redacted
    /// entries appear as tombstones. Reloaded after every operation that can change it.
    @Published private(set) var history: [HistoryItem] = []
    /// The privacy-preserving activity report (TS08), from the core.
    @Published private(set) var report: ActivityReport?
    /// The export sheet's content when presented (TS10).
    @Published var exportPreview: ExportPreview?
    /// The credentials shown on the wallet home, decoded from the held credential's disclosures
    /// with display names from the attestation catalogue (TS11).
    @Published private(set) var credentials: [WalletCredential] = []

    private var executor: EffectExecutor?
    /// The engine whose log/report/export the P1 screens operate on (the most recent flows).
    private var engine: WalletEngine?

    init() {
        loadWallet()
    }

    /// Populate the wallet's held credentials from the demo scenario, decoding each disclosure
    /// (`[salt, name, value]`) to a display value and labelling it via the attestation catalogue.
    private func loadWallet() {
        let scenario = DemoWallet().scenario()
        let pidType = catalogueItems().first { $0.id == "urn:eudi:pid:1" }

        // claim path -> display name, from the catalogue.
        var display: [String: String] = [:]
        for c in pidType?.claims ?? [] { display[c.path] = c.displayName }

        // Decode disclosures: { "<claim>": "<base64url([salt,name,value])>" }.
        var claims: [(String, String)] = []
        if let data = scenario.disclosuresByClaimJson.data(using: .utf8),
           let obj = try? JSONSerialization.jsonObject(with: data) as? [String: String] {
            for (claim, disclosureB64) in obj.sorted(by: { $0.key < $1.key }) {
                guard let raw = Self.base64urlDecode(disclosureB64),
                      let arr = try? JSONSerialization.jsonObject(with: raw) as? [Any],
                      arr.count == 3
                else { continue }
                let value = String(describing: arr[2])
                claims.append((display[claim] ?? claim, value))
            }
        }
        let holder = claims.first { $0.0 == "Family name" }.map { "A. \($0.1)" } ?? "EU Citizen"
        credentials = [
            WalletCredential(
                id: "urn:eudi:pid:1",
                typeName: pidType?.displayName ?? "Person Identification Data",
                issuer: "issuer.example",
                holder: holder,
                claims: claims,
                gradientHex: (0x2A5BD7, 0x6E48D9))
        ]
    }

    /// Base64url (no padding) → bytes.
    private static func base64urlDecode(_ s: String) -> Data? {
        var b = s.replacingOccurrences(of: "-", with: "+").replacingOccurrences(of: "_", with: "/")
        while b.count % 4 != 0 { b.append("=") }
        return Data(base64Encoded: b)
    }


    /// Build a fresh engine loaded with the demo credential, device key, and trusted list.
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
                reloadHistory()
                phase = .done("Payment authorised — SCA auth code delivered.")
            } else {
                await executor?.send(eventJson: WalletEventJSON.userConsented())
                note("Device signed the key-binding JWT; vp_token posted to the RP.")
                reloadHistory()
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
    /// SILENTLY (no-op render) through ONE engine — exactly like the core's own txn_log test — so
    /// the wallet log holds both entries and the P1 screens operate on real accumulated state.
    /// `redactFirst` then erases entry #0 (the TS07 tombstone path); `thenExport` opens the TS10
    /// export sheet.
    func seedHistoryForDemo(redactFirst: Bool = false, thenExport: Bool = false) {
        Task {
            let (e, d, s) = makeEngine()
            self.engine = e
            let ex = makeExecutor(e, d, s, render: { _ in })
            await ex.send(
                eventJson: WalletEventJSON.authorizationRequestReceived(s.presentationRequest))
            await ex.send(eventJson: WalletEventJSON.userConsented())
            await ex.send(
                eventJson: WalletEventJSON.paymentAuthorizationRequestReceived(s.paymentRequest))
            await ex.send(eventJson: WalletEventJSON.paymentApproved())
            if redactFirst {
                _ = e.redactTransaction(seq: 0)
            }
            reloadHistory()
            if thenExport {
                exportPreview = makeExport()
            }
        }
    }

    // MARK: - P1 operations (all real core functions over the FFI)

    /// Refresh the history list + activity report from the engine's in-core log.
    func reloadHistory() {
        guard let engine else {
            history = []
            report = nil
            return
        }
        if let data = engine.transactionLogJson().data(using: .utf8),
           let items = try? JSONDecoder().decode([HistoryItem].self, from: data) {
            history = items
        }
        if let data = engine.transactionReportJson().data(using: .utf8),
           let r = try? JSONDecoder().decode(ActivityReport.self, from: data) {
            report = r
        }
    }

    /// Erase one entry's content (TS07). The core leaves a chain-preserving tombstone.
    func redact(seq: UInt64) {
        _ = engine?.redactTransaction(seq: seq)
        reloadHistory()
    }

    /// Erase the entire log (TS07).
    func wipeLog() {
        engine?.wipeTransactionLog()
        reloadHistory()
    }

    /// The integrity-protected export bundle (TS10) plus whether it verifies, and a proof that a
    /// TAMPERED copy fails — both checks performed by the core's own verifier.
    func makeExport() -> ExportPreview? {
        guard let engine else { return nil }
        let json = engine.exportJson()
        let verifies = verifyWalletExport(json: json)
        let tampered = json.replacingOccurrences(of: "rp.example", with: "evil.example")
        let tamperDetected = tampered != json && !verifyWalletExport(json: tampered)
        return ExportPreview(json: json, verifies: verifies, tamperDetected: tamperDetected)
    }

    /// The attestation catalogue (TS11): the credential types this wallet understands.
    func catalogueItems() -> [CatalogueItem] {
        let e = engine ?? makeEngine().0
        guard let data = e.attestationCatalogueJson().data(using: .utf8),
              let items = try? JSONDecoder().decode([CatalogueItem].self, from: data)
        else { return [] }
        return items
    }
}

/// One transaction-log entry as decoded from `WalletEngine.transactionLogJson()`. Mirrors the
/// core's privacy-preserving record: claim PATHS + a committing consent hash, never values.
/// `redacted == true` marks a chain-preserving tombstone (content erased, position retained).
struct HistoryItem: Decodable {
    let seq: UInt64
    let kind: String
    let counterparty: String
    let outcome: String
    let consentHash: String
    let redacted: Bool
    let claimPaths: [String]
    let payment: PaymentInfo?

    struct PaymentInfo: Decodable {
        let payee: String
        let amountMinor: UInt64
        let currency: String
    }
}

/// The core's activity report (TS08): counts only, no claim values.
struct ActivityReport: Decodable {
    let total: Int
    let presentations: Int
    let issuances: Int
    let payments: Int
    let transfers: Int
    let redacted: Int
    let counterparties: [String]
}

/// The export bundle (TS10) with the core-verified integrity results for display.
struct ExportPreview: Identifiable {
    let id = UUID()
    let json: String
    let verifies: Bool
    let tamperDetected: Bool
}

/// A credential shown on the wallet home — decoded from the held credential, labelled via the
/// catalogue. `claims` are (display name, value) pairs; the card never shows raw disclosure blobs.
struct WalletCredential: Identifiable {
    let id: String
    let typeName: String
    let issuer: String
    let holder: String
    let claims: [(String, String)]
    /// Two hex colors for the card gradient.
    let gradientHex: (UInt32, UInt32)
}

/// One attestation-catalogue entry (TS11).
struct CatalogueItem: Decodable {
    let id: String
    let displayName: String
    let format: String
    let claims: [Claim]
    let trustedIssuers: [String]

    struct Claim: Decodable {
        let path: String
        let displayName: String
        let mandatory: Bool
    }
}
