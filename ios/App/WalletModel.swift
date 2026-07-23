import Foundation

// WalletShell sources, the generated UniFFI bindings, and these App sources are compiled into one
// app module (see ios/project.yml), so no cross-module import is needed.

/// Orchestrates the real Rust core for the demo app. One PERSISTENT wallet engine lives for the
/// session: credentials are obtained through a real OpenID4VCI issuance and stored in-core, the
/// wallet home reflects exactly what the core holds, and presentations/payments/history/export all
/// operate on that same engine's state over the FFI. The device signer and RP/issuer trust come
/// from `DemoWallet` (real aws-lc-rs keys), so every run is a genuine end-to-end flow — only the
/// network transport is stubbed.
@MainActor
final class WalletModel: ObservableObject {
    enum Phase: Equatable {
        case home
        case running
        case screen(ScreenDescription)
        case done(String)
        case failed(String)
    }

    /// The credential types this demo wallet can be issued (mirrors the core's attestation
    /// catalogue). Each maps to an issuer-signed credential the stub issuer hands back.
    enum CredentialType: String, CaseIterable, Identifiable {
        case pid = "urn:eudi:pid:1"
        case mdl = "urn:eudi:mdl:1"
        case passport = "urn:eudi:passport:1"
        case nid = "urn:eudi:nid:1"
        case germanId = "urn:eudi:pid:de:1"
        // ISO 18013-5 mDL in the mso_mdoc format (rawValue is the doctype). Issued and presented
        // over the mdoc-over-OpenID4VP path: the response is a signed DeviceResponse, not an SD-JWT.
        case mdlMdoc = "org.iso.18013.5.1.mDL"
        var id: String { rawValue }
        var displayName: String {
            switch self {
            case .pid: return "Digital ID"
            case .mdl: return "Mobile Driving Licence"
            case .passport: return "Passport"
            case .nid: return "National ID Card"
            case .germanId: return "German ID Card"
            case .mdlMdoc: return "Mobile Driving Licence"
            }
        }
        var subtitle: String {
            switch self {
            case .pid: return "Your verified name, age and identity details"
            case .mdl: return "Your driving licence on this phone"
            case .passport: return "Your digital travel document"
            case .nid: return "Government identity card"
            case .germanId: return "Your German identity card"
            case .mdlMdoc: return "Your driving licence on this phone"
            }
        }
        var systemImage: String {
            switch self {
            case .pid: return "person.text.rectangle.fill"
            case .mdl: return "car.fill"
            case .passport: return "book.closed.fill"
            case .nid: return "person.crop.rectangle.fill"
            case .germanId: return "flag.fill"
            case .mdlMdoc: return "car.circle.fill"
            }
        }
        /// The credential format this type issues in — routes the issuance offer + response.
        var issuanceFormat: String {
            self == .mdlMdoc ? "mso_mdoc" : "dc+sd-jwt"
        }
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
    /// The credentials shown on the wallet home — decoded from what the CORE actually holds
    /// (`held_credentials_json`), labelled via the attestation catalogue (TS11).
    @Published private(set) var credentials: [WalletCredential] = []
    /// True while a real OpenID4VCI issuance is running (drives the home's progress state).
    @Published private(set) var isIssuing = false
    /// Drives the real "Connect" sheet (scan/paste a link, probe the live issuer).
    @Published var showConnectSheet = false
    /// Human-readable classification of the last scanned/pasted link.
    @Published var lastScan: String?
    /// Result of probing the live EUDI reference issuer over real HTTPS.
    @Published var probeResult: String?

    private let demo = DemoWallet()
    /// The one controlled runtime for the whole session. Core mutations are available only through
    /// its durable lifecycle; read-only projections remain available for rendering wallet state.
    private let runtime: FfiWalletRuntime?
    private let issuance: IssuanceScenario
    /// RP trust material for presentation (static demo chain), captured once.
    private let rpCertChain: [Data]
    private let redirectUris: [String]
    /// The executor bound to `engine` for the current flow (rebuilt per flow; same engine).
    private var executor: EffectExecutor?
    /// Correlation id attached by Rust to the currently rendered confirmation. A decision without
    /// this exact id is rejected as stale at the production JSON boundary.
    private var decisionOperationId: UInt64?
    private var decisionAuthorizationHash: Data?
    private var decisionKind: WalletDecisionKind?
    /// Monotonic nonce source: a persistent engine records used nonces (replay protection), so each
    /// presentation/payment/issuance must carry a fresh one.
    private var nonceCounter: UInt64 = 1

    init() {
        let issuance = demo.issuanceScenario()
        let scenario = demo.scenario()
        self.issuance = issuance
        self.rpCertChain = scenario.rpCertChain
        self.redirectUris = scenario.registeredRedirectUris
        do {
            runtime = try Self.makeRuntime(issuance)
        } catch {
            runtime = nil
            phase = .failed("We couldn't open your wallet. Please close the app and try again.")
        }
        reloadCredentials()
        reloadHistory()
        presentRestoredStateIfNeeded()
    }

    // MARK: - Engine + executor

    /// Build the persistent engine, configured for BOTH issuance and presentation: device key,
    /// clock, an all-services trusted list, and the Wallet Unit Attestation — but NO credential
    /// (the wallet starts empty; credentials arrive via issuance).
    private static func makeRuntime(_ issuance: IssuanceScenario) throws -> FfiWalletRuntime {
        try FfiWalletRuntime.ephemeralDemo(
            applicationIdentifier: "eu.advatar.wallet.demo",
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

    /// Build an executor bound to the persistent engine. `issuer` is supplied only for issuance;
    /// `render` maps the core's screens to the live UI (or a no-op for silent seeding).
    private func makeExecutor(
        issuer: IssuerResponder?,
        render: @escaping (UInt64?, Data?, ScreenDescription) -> Void
    ) -> EffectExecutor? {
        guard let runtime else {
            phase = .failed("Durable wallet lifecycle is unavailable")
            return nil
        }
        return EffectExecutor(
            lifecycle: runtime.lifecycle,
            signer: DemoSigner(demo: demo),
            http: StubHttpClient(),
            storage: InMemoryStorage(),
            trust: DemoTrustResolver(certChain: rpCertChain, redirectUris: redirectUris),
            issuer: issuer,
            render: render)
    }

    private func liveExecutor() -> EffectExecutor? {
        clearDecision()
        guard let ex = makeExecutor(issuer: nil, render: {
            [weak self] operationId, authorizationHash, screen in
            Task { @MainActor in
                guard let self else { return }
                if let kind = WalletDecisionKind(screen: screen) {
                    self.decisionOperationId = operationId
                    self.decisionAuthorizationHash = authorizationHash
                    self.decisionKind = kind
                } else {
                    self.clearDecision()
                }
                self.phase = .screen(screen)
            }
        }) else { return nil }
        self.executor = ex
        return ex
    }

    private func presentRestoredStateIfNeeded() {
        guard let runtime,
            let recovery = try? runtime.durableResumeEffectsJSON(),
            recovery != "[]",
            let executor = liveExecutor()
        else { return }
        self.executor = executor
        do {
            try executor.presentRestoredState(coreOutput: recovery)
        } catch {
            phase = .failed("We couldn't restore your wallet safely. Please start again.")
        }
    }

    private func nextNonce() -> UInt64 {
        nonceCounter += 1
        return nonceCounter
    }

    private func note(_ line: String) { log.append(line) }

    private func clearDecision() {
        decisionOperationId = nil
        decisionAuthorizationHash = nil
        decisionKind = nil
    }

    private enum RequiredCascadeOutcome: String {
        case awaitingInput
        case succeeded
        case declined
        case idle

        func matches(_ outcome: EffectCascadeOutcome) -> Bool {
            switch (self, outcome) {
            case (.awaitingInput, .awaitingInput), (.succeeded, .succeeded), (.declined, .declined):
                return true
            case (.idle, .idle):
                return true
            default:
                return false
            }
        }
    }

    /// Run one shell cascade and surface infrastructure/core-contract failures as a terminal app
    /// failure. A failed cascade must never let a caller publish a success message.
    @discardableResult
    private func run(
        _ executor: EffectExecutor,
        eventJson: String,
        requiring required: RequiredCascadeOutcome
    ) async -> Bool {
        do {
            let outcome = try await executor.send(eventJson: eventJson)
            guard required.matches(outcome) else {
                let message: String
                if case .aborted(let reason) = outcome {
                    message = reason.message
                } else {
                    message = "Wallet flow returned \(outcome) while \(required.rawValue) was required"
                }
                note("Wallet operation failed: \(message)")
                phase = .failed(message)
                return false
            }
            return true
        } catch {
            let message = error.localizedDescription
            note("Wallet operation failed: \(message)")
            phase = .failed(message)
            return false
        }
    }

    // MARK: - Add a credential (real OpenID4VCI issuance)

    /// Add a credential to the wallet by running a REAL OpenID4VCI issuance through the core: the
    /// core decides issuer trust in-core, gates on the WUA key-attestation, has the device sign the
    /// proof-of-possession, and stores the issuer-signed credential it receives. The home then
    /// reflects the new holding. Only the issuer's token/credential transport is stubbed.
    func addCredential(_ type: CredentialType) {
        guard !isIssuing else { return }
        isIssuing = true
        log = ["Adding \(type.displayName)…"]
        Task {
            guard await issue(type, requiresReview: true) else { isIssuing = false; return }
        }
    }

    /// Screenshot/demo affordance: issue BOTH a PID and an mDL (sequentially — a real issuance is
    /// one OpenID4VCI session at a time), landing on a two-card home.
    func seedBothForDemo() {
        guard !isIssuing else { return }
        isIssuing = true
        Task {
            guard await issue(.pid), await issue(.mdl) else { isIssuing = false; return }
            reloadCredentials()
            reloadHistory()
            isIssuing = false
        }
    }

    /// Screenshot/demo affordance: issue the national ID + German ID cards (sequentially).
    func seedIdCardsForDemo() {
        guard !isIssuing else { return }
        isIssuing = true
        Task {
            guard await issue(.nid), await issue(.germanId) else { isIssuing = false; return }
            reloadCredentials()
            reloadHistory()
            isIssuing = false
        }
    }

    /// Screenshot/demo affordance: issue every supported credential type (sequentially).
    func seedAllForDemo() {
        guard !isIssuing else { return }
        isIssuing = true
        Task {
            for type in CredentialType.allCases {
                guard await issue(type) else { isIssuing = false; return }
            }
            reloadCredentials()
            reloadHistory()
            isIssuing = false
        }
    }

    /// A pre-authorized `mso_mdoc` credential offer — the mdoc analogue of `issuance.offer`, which
    /// declares `dc+sd-jwt`. The offer format must match the issued credential's format (the core
    /// aborts on mismatch), so the mdoc issuance path advertises `mso_mdoc` up front.
    private static let mdocOffer = Data(
        #"{"format":"mso_mdoc","grant":"pre-authorized","tx_code_required":false}"#.utf8)

    /// The awaitable core of issuance (also used to seed demo state silently). Routes the credential
    /// compact, offer, and format by type — `.mdlMdoc` issues the ISO 18013-5 mDL in `mso_mdoc`.
    private func issue(_ type: CredentialType, requiresReview: Bool = false) async -> Bool {
        let compact: String
        switch type {
        case .pid: compact = issuance.pidCredentialCompact
        case .mdl: compact = issuance.mdlCredentialCompact
        case .passport: compact = issuance.passportCredentialCompact
        case .nid: compact = issuance.nidCredentialCompact
        case .germanId: compact = issuance.germanIdCredentialCompact
        case .mdlMdoc: compact = issuance.mdlMdocCredential
        }
        let offer = type == .mdlMdoc ? Self.mdocOffer : issuance.offer
        let issuer = DemoIssuer(
            credentialCompact: Data(compact.utf8),
            cNonce: nextNonce(),
            format: type.issuanceFormat)
        var reviewOperationId: UInt64?
        var reviewAuthorizationHash: Data?
        guard let ex = makeExecutor(issuer: issuer, render: {
            [weak self] operationId, authorizationHash, screen in
            reviewOperationId = operationId
            reviewAuthorizationHash = authorizationHash
            guard requiresReview, let self else { return }
            self.decisionOperationId = operationId
            self.decisionAuthorizationHash = authorizationHash
            self.decisionKind = WalletDecisionKind(screen: screen)
            self.phase = .screen(screen)
        }) else {
            return false
        }
        self.executor = requiresReview ? ex : self.executor
        guard await run(ex, eventJson: WalletEventJSON.credentialOfferReceived(
            offer: offer,
            issuerCertChain: issuance.issuerCertChain,
            issuerId: issuance.issuerId), requiring: .awaitingInput) else { return false }
        if requiresReview { return true }
        guard let reviewOperationId, let reviewAuthorizationHash else { return false }
        return await run(
            ex,
            eventJson: WalletEventJSON.credentialOfferAccepted(
                operationId: reviewOperationId,
                authorizationHash: reviewAuthorizationHash),
            requiring: .succeeded)
    }

    // MARK: - Flows (presentation / payment) on the persistent engine

    /// OpenID4VP remote presentation: request → in-core trust + data minimisation → consent.
    func startPresentation() {
        guard !credentials.isEmpty else { return } // nothing to present yet
        phase = .running
        log = ["Presentation: feeding RP-signed authorization request…"]
        guard let ex = liveExecutor() else { return }
        let request = demo.presentationRequest(nonce: nextNonce())
        Task {
            guard await run(
                ex,
                eventJson: WalletEventJSON.authorizationRequestReceived(request),
                requiring: .awaitingInput
            ) else { return }
            note("Core resolved RP trust in-core and computed the minimised consent screen.")
        }
    }

    /// mdoc-over-OpenID4VP: a DCQL `mso_mdoc` request selects the held mDL by doctype; the core
    /// answers with a signed ISO 18013-5 `DeviceResponse` (device auth over the SessionTranscript).
    func startMdocPresentation() {
        guard credentials.contains(where: { $0.format == "mso_mdoc" }) else { return }
        phase = .running
        log = ["mdoc presentation: feeding RP-signed DCQL mso_mdoc request…"]
        guard let ex = liveExecutor() else { return }
        let request = demo.mdocPresentationRequest(nonce: nextNonce())
        Task {
            guard await run(
                ex,
                eventJson: WalletEventJSON.authorizationRequestReceived(request),
                requiring: .awaitingInput
            ) else { return }
            note("Core selected the mDL by doctype and will emit a signed DeviceResponse vp_token.")
        }
    }

    /// PSD2/TS12 payment SCA: request → what-you-see-is-what-you-authorise confirmation.
    func startPayment() {
        phase = .running
        log = ["Payment: feeding PSD2/TS12 authorization request…"]
        guard let ex = liveExecutor() else { return }
        let request = demo.paymentRequest(nonce: nextNonce())
        Task {
            guard await run(
                ex,
                eventJson: WalletEventJSON.paymentAuthorizationRequestReceived(request),
                requiring: .awaitingInput
            ) else { return }
            note("Core produced the payment confirmation screen (amount + payee bound in-core).")
        }
    }

    /// User approved the on-screen consent/payment: device signs (demo key), core assembles and
    /// the shell "delivers" the vp_token / SCA auth code. Drains to `Close`.
    func approve() {
        let operationId = decisionOperationId
        let authorizationHash = decisionAuthorizationHash
        let kind = decisionKind
        clearDecision()
        phase = .running
        guard let executor else {
            phase = .failed("Wallet executor is unavailable")
            return
        }
        guard let operationId, let authorizationHash, let kind else {
            phase = .failed("Wallet confirmation is no longer active")
            return
        }
        Task {
            guard await run(
                executor,
                eventJson: kind.approvalEvent(
                    operationId: operationId,
                    authorizationHash: authorizationHash),
                requiring: .succeeded
            ) else { return }
            switch kind {
            case .presentation:
                note("Device signed the key-binding JWT; vp_token posted to the RP.")
                reloadHistory()
                phase = .done("Information shared successfully.")
            case .payment:
                note("Device signed the dynamic-linking binding; auth code posted to the PSP.")
                reloadHistory()
                phase = .done("Payment approved.")
            case .qes:
                note("Device authorized the exact document hash; the response was acknowledged by the QTSP.")
                reloadHistory()
                phase = .done("Document signed successfully.")
            case .issuance:
                note("The approved issuer offer completed with a device-bound proof and verified credential.")
                reloadCredentials()
                reloadHistory()
                isIssuing = false
                // The core's final authenticated IssuanceReady screen is the product completion
                // state. Do not replace it with the shell's generic completion message.
            }
        }
    }

    func decline() {
        let operationId = decisionOperationId
        let kind = decisionKind
        clearDecision()
        phase = .running
        guard let executor else {
            phase = .failed("Wallet executor is unavailable")
            return
        }
        guard let operationId, let kind else {
            phase = .failed("Wallet confirmation is no longer active")
            return
        }
        Task {
            guard await run(
                executor,
                eventJson: kind.declineEvent(operationId: operationId),
                requiring: .declined
            ) else { return }
            if kind == .issuance { isIssuing = false }
            phase = .done(kind == .issuance ? "Nothing was added." : "Nothing was shared.")
        }
    }

    func reset() {
        executor = nil
        clearDecision()
        phase = .home
        log = []
    }

    /// Demo/screenshot affordance: add a PID, then drive a full presentation AND a full payment to
    /// completion SILENTLY through the persistent engine, so the wallet holds a credential and the
    /// log holds both entries. `redactFirst` erases entry #0 (TS07); `thenExport` opens the export
    /// sheet (TS10).
    func seedHistoryForDemo(redactFirst: Bool = false, thenExport: Bool = false) {
        Task {
            guard await issue(.pid) else { return }
            var seededOperationId: UInt64?
            var seededAuthorizationHash: Data?
            guard let ex = makeExecutor(issuer: nil, render: {
                operationId, authorizationHash, _ in
                seededOperationId = operationId
                seededAuthorizationHash = authorizationHash
            }) else { return }
            guard await run(
                ex,
                eventJson: WalletEventJSON.authorizationRequestReceived(
                    demo.presentationRequest(nonce: nextNonce())),
                requiring: .awaitingInput) else { return }
            guard let presentationOperationId = seededOperationId else { return }
            guard let presentationAuthorizationHash = seededAuthorizationHash else { return }
            guard await run(
                ex,
                eventJson: WalletEventJSON.userConsented(
                    operationId: presentationOperationId,
                    authorizationHash: presentationAuthorizationHash),
                requiring: .succeeded) else { return }
            guard await run(
                ex,
                eventJson: WalletEventJSON.paymentAuthorizationRequestReceived(
                    demo.paymentRequest(nonce: nextNonce())),
                requiring: .awaitingInput) else { return }
            guard let paymentOperationId = seededOperationId else { return }
            guard let paymentAuthorizationHash = seededAuthorizationHash else { return }
            guard await run(
                ex,
                eventJson: WalletEventJSON.paymentApproved(
                    operationId: paymentOperationId,
                    authorizationHash: paymentAuthorizationHash),
                requiring: .succeeded) else { return }
            if redactFirst {
                guard await run(
                    ex,
                    eventJson: WalletEventJSON.historyRedaction(seq: 0),
                    requiring: .idle
                ) else { return }
            }
            reloadCredentials()
            reloadHistory()
            if thenExport {
                exportPreview = makeExport()
            }
        }
    }

    // MARK: - Holdings + P1 operations (all real core functions over the FFI)

    /// Rebuild the wallet home's cards from what the core holds (`held_credentials_json`), labelled
    /// via the attestation catalogue. Never shows raw disclosure blobs — decodes each to its value.
    func reloadCredentials() {
        let catalogue = catalogueItems()
        guard let runtime,
              let data = runtime.heldCredentialsJSON().data(using: .utf8),
              let arr = try? JSONSerialization.jsonObject(with: data) as? [[String: Any]]
        else {
            credentials = []
            return
        }
        credentials = arr.enumerated().map { i, obj in
            Self.decodeCard(obj, index: i, catalogue: catalogue)
        }
    }

    /// Decode one `held_credentials_json` entry into a card: label each disclosure via the
    /// catalogue, derive the holder from name claims, colour by type.
    private static func decodeCard(
        _ obj: [String: Any], index: Int, catalogue: [CatalogueItem]
    ) -> WalletCredential {
        let vct = obj["vct"] as? String ?? "unknown"
        let format = obj["format"] as? String ?? "dc+sd-jwt"
        let issuer = (obj["issuer"] as? String ?? "").replacingOccurrences(of: "https://", with: "")
        let type = catalogue.first { $0.id == vct }
        var labelFor: [String: String] = [:]
        for c in type?.claims ?? [] { labelFor[c.path] = c.displayName }

        var claims: [(String, String)] = []
        var given = "", family = ""
        // mdoc entries carry their (already-decoded) element values directly in `claims`; SD-JWT
        // entries carry base64url disclosure blobs in `disclosuresByClaim`.
        if let mdocClaims = obj["claims"] as? [String: Any], !mdocClaims.isEmpty {
            for (elementId, value) in mdocClaims.sorted(by: { $0.key < $1.key }) {
                let v = String(describing: value)
                if elementId == "given_name" { given = v }
                if elementId == "family_name" { family = v }
                claims.append((labelFor[elementId] ?? elementId, v))
            }
        } else {
            let disclosures = obj["disclosuresByClaim"] as? [String: String] ?? [:]
            for (claim, disclosureB64) in disclosures.sorted(by: { $0.key < $1.key }) {
                guard let raw = base64urlDecode(disclosureB64),
                      let a = try? JSONSerialization.jsonObject(with: raw) as? [Any], a.count == 3
                else { continue }
                let value = String(describing: a[2])
                if claim == "given_name" { given = value }
                if claim == "family_name" { family = value }
                claims.append((labelFor[claim] ?? claim, value))
            }
        }
        let holder = [given, family].filter { !$0.isEmpty }.joined(separator: " ")
        let typeName = type?.displayName
            ?? (format == "mso_mdoc" ? "Mobile Driving Licence (mdoc)" : vct)
        return WalletCredential(
            id: "\(vct)#\(index)",
            typeName: typeName,
            issuer: issuer.isEmpty ? "issuer" : issuer,
            holder: holder.isEmpty ? "EU Citizen" : holder,
            claims: claims,
            format: format,
            gradientHex: gradient(for: vct))
    }

    /// Card gradient by credential type (our own palette; not any product's branding).
    private static func gradient(for vct: String) -> (UInt32, UInt32) {
        switch vct {
        case "urn:eudi:mdl:1": return (0x0E8F6B, 0x14B37D)      // teal-green: driving licence
        case "urn:eudi:passport:1": return (0x7A1E2B, 0xB23A48) // burgundy: passport
        case "urn:eudi:nid:1": return (0xB5651D, 0xE08A2E)      // amber: national ID
        case "urn:eudi:pid:de:1": return (0x6B5410, 0xC9A227)   // bronze-gold: German ID
        default: return (0x2A5BD7, 0x6E48D9)                    // blue-purple: PID
        }
    }

    /// Base64url (no padding) → bytes.
    private static func base64urlDecode(_ s: String) -> Data? {
        var b = s.replacingOccurrences(of: "-", with: "+").replacingOccurrences(of: "_", with: "/")
        while b.count % 4 != 0 { b.append("=") }
        return Data(base64Encoded: b)
    }

    /// Refresh the history list + activity report from the engine's in-core log.
    func reloadHistory() {
        guard let runtime else {
            history = []
            report = nil
            return
        }
        if let data = runtime.transactionLogJSON().data(using: .utf8),
           let items = try? JSONDecoder().decode([HistoryItem].self, from: data) {
            history = items
        }
        if let data = runtime.transactionReportJSON().data(using: .utf8),
           let r = try? JSONDecoder().decode(ActivityReport.self, from: data) {
            report = r
        }
    }

    /// Erase one entry's content (TS07). The core leaves a chain-preserving tombstone.
    func redact(seq: UInt64) {
        guard let executor = makeExecutor(issuer: nil, render: { _, _, _ in }) else { return }
        Task {
            guard await run(
                executor,
                eventJson: WalletEventJSON.historyRedaction(seq: seq),
                requiring: .idle
            ) else { return }
            reloadHistory()
        }
    }

    /// Erase the entire log (TS07).
    func wipeLog() {
        guard let executor = makeExecutor(issuer: nil, render: { _, _, _ in }) else { return }
        Task {
            guard await run(
                executor,
                eventJson: WalletEventJSON.historyWipe(),
                requiring: .idle
            ) else { return }
            reloadHistory()
        }
    }

    /// The integrity-protected export bundle (TS10) plus whether it verifies, and a proof that a
    /// TAMPERED copy fails — both checks performed by the core's own verifier.
    func makeExport() -> ExportPreview? {
        guard let runtime else { return nil }
        let json = runtime.exportJSON()
        let verifies = verifyWalletExport(json: json)
        let tampered = json.replacingOccurrences(of: "rp.example", with: "evil.example")
        let tamperDetected = tampered != json && !verifyWalletExport(json: tampered)
        return ExportPreview(json: json, verifies: verifies, tamperDetected: tamperDetected)
    }

    /// The attestation catalogue (TS11): the credential types this wallet understands.
    func catalogueItems() -> [CatalogueItem] {
        guard let runtime,
              let data = runtime.attestationCatalogueJSON().data(using: .utf8),
              let items = try? JSONDecoder().decode([CatalogueItem].self, from: data)
        else { return [] }
        return items
    }

    // MARK: - Real connect (foundation for issuer/verifier over the network)

    /// Classify a scanned/pasted link — what wallet action it would trigger (add a credential vs.
    /// present to a verifier) — using the pure `ScannedRequest` parser.
    func handleScanned(_ text: String) {
        switch ScannedRequest.parse(text) {
        case let .credentialOffer(issuer, ids):
            lastScan = "✅ Credential offer from \(issuer)\n"
                + "\(ids.count) type(s): \(ids.joined(separator: ", "))"
        case let .credentialOfferByReference(uri):
            lastScan = "✅ Credential offer (by reference)\n\(uri)"
        case let .presentation(requestUri, clientId):
            lastScan = "✅ Presentation request\nclient: \(clientId ?? "—")\n"
                + "request_uri: \(requestUri ?? "—")"
        case let .unknown(s):
            lastScan = "⚠️ Not a recognised wallet link:\n\(s.prefix(80))"
        }
    }

    /// Fetch the LIVE EUDI reference issuer's metadata over real HTTPS — proof that real networking
    /// works end to end, and a listing of the credential types the reference issuer offers.
    func probeReferenceIssuer() {
        probeResult = "Contacting issuer.eudiw.dev…"
        Task {
            let client = URLSessionHttpClient()
            do {
                let response = try await client.fetchIssuerMetadata(
                    issuer: "https://issuer.eudiw.dev")
                var summary = "HTTP \(response.statusCode)"
                if response.statusCode == 200,
                   let obj = try? JSONSerialization.jsonObject(with: response.body) as? [String: Any] {
                    let iss = obj["credential_issuer"] as? String ?? "?"
                    let configs = (obj["credential_configurations_supported"] as? [String: Any])?.keys.sorted()
                        ?? (obj["credentials_supported"] as? [String: Any])?.keys.sorted()
                        ?? []
                    summary += "\nissuer: \(iss)\n\(configs.count) credential types; e.g.\n• "
                        + configs.prefix(5).joined(separator: "\n• ")
                } else {
                    summary += "\n" + String(
                        decoding: response.body.prefix(200),
                        as: UTF8.self)
                }
                probeResult = summary
            } catch {
                probeResult = "Network error: \(error.localizedDescription)"
            }
        }
    }

    /// A short fingerprint of the device's REAL signing key (strict Secure Enclave policy on a
    /// physical device; an explicit development-only keychain key on the Simulator).
    func deviceKeyPreview() -> String {
        let signer = SecureEnclaveSigner()
        if let pub = try? signer.publicKeyRaw(keyRef: "wallet-device-key") {
            let head = pub.prefix(8).map { String(format: "%02x", $0) }.joined()
            return "\(head)… (\(pub.count) bytes)"
        }
        return "unavailable"
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

/// A credential shown on the wallet home — decoded from what the core holds, labelled via the
/// catalogue. `claims` are (display name, value) pairs; the card never shows raw disclosure blobs.
struct WalletCredential: Identifiable {
    let id: String
    let typeName: String
    let issuer: String
    let holder: String
    let claims: [(String, String)]
    /// The credential format (`dc+sd-jwt` or `mso_mdoc`) — drives the format badge + mdoc present.
    let format: String
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
