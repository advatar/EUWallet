import SwiftUI

/// A minimal SwiftUI harness that runs the real Rust wallet core on the iOS Simulator.
///
/// Two orthogonal state owners (plan §8.10):
///  - `WalletModel` surfaces the core's screen *content* (`ScreenDescription` over the FFI) and
///    the P1 wallet functions (history/deletion/report/export/catalogue — all core FFI calls).
///  - `NavigationMachine` owns app-shell *containment/routing*. It holds no security state.
@main
struct EUWalletDemoApp: App {
    var body: some Scene {
        WindowGroup { ContentView() }
    }
}

struct ContentView: View {
    @StateObject private var model = WalletModel()
    @StateObject private var nav = NavigationMachine()

    var body: some View {
        NavigationStack {
            container
                .navigationTitle("EUDI Wallet")
                .padding()
        }
        // Derive coarse navigation milestones from what the core rendered — a thin mapping, NOT
        // protocol logic (the machine never sees credential data).
        .onChange(of: model.phase) { phase in
            switch phase {
            case .screen: nav.send(.startPresentation)
            case .done, .failed: nav.send(.presentationCompleted)
            default: break
            }
        }
        .onAppear(perform: handleLaunchArguments)
    }

    /// The app-shell container the navigation machine currently presents.
    @ViewBuilder private var container: some View {
        switch nav.state {
        case .onboarding:
            OnboardingView { nav.send(.finishedOnboarding) }
        case .home:
            HomeView(
                startPresentation: { nav.send(.startPresentation); model.startPresentation() },
                startPayment: { nav.send(.startPresentation); model.startPayment() },
                openHistory: { model.reloadHistory(); nav.send(.openHistory) },
                openCatalogue: { nav.send(.openCatalogue) },
                openSettings: { nav.send(.openSettings) },
                historyCount: model.history.count)
        case .presenting:
            PresentingContainer(model: model) {
                model.reset()
                nav.send(.presentationCompleted)
            }
        case .settings:
            SettingsView { nav.send(.cancelled) }
        case .history:
            HistoryView(model: model) { nav.send(.cancelled) }
        case .catalogue:
            CatalogueView(items: model.catalogueItems()) { nav.send(.cancelled) }
        case .issuing, .scanning:
            ProgressView()
        }
    }

    /// UI-test / screenshot affordance: `-autostart presentation|payment|history|catalogue`.
    private func handleLaunchArguments() {
        let args = ProcessInfo.processInfo.arguments
        guard let i = args.firstIndex(of: "-autostart"), i + 1 < args.count else { return }
        switch args[i + 1] {
        case "presentation": nav.send(.startPresentation); model.startPresentation()
        case "payment": nav.send(.startPresentation); model.startPayment()
        case "history":
            model.seedHistoryForDemo()
            nav.send(.finishedOnboarding)
            nav.send(.openHistory)
        case "history-redacted":
            model.seedHistoryForDemo(redactFirst: true)
            nav.send(.finishedOnboarding)
            nav.send(.openHistory)
        case "export":
            model.seedHistoryForDemo(thenExport: true)
            nav.send(.finishedOnboarding)
            nav.send(.openHistory)
        case "catalogue":
            nav.send(.finishedOnboarding)
            nav.send(.openCatalogue)
        default: break
        }
    }
}

/// First-run container (app-shell, no core involvement).
struct OnboardingView: View {
    let onContinue: () -> Void
    var body: some View {
        VStack(alignment: .leading, spacing: 16) {
            Spacer()
            Image(systemName: "wallet.pass").font(.system(size: 48)).foregroundStyle(.tint)
            Text("Your EU Digital Identity").font(.title.bold())
            Text("Present credentials and authorise payments — every trust, minimisation and "
                 + "signing decision is made in the verified Rust core.")
                .font(.body).foregroundStyle(.secondary)
            Spacer()
            Button("Get started", action: onContinue)
                .buttonStyle(.borderedProminent)
                .frame(maxWidth: .infinity)
        }
        .frame(maxWidth: .infinity, alignment: .leading)
    }
}

/// Flow picker. Each row drives one real core flow or opens a P1 wallet screen.
struct HomeView: View {
    let startPresentation: () -> Void
    let startPayment: () -> Void
    let openHistory: () -> Void
    let openCatalogue: () -> Void
    let openSettings: () -> Void
    let historyCount: Int

    var body: some View {
        VStack(alignment: .leading, spacing: 18) {
            Text("Running the real Rust core on-device.")
                .font(.subheadline).foregroundStyle(.secondary)

            Button(action: startPresentation) {
                Label {
                    VStack(alignment: .leading) {
                        Text("Identity presentation").font(.headline)
                        Text("OpenID4VP · data-minimised consent").font(.caption)
                    }
                } icon: { Image(systemName: "person.text.rectangle") }
            }
            .buttonStyle(.bordered)

            Button(action: startPayment) {
                Label {
                    VStack(alignment: .leading) {
                        Text("Payment authorisation").font(.headline)
                        Text("PSD2/TS12 · strong customer authentication").font(.caption)
                    }
                } icon: { Image(systemName: "creditcard") }
            }
            .buttonStyle(.bordered)

            Button(action: openHistory) {
                Label {
                    VStack(alignment: .leading) {
                        Text("Transaction history").font(.headline)
                        Text("\(historyCount) recorded · erase & report · paths, never values")
                            .font(.caption)
                    }
                } icon: { Image(systemName: "list.bullet.rectangle") }
            }
            .buttonStyle(.bordered)

            Button(action: openCatalogue) {
                Label {
                    VStack(alignment: .leading) {
                        Text("Credential catalogue").font(.headline)
                        Text("TS11 · attestation types this wallet understands").font(.caption)
                    }
                } icon: { Image(systemName: "books.vertical") }
            }
            .buttonStyle(.bordered)

            Spacer()
            Button(action: openSettings) {
                Label("Settings", systemImage: "gear")
            }
            .font(.subheadline)
        }
        .frame(maxWidth: .infinity, alignment: .leading)
    }
}

/// The container the navigation machine presents for an in-flight flow.
struct PresentingContainer: View {
    @ObservedObject var model: WalletModel
    let onFinish: () -> Void

    var body: some View {
        switch model.phase {
        case .running, .home:
            ProgressView("Working with the core…")
        case .screen(let screen):
            ScreenRenderer(screen: screen, onConsent: model.approve, onDecline: model.decline)
        case .done(let message):
            ResultView(symbol: "checkmark.seal.fill", tint: .green, message: message,
                       log: model.log, onDone: onFinish)
        case .failed(let message):
            ResultView(symbol: "xmark.octagon.fill", tint: .red, message: message,
                       log: model.log, onDone: onFinish)
        }
    }
}

/// The transaction-history screen (TS06/07/08/10). Every action here is a REAL core function over
/// the FFI: swipe-to-erase → chain-preserving redaction; Report → in-core activity summary;
/// Export → integrity-hashed bundle verified (and tamper-checked) by the core; Wipe → full erasure.
struct HistoryView: View {
    @ObservedObject var model: WalletModel
    let onBack: () -> Void

    var body: some View {
        VStack(alignment: .leading, spacing: 10) {
            if let r = model.report {
                Text("\(r.total) recorded · \(r.presentations) presentations · \(r.payments) payments · \(r.redacted) erased")
                    .font(.caption).foregroundStyle(.secondary)
                    .accessibilityLabel("Activity report")
            }
            if model.history.isEmpty {
                Spacer()
                Text("No transactions yet. Run a presentation or payment first.")
                    .font(.callout).foregroundStyle(.secondary)
                Spacer()
            } else {
                List {
                    ForEach(model.history, id: \.seq) { item in
                        HistoryRow(item: item)
                            .listRowInsets(EdgeInsets(top: 8, leading: 4, bottom: 8, trailing: 4))
                            .swipeActions(edge: .trailing) {
                                if !item.redacted {
                                    Button(role: .destructive) {
                                        model.redact(seq: item.seq)
                                    } label: {
                                        Label("Erase", systemImage: "trash")
                                    }
                                }
                            }
                    }
                }
                .listStyle(.plain)
            }
            HStack(spacing: 12) {
                Button("Back", action: onBack).buttonStyle(.borderedProminent)
                Spacer()
                Button {
                    model.exportPreview = model.makeExport()
                } label: {
                    Label("Export", systemImage: "square.and.arrow.up")
                }
                Button(role: .destructive) {
                    model.wipeLog()
                } label: {
                    Label("Wipe", systemImage: "trash.slash")
                }
            }
            .font(.subheadline)
        }
        .frame(maxWidth: .infinity, alignment: .leading)
        .sheet(item: $model.exportPreview) { preview in
            ExportSheet(preview: preview)
        }
    }
}

struct HistoryRow: View {
    let item: HistoryItem

    private var icon: String {
        if item.redacted { return "trash.slash" }
        switch item.kind {
        case "payment": return "creditcard"
        case "issuance": return "plus.rectangle.on.folder"
        default: return "person.text.rectangle"
        }
    }

    var body: some View {
        HStack(alignment: .top, spacing: 12) {
            Image(systemName: icon).font(.title3)
                .foregroundStyle(item.redacted ? AnyShapeStyle(.tertiary) : AnyShapeStyle(.tint))
                .frame(width: 28)
            VStack(alignment: .leading, spacing: 3) {
                if item.redacted {
                    Text("Erased entry").font(.headline).foregroundStyle(.secondary)
                    Text("Content removed · position #\(item.seq) retained, chain intact")
                        .font(.caption).foregroundStyle(.tertiary)
                } else {
                    Text(item.counterparty).font(.headline)
                    if let p = item.payment {
                        Text(String(format: "%.2f %@", Double(p.amountMinor) / 100.0, p.currency))
                            .font(.subheadline)
                    } else if !item.claimPaths.isEmpty {
                        Text("Shared: \(item.claimPaths.joined(separator: ", "))")
                            .font(.subheadline)
                    }
                    Text("\(item.kind.capitalized) · \(item.outcome)")
                        .font(.caption).foregroundStyle(.secondary)
                    Text("consent \(item.consentHash.prefix(12))…")
                        .font(.caption2).foregroundStyle(.tertiary)
                }
            }
        }
        .accessibilityElement(children: .combine)
    }
}

/// The export bundle (TS10): shown with the CORE's own verification verdicts — the untampered
/// bundle verifies, a tampered copy is detected.
struct ExportSheet: View {
    let preview: ExportPreview

    private var integrityHash: String {
        guard let data = preview.json.data(using: .utf8),
              let obj = try? JSONSerialization.jsonObject(with: data) as? [String: Any],
              let h = obj["integrityHash"] as? String
        else { return "—" }
        return h
    }

    var body: some View {
        VStack(alignment: .leading, spacing: 14) {
            Text("Wallet export").font(.title2.bold())
            Label(
                preview.verifies ? "Integrity verified by the core" : "Integrity check FAILED",
                systemImage: preview.verifies ? "checkmark.seal.fill" : "xmark.octagon.fill")
                .foregroundStyle(preview.verifies ? .green : .red)
            Label(
                preview.tamperDetected
                    ? "Tampered copy detected and rejected" : "Tamper check inconclusive",
                systemImage: preview.tamperDetected ? "shield.checkered" : "questionmark.diamond")
                .foregroundStyle(preview.tamperDetected ? .green : .orange)
            Text("SHA-256 \(integrityHash.prefix(24))…")
                .font(.caption.monospaced()).foregroundStyle(.secondary)
            Divider()
            ScrollView {
                Text(preview.json)
                    .font(.caption2.monospaced())
                    .frame(maxWidth: .infinity, alignment: .leading)
            }
        }
        .padding()
    }
}

/// The attestation catalogue (TS11): the credential types this wallet understands, straight from
/// the core (`attestationCatalogueJson`).
struct CatalogueView: View {
    let items: [CatalogueItem]
    let onBack: () -> Void

    var body: some View {
        VStack(alignment: .leading, spacing: 12) {
            if items.isEmpty {
                Text("No attestation types registered.").foregroundStyle(.secondary)
            } else {
                List {
                    ForEach(items, id: \.id) { item in
                        VStack(alignment: .leading, spacing: 6) {
                            Text(item.displayName).font(.headline)
                            Text("\(item.id) · \(item.format)")
                                .font(.caption.monospaced()).foregroundStyle(.secondary)
                            ForEach(item.claims, id: \.path) { claim in
                                HStack(spacing: 6) {
                                    Image(systemName: claim.mandatory ? "asterisk.circle.fill" : "circle")
                                        .font(.caption2)
                                        .foregroundStyle(claim.mandatory ? AnyShapeStyle(.tint) : AnyShapeStyle(.tertiary))
                                    Text(claim.displayName).font(.subheadline)
                                    Text(claim.path).font(.caption.monospaced()).foregroundStyle(.tertiary)
                                }
                            }
                            Text("Issuers: \(item.trustedIssuers.joined(separator: ", "))")
                                .font(.caption).foregroundStyle(.secondary)
                        }
                        .listRowInsets(EdgeInsets(top: 10, leading: 4, bottom: 10, trailing: 4))
                    }
                }
                .listStyle(.plain)
            }
            Button("Back", action: onBack).buttonStyle(.borderedProminent)
        }
        .frame(maxWidth: .infinity, alignment: .leading)
    }
}

/// App-shell settings (no core involvement); back returns home via `.cancelled`.
struct SettingsView: View {
    let onBack: () -> Void
    var body: some View {
        VStack(alignment: .leading, spacing: 16) {
            Text("This demo builds every screen from the core's `ScreenDescription`. Navigation "
                 + "containment is an app-shell statechart, deliberately outside the certification core.")
                .font(.callout).foregroundStyle(.secondary)
            Spacer()
            Button("Back", action: onBack).buttonStyle(.borderedProminent)
        }
        .frame(maxWidth: .infinity, alignment: .leading)
    }
}

/// Terminal state of a flow, with the step log so the run is legible in a screenshot.
struct ResultView: View {
    let symbol: String
    let tint: Color
    let message: String
    let log: [String]
    let onDone: () -> Void

    var body: some View {
        VStack(alignment: .leading, spacing: 16) {
            HStack(spacing: 10) {
                Image(systemName: symbol).font(.largeTitle).foregroundStyle(tint)
                Text(message).font(.headline)
            }
            if !log.isEmpty {
                Divider()
                ForEach(Array(log.enumerated()), id: \.offset) { _, line in
                    Text("• \(line)").font(.caption).foregroundStyle(.secondary)
                }
            }
            Spacer()
            Button("Back to flows", action: onDone).buttonStyle(.borderedProminent)
        }
        .frame(maxWidth: .infinity, alignment: .leading)
    }
}
