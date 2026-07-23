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
            ZStack {
                ConsumerDesign.paper.ignoresSafeArea()
                container
                    .frame(maxWidth: .infinity, maxHeight: .infinity)
            }
            .consumerPage()
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
            WalletHomeView(
                model: model,
                onPresent: { nav.send(.startPresentation); model.startPresentation() },
                onPay: { nav.send(.startPresentation); model.startPayment() },
                onPresentMdoc: { nav.send(.startPresentation); model.startMdocPresentation() },
                onOpenHistory: { model.reloadHistory(); nav.send(.openHistory) },
                onOpenCatalogue: { nav.send(.openCatalogue) },
                onOpenSettings: { nav.send(.openSettings) })
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
        case "home": nav.send(.finishedOnboarding)
        case "add", "issue":
            // Exercise the real OpenID4VCI issuance and land on a populated home.
            nav.send(.finishedOnboarding)
            model.addCredential(.pid)
        case "add-mdl":
            nav.send(.finishedOnboarding)
            model.addCredential(.mdl)
        case "add-both":
            nav.send(.finishedOnboarding)
            model.seedBothForDemo()
        case "add-all":
            nav.send(.finishedOnboarding)
            model.seedAllForDemo()
        case "add-ids":
            nav.send(.finishedOnboarding)
            model.seedIdCardsForDemo()
        case "probe-issuer":
            // Open the real Connect sheet and hit the live EUDI reference issuer over HTTPS.
            nav.send(.finishedOnboarding)
            model.showConnectSheet = true
            model.probeReferenceIssuer()
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
        VStack(alignment: .leading, spacing: 18) {
            Spacer()
            ConsumerStatusOrb(systemImage: "wallet.pass.fill")
            Text("Your ID, safely on your phone")
                .font(.largeTitle.bold())
                .accessibilityAddTraits(.isHeader)
            Text("Add trusted documents, use them when asked, and always see what you are sharing before you approve.")
                .font(.title3).foregroundStyle(ConsumerDesign.mutedInk)
            VStack(alignment: .leading, spacing: 0) {
                Label("You choose what to share", systemImage: "checkmark.shield")
                Divider().padding(.vertical, 12)
                Label("Protected on this device", systemImage: "lock")
                Divider().padding(.vertical, 12)
                Label("Simple activity history", systemImage: "clock.arrow.circlepath")
            }
            .consumerSurface()
            Spacer()
            Button("Set up my wallet", action: onContinue)
                .buttonStyle(ConsumerPrimaryButtonStyle())
        }
        .padding(20)
        .frame(maxWidth: .infinity, alignment: .leading)
    }
}

/// Flow picker. Each row drives one real core flow or opens a P1 wallet screen.
/// The container the navigation machine presents for an in-flight flow.
struct PresentingContainer: View {
    @ObservedObject var model: WalletModel
    let onFinish: () -> Void

    var body: some View {
        switch model.phase {
        case .running, .home:
            VStack(spacing: 20) {
                ConsumerStatusOrb(systemImage: "checkmark.shield.fill")
                Text("Checking the request")
                    .font(.largeTitle.bold())
                    .multilineTextAlignment(.center)
                Text("Making sure it is safe and showing only what is needed.")
                    .font(.title3)
                    .foregroundStyle(ConsumerDesign.mutedInk)
                    .multilineTextAlignment(.center)
                ProgressView().controlSize(.large).accessibilityLabel("Checking the request")
            }
            .padding(24)
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
    @State private var entryToRemove: UInt64?
    @State private var confirmClearAll = false

    var body: some View {
        VStack(alignment: .leading, spacing: 10) {
            if let r = model.report {
                Text("\(r.total) activities · \(r.presentations) information shares · \(r.payments) payments")
                    .font(.caption).foregroundStyle(.secondary)
                    .accessibilityLabel("Activity report")
            }
            if model.history.isEmpty {
                Spacer()
                VStack(spacing: 10) {
                    Image(systemName: "clock").font(.largeTitle).foregroundStyle(.secondary)
                    Text("No activity yet").font(.headline)
                    Text("Actions such as adding or sharing a document will appear here.")
                        .font(.callout).foregroundStyle(.secondary).multilineTextAlignment(.center)
                }
                .frame(maxWidth: .infinity)
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
                                        entryToRemove = item.seq
                                    } label: {
                                        Label("Remove", systemImage: "trash")
                                    }
                                }
                            }
                    }
                }
                .listStyle(.plain)
            }
            HStack(spacing: 12) {
                Button("Done", action: onBack).buttonStyle(.borderedProminent)
                Spacer()
                Button {
                    model.exportPreview = model.makeExport()
                } label: {
                    Label("Save copy", systemImage: "square.and.arrow.up")
                }
                Button(role: .destructive) {
                    confirmClearAll = true
                } label: {
                    Label("Clear all", systemImage: "trash.slash")
                }
            }
            .font(.subheadline)
        }
        .frame(maxWidth: .infinity, alignment: .leading)
        .sheet(item: $model.exportPreview) { preview in
            ExportSheet(preview: preview)
        }
        .confirmationDialog(
            "Remove this activity?",
            isPresented: Binding(get: { entryToRemove != nil }, set: { if !$0 { entryToRemove = nil } }),
            titleVisibility: .visible
        ) {
            Button("Remove activity", role: .destructive) {
                if let seq = entryToRemove { model.redact(seq: seq) }
                entryToRemove = nil
            }
            Button("Cancel", role: .cancel) { entryToRemove = nil }
        } message: {
            Text("The details will be deleted from this phone.")
        }
        .confirmationDialog("Clear all activity?", isPresented: $confirmClearAll, titleVisibility: .visible) {
            Button("Clear all activity", role: .destructive) { model.wipeLog() }
            Button("Cancel", role: .cancel) {}
        } message: {
            Text("This deletes all activity details from this phone and cannot be undone.")
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
                    Text("Removed activity").font(.headline).foregroundStyle(.secondary)
                    Text("Details deleted")
                        .font(.caption).foregroundStyle(.tertiary)
                } else {
                    Text(item.counterparty).font(.headline)
                    if let p = item.payment {
                        Text(String(format: "%.2f %@", Double(p.amountMinor) / 100.0, p.currency))
                            .font(.subheadline)
                    } else if !item.claimPaths.isEmpty {
                        Text("Shared: \(item.claimPaths.map(ConsumerCopy.claimName).joined(separator: ", "))")
                            .font(.subheadline)
                    }
                    Text("\(ConsumerCopy.activityName(item.kind)) · \(ConsumerCopy.outcomeName(item.outcome))")
                        .font(.caption).foregroundStyle(.secondary)
#if DEBUG
                    Text("consent \(item.consentHash.prefix(12))…")
                        .font(.caption2).foregroundStyle(.tertiary)
#endif
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
            Text("Activity copy").font(.title2.bold())
            Label(
                preview.verifies ? "Copy verified" : "Copy could not be verified",
                systemImage: preview.verifies ? "checkmark.seal.fill" : "xmark.octagon.fill")
                .foregroundStyle(preview.verifies ? .green : .red)
            Label(
                preview.tamperDetected
                    ? "Tampered copy detected and rejected" : "Tamper check inconclusive",
                systemImage: preview.tamperDetected ? "shield.checkered" : "questionmark.diamond")
                .foregroundStyle(preview.tamperDetected ? .green : .orange)
#if DEBUG
            Text("SHA-256 \(integrityHash.prefix(24))…")
                .font(.caption.monospaced()).foregroundStyle(.secondary)
            Divider()
            ScrollView {
                Text(preview.json)
                    .font(.caption2.monospaced())
                    .frame(maxWidth: .infinity, alignment: .leading)
            }
#else
            Text("This copy is protected so later changes can be detected.")
                .font(.callout).foregroundStyle(.secondary)
#endif
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
            Label("Protected on this device", systemImage: "lock.shield")
                .font(.headline)
            Text("You will always see what an organisation is requesting before anything is shared.")
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
#if DEBUG
            if !log.isEmpty {
                Divider()
                ForEach(Array(log.enumerated()), id: \.offset) { _, line in
                    Text("• \(line)").font(.caption).foregroundStyle(.secondary)
                }
            }
#endif
            Spacer()
            Button("Back to wallet", action: onDone).buttonStyle(.borderedProminent)
        }
        .frame(maxWidth: .infinity, alignment: .leading)
    }
}
