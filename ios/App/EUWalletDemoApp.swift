import SwiftUI

/// A minimal SwiftUI harness that runs the real Rust wallet core on the iOS Simulator.
///
/// Two orthogonal state owners (plan §8.10):
///  - `WalletModel` surfaces the core's screen *content* (`ScreenDescription` over the FFI).
///  - `NavigationMachine` owns app-shell *containment/routing* (onboarding / home / presenting /
///    settings). It holds no security state; the shell derives its milestone events from renders.
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
            case .screen: nav.send(.startPresentation)   // the core produced a flow screen
            case .done, .failed: nav.send(.presentationCompleted)  // the flow ended
            default: break
            }
        }
        .onAppear(perform: handleLaunchArguments)
    }

    /// The app-shell container the navigation machine currently presents. The core's screens are
    /// rendered INSIDE the `.presenting` container — content and containment stay orthogonal.
    @ViewBuilder private var container: some View {
        switch nav.state {
        case .onboarding:
            OnboardingView { nav.send(.finishedOnboarding) }
        case .home:
            HomeView(
                startPresentation: { nav.send(.startPresentation); model.startPresentation() },
                startPayment: { nav.send(.startPresentation); model.startPayment() },
                openHistory: { nav.send(.openHistory) },
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
            HistoryView(items: model.history) { nav.send(.cancelled) }
        case .issuing, .scanning:
            // Not wired to UI in this demo; the machine supports them for completeness.
            ProgressView()
        }
    }

    /// UI-test / screenshot affordance: `-autostart presentation|payment` skips onboarding and
    /// drives a flow on launch so a screenshot captures the core-rendered screen.
    private func handleLaunchArguments() {
        let args = ProcessInfo.processInfo.arguments
        guard let i = args.firstIndex(of: "-autostart"), i + 1 < args.count else { return }
        switch args[i + 1] {
        case "presentation": nav.send(.startPresentation); model.startPresentation()
        case "payment": nav.send(.startPresentation); model.startPayment()
        case "history":
            model.seedHistoryForDemo()
            nav.send(.finishedOnboarding) // onboarding → home
            nav.send(.openHistory) // home → history

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

/// Flow picker. Each row drives one real core flow.
struct HomeView: View {
    let startPresentation: () -> Void
    let startPayment: () -> Void
    let openHistory: () -> Void
    let openSettings: () -> Void
    let historyCount: Int

    var body: some View {
        VStack(alignment: .leading, spacing: 20) {
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
                        Text("\(historyCount) recorded · paths + consent hash, never values")
                            .font(.caption)
                    }
                } icon: { Image(systemName: "list.bullet.rectangle") }
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

/// The transaction-history screen (TS06). Renders the wallet's privacy-preserving audit log:
/// counterparty, what was shared (claim PATHS or payment summary), outcome, and the consent hash
/// that commits to it — never the underlying claim values.
struct HistoryView: View {
    let items: [HistoryItem]
    let onBack: () -> Void

    var body: some View {
        VStack(alignment: .leading, spacing: 12) {
            if items.isEmpty {
                Text("No transactions yet. Run a presentation or payment first.")
                    .font(.callout).foregroundStyle(.secondary)
            } else {
                ScrollView {
                    VStack(alignment: .leading, spacing: 14) {
                        ForEach(Array(items.enumerated()), id: \.offset) { _, item in
                            HistoryRow(item: item)
                        }
                    }
                }
            }
            Spacer()
            Button("Back", action: onBack).buttonStyle(.borderedProminent)
        }
        .frame(maxWidth: .infinity, alignment: .leading)
    }
}

struct HistoryRow: View {
    let item: HistoryItem

    private var icon: String {
        switch item.kind {
        case "payment": return "creditcard"
        case "issuance": return "plus.rectangle.on.folder"
        default: return "person.text.rectangle"
        }
    }

    var body: some View {
        HStack(alignment: .top, spacing: 12) {
            Image(systemName: icon).font(.title3).foregroundStyle(.tint).frame(width: 28)
            VStack(alignment: .leading, spacing: 3) {
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
        .accessibilityElement(children: .combine)
    }
}

/// The container the navigation machine presents for an in-flight flow. It renders the CORE's
/// screens (`ScreenRenderer`) and its terminal result — nothing protocol-specific lives here.
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
