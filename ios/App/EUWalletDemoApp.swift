import SwiftUI

/// A minimal SwiftUI harness that runs the real Rust wallet core on the iOS Simulator. It does not
/// add wallet behaviour — every trust, minimisation, key-binding and SCA decision happens in the
/// core over the FFI. The screens are the core's own `ScreenDescription`s, rendered by the shell's
/// `ScreenRenderer`. Pick a flow to drive it end to end against the core.
@main
struct EUWalletDemoApp: App {
    var body: some Scene {
        WindowGroup {
            ContentView()
        }
    }
}

struct ContentView: View {
    @StateObject private var model = WalletModel()

    var body: some View {
        NavigationStack {
            Group {
                switch model.phase {
                case .home:
                    HomeView(model: model)
                case .running:
                    ProgressView("Working with the core…")
                case .screen(let screen):
                    ScreenRenderer(screen: screen, onConsent: model.approve, onDecline: model.decline)
                case .done(let message):
                    ResultView(symbol: "checkmark.seal.fill", tint: .green, message: message,
                               log: model.log, onDone: model.reset)
                case .failed(let message):
                    ResultView(symbol: "xmark.octagon.fill", tint: .red, message: message,
                               log: model.log, onDone: model.reset)
                }
            }
            .navigationTitle("EUDI Wallet")
            .padding()
        }
        .onAppear {
            // UI-test / screenshot affordance: `-autostart presentation|payment` drives a flow on
            // launch so a screenshot captures the core-rendered screen. No effect in normal use.
            let args = ProcessInfo.processInfo.arguments
            if let i = args.firstIndex(of: "-autostart"), i + 1 < args.count {
                switch args[i + 1] {
                case "presentation": model.startPresentation()
                case "payment": model.startPayment()
                default: break
                }
            }
        }
    }
}

/// Flow picker. Each row drives one real core flow.
struct HomeView: View {
    @ObservedObject var model: WalletModel

    var body: some View {
        VStack(alignment: .leading, spacing: 20) {
            Text("Running the real Rust core on-device.")
                .font(.subheadline).foregroundStyle(.secondary)

            Button(action: model.startPresentation) {
                Label {
                    VStack(alignment: .leading) {
                        Text("Identity presentation").font(.headline)
                        Text("OpenID4VP · data-minimised consent").font(.caption)
                    }
                } icon: { Image(systemName: "person.text.rectangle") }
            }
            .buttonStyle(.bordered)

            Button(action: model.startPayment) {
                Label {
                    VStack(alignment: .leading) {
                        Text("Payment authorisation").font(.headline)
                        Text("PSD2/TS12 · strong customer authentication").font(.caption)
                    }
                } icon: { Image(systemName: "creditcard") }
            }
            .buttonStyle(.bordered)

            Spacer()
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
