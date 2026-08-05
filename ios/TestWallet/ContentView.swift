import SwiftUI

/// Minimal test-wallet UI. Not a real wallet: it exercises the cross-wallet PID Capture flow —
/// scan/enter an issuer, launch PIDCapture, and display the PID that comes back. Nothing is stored.
struct ContentView: View {
    @ObservedObject var model: TestWalletModel
    @State private var scanning = false

    var body: some View {
        NavigationStack {
            Group {
                switch model.phase {
                case .idle:
                    idle
                case .creating:
                    status("Creating a capture session…")
                case .awaiting:
                    status("Complete the capture in PID Capture,\nthen you'll be offered your PID here.")
                case .displaying:
                    display
                case let .failed(message):
                    failure(message)
                }
            }
            .padding()
            .navigationTitle("PID Test Wallet")
        }
    }

    private var idle: some View {
        VStack(spacing: 20) {
            Image(systemName: "wallet.pass").font(.system(size: 48)).foregroundStyle(.tint)
            Text("Get a PID by capture")
                .font(.title2).bold()
            Text("This test wallet asks the issuer for a PID, launches PID Capture to read your document, and displays the credential you're issued.")
                .font(.footnote).foregroundStyle(.secondary).multilineTextAlignment(.center)
            VStack(alignment: .leading, spacing: 6) {
                Text("Issuer").font(.caption).foregroundStyle(.secondary)
                TextField("https://issuer.advatar.systems", text: $model.issuerURL)
                    .textFieldStyle(.roundedBorder)
                    .textInputAutocapitalization(.never)
                    .autocorrectionDisabled()
                    .keyboardType(.URL)
            }
            Button {
                model.start()
            } label: {
                Label("Start capture", systemImage: "arrow.right.circle.fill").frame(maxWidth: .infinity)
            }
            .buttonStyle(.borderedProminent)

            if #available(iOS 16.0, *), QRScannerView.isAvailable {
                Button {
                    scanning = true
                } label: {
                    Label("Scan issuer QR", systemImage: "qrcode.viewfinder")
                }
            }
            Spacer()
        }
        .sheet(isPresented: $scanning) {
            if #available(iOS 16.0, *) {
                QRScannerView { payload in
                    scanning = false
                    // A wallet may scan a credential-offer QR directly — display it, no capture.
                    if let offer = URL(string: payload), offer.scheme == "openid-credential-offer" {
                        model.handleIncomingOffer(offer)
                        return
                    }
                    // Otherwise treat the QR as the issuer entry point: use only its origin
                    // (scheme://host[:port]) so any path/query in the code can't corrupt the API base.
                    if let comps = URLComponents(string: payload),
                        let scheme = comps.scheme, scheme.hasPrefix("http"),
                        let host = comps.host
                    {
                        var origin = "\(scheme)://\(host)"
                        if let port = comps.port { origin += ":\(port)" }
                        model.issuerURL = origin
                    }
                    model.start()
                }
                .ignoresSafeArea()
            }
        }
    }

    private func status(_ text: String) -> some View {
        VStack(spacing: 16) {
            ProgressView()
            Text(text).multilineTextAlignment(.center).foregroundStyle(.secondary)
        }
    }

    private var display: some View {
        VStack(spacing: 16) {
            Label("PID issued", systemImage: "checkmark.seal.fill")
                .font(.headline).foregroundStyle(.green)
            List(model.claims) { claim in
                HStack {
                    Text(claim.key).foregroundStyle(.secondary)
                    Spacer()
                    Text(claim.value).multilineTextAlignment(.trailing)
                }
                .font(.callout)
            }
            .listStyle(.insetGrouped)
            Text("Displayed only — this test wallet does not store the credential.")
                .font(.caption2).foregroundStyle(.secondary)
            Button("Start over") { model.reset() }
        }
    }

    private func failure(_ message: String) -> some View {
        VStack(spacing: 16) {
            Label("Something went wrong", systemImage: "xmark.octagon.fill")
                .font(.headline).foregroundStyle(.red)
            Text(message).font(.footnote).foregroundStyle(.secondary).multilineTextAlignment(.center)
            Button("Try again") { model.reset() }
        }
    }
}
