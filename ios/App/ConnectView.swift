import SwiftUI

/// The real "connect" entry point: scan (or paste) a credential-offer / verifier-request link and
/// see how the wallet classifies it, probe the LIVE EUDI reference issuer over real HTTPS, and
/// confirm the device holds a real signing key. This is the foundation the issuance/presentation
/// flows against real endpoints (issuer.eudiw.dev / verifier.eudiw.dev) build on.
struct ConnectView: View {
    @ObservedObject var model: WalletModel
    @Environment(\.dismiss) private var dismiss
    @State private var pasted = ""
    @State private var scanning = false

    var body: some View {
        NavigationStack {
            Form {
                Section("Scan") {
                    if #available(iOS 16.0, *), QRScannerView.isAvailable {
                        Button { scanning = true } label: {
                            Label("Scan a QR code", systemImage: "qrcode.viewfinder")
                        }
                    } else {
                        Label("The camera isn't available. You can enter the link below.",
                              systemImage: "camera.metering.unknown")
                            .font(.caption).foregroundStyle(.secondary)
                    }
                    TextField("Paste a link",
                              text: $pasted, axis: .vertical)
                        .textInputAutocapitalization(.never)
                        .autocorrectionDisabled()
                    Button("Continue with link") { model.handleScanned(pasted) }
                        .disabled(pasted.trimmingCharacters(in: .whitespaces).isEmpty)
                    if let scan = model.lastScan {
                        Text(scan).font(.callout).foregroundStyle(.primary)
                    }
                }

#if DEBUG
                Section {
                    Button { model.probeReferenceIssuer() } label: {
                        Label("Probe issuer.eudiw.dev", systemImage: "antenna.radiowaves.left.and.right")
                    }
                    if let result = model.probeResult {
                        Text(result).font(.caption.monospaced()).foregroundStyle(.secondary)
                    }
                } header: {
                    Text("Live reference issuer")
                } footer: {
                    Text("Makes a real HTTPS request to the EU reference issuer's metadata endpoint "
                         + "and lists the credential types it offers.")
                }

                Section("This device") {
                    Text("Signing key: \(model.deviceKeyPreview())")
                        .font(.caption.monospaced()).foregroundStyle(.secondary)
                    Text("Secure Enclave on device; a keychain key stands in on the Simulator.")
                        .font(.caption2).foregroundStyle(.tertiary)
                }
#endif
            }
            .navigationTitle("Scan a QR code")
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .cancellationAction) { Button("Done") { dismiss() } }
            }
            .sheet(isPresented: $scanning) {
                if #available(iOS 16.0, *) {
                    QRScannerView { payload in
                        scanning = false
                        model.handleScanned(payload)
                    }
                    .ignoresSafeArea()
                }
            }
        }
    }
}
