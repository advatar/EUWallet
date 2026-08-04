import SwiftUI

/// Discoverable entry point for TLSNotary "web evidence" credentials.
///
/// TLSNotary attests a fact from a real TLS (HTTPS) session — a notary co-signs the transcript so a
/// verifier can trust a web fact without the origin server participating. The wallet cannot originate
/// a notary attestation itself (that happens in a browser/notary session); this screen explains the
/// credential and lets the user bring in the resulting **credential-offer** (scan the QR or paste the
/// link), which flows through the same OpenID4VCI issuance path as any other offer. The wallet's
/// TLSNotary-specific policy check (see `IssuerClient`) then runs during redemption.
struct AddWebEvidenceView: View {
    @ObservedObject var model: WalletModel
    @Environment(\.dismiss) private var dismiss
    @State private var pasted = ""
    @State private var scanning = false

    var body: some View {
        NavigationStack {
            Form {
                Section {
                    Label {
                        VStack(alignment: .leading, spacing: 4) {
                            Text("TLSNotary web evidence").font(.headline)
                            Text("A verifiable fact captured from a real HTTPS session and co-signed "
                                + "by a notary — provable to others without the website taking part.")
                                .font(.subheadline).foregroundStyle(.secondary)
                        }
                    } icon: {
                        Image(systemName: "checkmark.shield").foregroundStyle(.tint)
                    }
                } footer: {
                    Text("Create the evidence in the notarised web session, then bring the offer here.")
                }

                Section {
                    if #available(iOS 16.0, *), QRScannerView.isAvailable {
                        Button { scanning = true } label: {
                            Label("Scan the evidence offer", systemImage: "qrcode.viewfinder")
                        }
                    }
                    TextField("Paste the offer link", text: $pasted, axis: .vertical)
                        .textInputAutocapitalization(.never)
                        .autocorrectionDisabled()
                    Button("Add web evidence") {
                        model.handleScanned(pasted.trimmingCharacters(in: .whitespacesAndNewlines))
                    }
                    .disabled(pasted.trimmingCharacters(in: .whitespaces).isEmpty)
                    if let scan = model.lastScan {
                        Text(scan).font(.callout)
                    }
                } header: {
                    Text("Add the credential")
                } footer: {
                    Text("Scan or paste the openid-credential-offer link from the notarised session. "
                        + "You will review it before anything is stored.")
                }
            }
            .navigationTitle("Add web evidence")
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
