import SwiftUI

/// Discoverable entry point for TLSNotary "web evidence" credentials.
///
/// TLSNotary attests a fact from a real TLS (HTTPS) session — a notary co-signs the transcript so a
/// verifier can trust a web fact without the origin server participating. The user captures the
/// evidence **inside the wallet**: this screen opens the TLSNotary capture web app in an embedded
/// browser ([`TLSNotaryCaptureView`]); when the notarisation completes, the capture page hands back
/// an OpenID4VCI credential-offer, which flows through the same issuance path as any other offer
/// (`handleScanned` → `startLiveIssuance`). A paste field remains as a fallback for a pre-made offer.
struct AddWebEvidenceView: View {
    @ObservedObject var model: WalletModel
    @Environment(\.dismiss) private var dismiss

    /// The TLSNotary capture web app URL (editable; persisted). Points at the page that runs the
    /// browser prover and posts the artifact to VCIssuer's `/evidence-offers/tlsnotary`.
    @AppStorage("tlsn.captureURL") private var captureURLString =
        "https://issuer.advatar.systems/tlsn/capture"
    @State private var capturing = false
    @State private var pasted = ""

    private var captureURL: URL? {
        let trimmed = captureURLString.trimmingCharacters(in: .whitespaces)
        guard let url = URL(string: trimmed), url.scheme?.hasPrefix("http") == true else {
            return nil
        }
        return url
    }

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
                }

                Section {
                    Button {
                        capturing = true
                    } label: {
                        Label("Capture web evidence", systemImage: "safari")
                    }
                    .disabled(captureURL == nil)
                } header: {
                    Text("Capture in the wallet")
                } footer: {
                    Text("Opens a secure in-app browser to notarise the web session. When it "
                        + "finishes you will review the credential before anything is stored.")
                }

                Section {
                    TextField("Capture app URL", text: $captureURLString)
                        .textInputAutocapitalization(.never)
                        .autocorrectionDisabled()
                        .font(.callout.monospaced())
                } header: {
                    Text("Capture app")
                } footer: {
                    Text("The TLSNotary capture web app that runs the browser prover and returns an "
                        + "openid-credential-offer link.")
                }

                Section {
                    TextField("Paste an offer link", text: $pasted, axis: .vertical)
                        .textInputAutocapitalization(.never)
                        .autocorrectionDisabled()
                    Button("Add from link") {
                        model.handleScanned(pasted.trimmingCharacters(in: .whitespacesAndNewlines))
                    }
                    .disabled(pasted.trimmingCharacters(in: .whitespaces).isEmpty)
                    if let scan = model.lastScan {
                        Text(scan).font(.callout)
                    }
                } header: {
                    Text("Or paste an offer")
                } footer: {
                    Text("If you already have an openid-credential-offer link from a notarised "
                        + "session, paste it here instead.")
                }
            }
            .navigationTitle("Add web evidence")
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .cancellationAction) { Button("Done") { dismiss() } }
            }
            .navigationDestination(isPresented: $capturing) {
                if let url = captureURL {
                    TLSNotaryCaptureView(url: url) { offerUri in
                        capturing = false
                        model.handleScanned(offerUri)
                        dismiss()
                    }
                    .ignoresSafeArea(edges: .bottom)
                    .navigationTitle("Capture web evidence")
                    .navigationBarTitleDisplayMode(.inline)
                }
            }
        }
    }
}
