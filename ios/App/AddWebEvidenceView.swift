import SwiftUI

#if canImport(TLSNotaryMobile)
    import TLSNotaryMobile
#endif

/// "Add web evidence" — opens straight into an embedded browser with an address bar (type a URL and
/// browse). When the native TLSNotary prover is linked (via project.local.yml → ../tlsn
/// `packages/TLSNotaryMobile`), "Create web evidence" notarises the current authenticated page with
/// the Rust prover, gets an OpenID4VCI offer from VCIssuer, and hands its `openid-credential-offer://`
/// deep link to the wallet's normal issuance flow. Without the prover linked (CI/base build) it is a
/// plain browser pointed at the hosted capture web app, whose page performs the same hand-back.
struct AddWebEvidenceView: View {
    @ObservedObject var model: WalletModel
    @Environment(\.dismiss) private var dismiss
    @StateObject private var browser = WebEvidenceBrowserModel()

    @AppStorage("tlsn.issuerURL") private var issuerURL = "https://vcissuer.advatar.systems"
    @AppStorage("tlsn.notaryURL") private var notaryURL = "https://notary.euwallet.advatar.systems"
    @AppStorage("tlsn.notaryKeyB64u") private var notaryKeyB64u = ""
    @AppStorage("tlsn.captureURL") private var captureURL = "https://euwallet.advatar.systems/tlsn/capture"

    @State private var address = ""
    @State private var status = ""
    @State private var busy = false
    @State private var didStart = false

    private var initialURL: String {
        #if canImport(TLSNotaryMobile)
            return "https://example.com/"
        #else
            return captureURL
        #endif
    }

    var body: some View {
        NavigationStack {
            VStack(spacing: 0) {
                addressBar
                WebViewHost(webView: browser.webView)
                footer
            }
            .navigationTitle("Web evidence")
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .cancellationAction) { Button("Done") { dismiss() } }
            }
            .task {
                if !didStart {
                    didStart = true
                    address = initialURL
                    browser.load(initialURL)
                }
            }
            .onChange(of: browser.currentURL) { _, url in
                if let url { address = url.absoluteString }
            }
            .onChange(of: browser.deliveredOffer) { _, offer in
                if let offer {
                    model.handleScanned(offer)
                    dismiss()
                }
            }
        }
    }

    private var addressBar: some View {
        HStack(spacing: 8) {
            if browser.canGoBack {
                Button { browser.goBack() } label: { Image(systemName: "chevron.left") }
            }
            TextField("Enter a URL", text: $address)
                .textInputAutocapitalization(.never)
                .autocorrectionDisabled()
                .keyboardType(.URL)
                .submitLabel(.go)
                .onSubmit { browser.load(address) }
                .textFieldStyle(.roundedBorder)
            Button { browser.load(address) } label: {
                Image(systemName: browser.isLoading ? "xmark" : "arrow.clockwise")
            }
        }
        .padding(8)
    }

    @ViewBuilder private var footer: some View {
        VStack(alignment: .leading, spacing: 8) {
            if !status.isEmpty {
                Text(status).font(.footnote).foregroundStyle(.secondary)
            }
            #if canImport(TLSNotaryMobile)
                Button {
                    Task { await notarizeAndOffer() }
                } label: {
                    Label(busy ? "Working…" : "Create web evidence", systemImage: "checkmark.shield")
                        .frame(maxWidth: .infinity)
                }
                .buttonStyle(.borderedProminent)
                .disabled(busy || browser.currentURL?.scheme != "https")
            #endif
        }
        .padding()
    }

    #if canImport(TLSNotaryMobile)
        private func notarizeAndOffer() async {
            guard
                let url = browser.currentURL,
                let notary = URL(string: notaryURL),
                let issuer = URL(string: issuerURL)
            else { return }
            busy = true
            status = "Running the TLSNotary prover on this page…"
            defer { busy = false }
            do {
                let holder: any HolderSigningKey =
                    (try? SecureEnclaveHolderKey()) ?? SoftwareHolderKey()
                let client = try TLSNotaryMobileClient(
                    notary: NotaryConfiguration(
                        baseURL: notary,
                        trustedPublicKeyX963: Self.decodeBase64URL(notaryKeyB64u) ?? Data()),
                    issuer: IssuerConfiguration(baseURL: issuer),
                    holderKey: holder)
                let cookie = await browser.cookieHeader()
                let headers = cookie.map { ["Cookie": $0] } ?? [:]
                let credential = try await client.notarize(url: url, headers: headers)
                status = "Preparing wallet offer…"
                let offer = try await client.prepareWalletOffer(from: credential)
                model.handleScanned(offer.walletURI.absoluteString)
                dismiss()
            } catch {
                status = error.localizedDescription
            }
        }

        private static func decodeBase64URL(_ string: String) -> Data? {
            guard !string.isEmpty else { return nil }
            var s = string.replacingOccurrences(of: "-", with: "+")
                .replacingOccurrences(of: "_", with: "/")
            while s.count % 4 != 0 { s += "=" }
            return Data(base64Encoded: s)
        }
    #endif
}
