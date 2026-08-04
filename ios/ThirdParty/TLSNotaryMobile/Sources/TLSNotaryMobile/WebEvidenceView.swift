#if os(iOS)
import SwiftUI
import WebKit

@available(iOS 17.0, *)
public struct WebEvidenceView: View {
    @State private var browser = BrowserModel()
    @State private var status = "Open an HTTPS page, then create evidence."
    @State private var credential: EvidenceCredential?
    @State private var walletOffer: WalletCredentialOffer?
    private let client: TLSNotaryMobileClient

    public init(client: TLSNotaryMobileClient) {
        self.client = client
    }

    public var body: some View {
        NavigationStack {
            VStack(spacing: 0) {
                BrowserRepresentable(model: browser)
                Divider()
                VStack(alignment: .leading, spacing: 10) {
                    Text(status).font(.footnote)
                    Button("Create evidence credential") {
                        Task { await createEvidence() }
                    }
                    .buttonStyle(.borderedProminent)
                    .disabled(browser.url?.scheme != "https" || browser.isLoading)

                    if let credential {
                        ShareLink(
                            "Export credential",
                            item: credential.credential,
                            preview: SharePreview("TLSNotary Evidence Credential")
                        )
                        Button("Prepare EU wallet offer") {
                            Task { await prepareWalletOffer(credential) }
                        }
                        .buttonStyle(.bordered)
                    }
                    if let walletOffer {
                        Link("Open in wallet", destination: walletOffer.walletURI)
                    }
                }
                .padding()
            }
            .navigationTitle(browser.title ?? "TLSNotary")
        }
    }

    @MainActor
    private func createEvidence() async {
        guard let url = browser.url else { return }
        status = "Running the Rust TLSNotary prover…"
        do {
            let cookie = await browser.cookieHeader()
            let headers = cookie.map { ["Cookie": $0] } ?? [:]
            let result = try await client.notarize(url: url, headers: headers)
            credential = result
            status = result.verifyHolderSignature()
                ? "Notarized evidence credential created and locally verified."
                : "Credential created, but holder verification failed."
        } catch {
            status = error.localizedDescription
        }
    }

    @MainActor
    private func prepareWalletOffer(_ credential: EvidenceCredential) async {
        status = "Preparing OpenID4VCI wallet offer…"
        do {
            walletOffer = try await client.prepareWalletOffer(from: credential)
            status = "Wallet offer ready."
        } catch {
            status = error.localizedDescription
        }
    }
}

@available(iOS 17.0, *)
@Observable
@MainActor
final class BrowserModel {
    fileprivate weak var webView: WKWebView?
    var url: URL?
    var title: String?
    var isLoading = false

    func cookieHeader() async -> String? {
        guard let webView else { return nil }
        let cookies = await webView.configuration.websiteDataStore.httpCookieStore.allCookies()
        let values = cookies.map { "\($0.name)=\($0.value)" }
        return values.isEmpty ? nil : values.joined(separator: "; ")
    }
}

@available(iOS 17.0, *)
private struct BrowserRepresentable: UIViewRepresentable {
    let model: BrowserModel

    func makeCoordinator() -> Coordinator { Coordinator(model: model) }

    func makeUIView(context: Context) -> WKWebView {
        let view = WKWebView()
        view.navigationDelegate = context.coordinator
        model.webView = view
        view.load(URLRequest(url: URL(string: "https://example.com")!))
        return view
    }

    func updateUIView(_ view: WKWebView, context: Context) {}

    final class Coordinator: NSObject, WKNavigationDelegate {
        let model: BrowserModel
        init(model: BrowserModel) { self.model = model }

        func webView(_ webView: WKWebView, didStartProvisionalNavigation navigation: WKNavigation?) {
            model.isLoading = true
        }

        func webView(_ webView: WKWebView, didFinish navigation: WKNavigation?) {
            model.url = webView.url
            model.title = webView.title
            model.isLoading = false
        }

        func webView(
            _ webView: WKWebView,
            didFail navigation: WKNavigation?,
            withError error: any Error
        ) {
            model.isLoading = false
        }
    }
}
#endif
