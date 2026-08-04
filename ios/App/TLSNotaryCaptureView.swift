import SwiftUI
import WebKit

/// Embedded browser that hosts the TLSNotary capture web app so the user can notarise a web fact
/// **in the wallet**. The wallet does not run the TLSNotary prover itself — it hosts the capture page
/// (which runs the browser prover, talks to the notary, and posts the artifact to VCIssuer's
/// `/evidence-offers/tlsnotary`). When that page has an OpenID4VCI credential-offer it hands it back,
/// either by:
///   • redirecting to an `openid-credential-offer://…` deep link (intercepted here), or
///   • posting `{ offerUri }` (or the bare URI string) via `window.webkit.messageHandlers.wallet`.
/// Both routes forward the offer to the wallet's normal issuance flow.
struct TLSNotaryCaptureView: UIViewRepresentable {
    let url: URL
    let onOffer: (String) -> Void

    func makeCoordinator() -> Coordinator { Coordinator(onOffer: onOffer) }

    func makeUIView(context: Context) -> WKWebView {
        let configuration = WKWebViewConfiguration()
        configuration.websiteDataStore = .default()
        configuration.userContentController.add(context.coordinator, name: "wallet")
        let webView = WKWebView(frame: .zero, configuration: configuration)
        webView.navigationDelegate = context.coordinator
        webView.allowsBackForwardNavigationGestures = true
        webView.load(URLRequest(url: url))
        return webView
    }

    func updateUIView(_: WKWebView, context _: Context) {}

    static func dismantleUIView(_ webView: WKWebView, coordinator _: Coordinator) {
        webView.configuration.userContentController.removeScriptMessageHandler(forName: "wallet")
        webView.stopLoading()
    }

    final class Coordinator: NSObject, WKNavigationDelegate, WKScriptMessageHandler {
        private let onOffer: (String) -> Void
        private var delivered = false

        init(onOffer: @escaping (String) -> Void) { self.onOffer = onOffer }

        /// Intercept the credential-offer hand-back deep link (the standard OpenID4VCI scheme).
        func webView(
            _: WKWebView,
            decidePolicyFor navigationAction: WKNavigationAction,
            decisionHandler: @escaping (WKNavigationActionPolicy) -> Void
        ) {
            if let url = navigationAction.request.url, Self.isOfferURL(url) {
                deliver(url.absoluteString)
                decisionHandler(.cancel)
                return
            }
            decisionHandler(.allow)
        }

        /// Or the page posts the offer URI directly through the `wallet` message handler.
        func userContentController(
            _: WKUserContentController, didReceive message: WKScriptMessage
        ) {
            if let uri = message.body as? String {
                deliver(uri)
            } else if let dict = message.body as? [String: Any],
                let uri = dict["offerUri"] as? String
            {
                deliver(uri)
            }
        }

        private static func isOfferURL(_ url: URL) -> Bool {
            switch url.scheme?.lowercased() {
            case "openid-credential-offer", "haip", "openid-vc": return true
            default: return false
            }
        }

        private func deliver(_ value: String) {
            let trimmed = value.trimmingCharacters(in: .whitespacesAndNewlines)
            guard !delivered, !trimmed.isEmpty else { return }
            delivered = true
            DispatchQueue.main.async { self.onOffer(trimmed) }
        }
    }
}
