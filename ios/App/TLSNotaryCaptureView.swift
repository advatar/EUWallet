import SwiftUI
import WebKit

/// An embedded browser (address bar + `WKWebView`) shared by the "Add web evidence" screen. WebKit
/// invokes the delegate callbacks on the main thread, so `@Published` updates here are main-thread
/// safe without extra hops. Two roles:
///   • drives the native TLSNotary prover — exposes the current URL + the page's cookies so the
///     prover can replay the authenticated GET;
///   • as the web fallback, intercepts the credential-offer hand-back (`openid-credential-offer://`
///     redirect, or a `{offerUri}` post via the `wallet` message handler).
final class WebEvidenceBrowserModel: NSObject, ObservableObject, WKNavigationDelegate,
    WKScriptMessageHandler
{
    let webView: WKWebView
    @Published var addressText: String = ""
    @Published var currentURL: URL?
    @Published var isLoading = false
    @Published var canGoBack = false
    /// Set when the (fallback) capture page hands back a credential offer.
    @Published var deliveredOffer: String?

    override init() {
        let configuration = WKWebViewConfiguration()
        configuration.websiteDataStore = .default()
        configuration.userContentController = WKUserContentController()
        webView = WKWebView(frame: .zero, configuration: configuration)
        super.init()
        webView.configuration.userContentController.add(self, name: "wallet")
        webView.navigationDelegate = self
        webView.allowsBackForwardNavigationGestures = true
    }

    /// Load a typed address (prepends `https://` when the scheme is missing).
    func load(_ text: String) {
        var candidate = text.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !candidate.isEmpty else { return }
        if !candidate.contains("://") { candidate = "https://" + candidate }
        guard let url = URL(string: candidate), url.scheme?.hasPrefix("http") == true else { return }
        addressText = url.absoluteString
        webView.load(URLRequest(url: url))
    }

    func reload() { webView.reload() }
    func goBack() { webView.goBack() }

    /// The current page's cookies as a `Cookie:` header value (so the prover replays the session).
    func cookieHeader() async -> String? {
        let cookies = await webView.configuration.websiteDataStore.httpCookieStore.allCookies()
        let values = cookies.map { "\($0.name)=\($0.value)" }
        return values.isEmpty ? nil : values.joined(separator: "; ")
    }

    func webView(
        _: WKWebView,
        decidePolicyFor navigationAction: WKNavigationAction,
        decisionHandler: @escaping (WKNavigationActionPolicy) -> Void
    ) {
        if let url = navigationAction.request.url, isOfferURL(url) {
            deliver(url.absoluteString)
            decisionHandler(.cancel)
            return
        }
        decisionHandler(.allow)
    }

    func webView(_: WKWebView, didStartProvisionalNavigation _: WKNavigation!) { isLoading = true }
    func webView(_: WKWebView, didFinish _: WKNavigation!) { syncChrome() }
    func webView(_: WKWebView, didFail _: WKNavigation!, withError _: Error) { syncChrome() }
    func webView(_: WKWebView, didFailProvisionalNavigation _: WKNavigation!, withError _: Error) {
        syncChrome()
    }

    private func syncChrome() {
        isLoading = false
        canGoBack = webView.canGoBack
        currentURL = webView.url
        if let url = webView.url?.absoluteString { addressText = url }
    }

    func userContentController(_: WKUserContentController, didReceive message: WKScriptMessage) {
        if let uri = message.body as? String {
            deliver(uri)
        } else if let dict = message.body as? [String: Any], let uri = dict["offerUri"] as? String {
            deliver(uri)
        }
    }

    private func isOfferURL(_ url: URL) -> Bool {
        switch url.scheme?.lowercased() {
        case "openid-credential-offer", "haip", "openid-vc": return true
        default: return false
        }
    }

    private func deliver(_ value: String) {
        let trimmed = value.trimmingCharacters(in: .whitespacesAndNewlines)
        guard deliveredOffer == nil, !trimmed.isEmpty else { return }
        deliveredOffer = trimmed
    }

    deinit {
        webView.configuration.userContentController.removeScriptMessageHandler(forName: "wallet")
    }
}

/// Thin SwiftUI wrapper hosting the model's `WKWebView`.
struct WebViewHost: UIViewRepresentable {
    let webView: WKWebView
    func makeUIView(context _: Context) -> WKWebView { webView }
    func updateUIView(_: WKWebView, context _: Context) {}
}
