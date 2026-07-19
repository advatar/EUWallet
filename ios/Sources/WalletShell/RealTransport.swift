import Foundation

/// Real network transport for production flows. Replaces `StubHttpClient`: performs genuine
/// HTTPS requests (TLS handled by the OS) to issuer/verifier endpoints. The wallet's protocol
/// decisions still happen in the Rust core; this only moves bytes over the wire.
public final class URLSessionHttpClient: HttpClient {
    private let session: URLSession

    public init(timeout: TimeInterval = 30) {
        let cfg = URLSessionConfiguration.ephemeral
        cfg.timeoutIntervalForRequest = timeout
        cfg.waitsForConnectivity = true
        cfg.httpShouldSetCookies = false // a wallet carries its own auth; no ambient cookies
        self.session = URLSession(configuration: cfg)
    }

    /// POST `body` to `url`. Content-Type is inferred from the body shape (JSON vs. the OAuth
    /// default of form-encoding), which matches the OpenID4VCI/VP endpoints the core drives.
    public func post(url: String, body: Data) async -> (UInt16, Data) {
        guard let u = URL(string: url), u.scheme == "https" || u.scheme == "http" else {
            return (0, Data())
        }
        var req = URLRequest(url: u)
        req.httpMethod = "POST"
        req.httpBody = body
        req.setValue(Self.contentType(for: body), forHTTPHeaderField: "Content-Type")
        req.setValue("application/json", forHTTPHeaderField: "Accept")
        return await perform(req)
    }

    /// GET `url` (issuer/verifier metadata, request objects fetched by reference, JWKS, …).
    public func get(url: String, headers: [String: String] = [:]) async -> (UInt16, Data) {
        guard let u = URL(string: url), u.scheme == "https" || u.scheme == "http" else {
            return (0, Data())
        }
        var req = URLRequest(url: u)
        req.httpMethod = "GET"
        headers.forEach { req.setValue($0.value, forHTTPHeaderField: $0.key) }
        return await perform(req)
    }

    /// Fetch an OpenID4VCI issuer's metadata (`/.well-known/openid-credential-issuer`).
    public func fetchIssuerMetadata(issuer: String) async -> (UInt16, Data) {
        let base = issuer.hasSuffix("/") ? String(issuer.dropLast()) : issuer
        return await get(url: base + "/.well-known/openid-credential-issuer")
    }

    private func perform(_ req: URLRequest) async -> (UInt16, Data) {
        do {
            let (data, resp) = try await session.data(for: req)
            let code = (resp as? HTTPURLResponse)?.statusCode ?? 0
            return (UInt16(clamping: code), data)
        } catch {
            // Surface the transport error as a zero status + its description (never a fake 200).
            return (0, Data(String(describing: error).utf8))
        }
    }

    private static func contentType(for body: Data) -> String {
        if let first = body.first, first == UInt8(ascii: "{") || first == UInt8(ascii: "[") {
            return "application/json"
        }
        return "application/x-www-form-urlencoded"
    }
}

/// A scanned/opened QR payload or deep link, classified into the wallet action it triggers.
/// Pure parsing — no I/O — so it is unit-testable on the host.
public enum ScannedRequest: Equatable {
    /// OpenID4VCI credential offer carried inline (`credential_offer=<json>`).
    case credentialOffer(issuer: String, configurationIds: [String])
    /// OpenID4VCI credential offer carried by reference (`credential_offer_uri=<url>`).
    case credentialOfferByReference(uri: String)
    /// OpenID4VP presentation request (inline or by `request_uri`).
    case presentation(requestUri: String?, clientId: String?)
    /// Not a recognised wallet link.
    case unknown(String)

    /// Classify a scanned string. Recognises the `openid-credential-offer://` and
    /// `openid4vp://` / `haip://` / `eudi-openid4vp://` schemes, plus the query parameters that
    /// identify each flow regardless of scheme.
    public static func parse(_ text: String) -> ScannedRequest {
        let trimmed = text.trimmingCharacters(in: .whitespacesAndNewlines)
        guard let comps = URLComponents(string: trimmed) else { return .unknown(trimmed) }
        let scheme = (comps.scheme ?? "").lowercased()
        let items = comps.queryItems ?? []
        func value(_ name: String) -> String? {
            items.first { $0.name == name }?.value
        }

        // --- OpenID4VCI credential offer ---
        let looksLikeOffer = scheme == "openid-credential-offer"
            || value("credential_offer") != nil
            || value("credential_offer_uri") != nil
        if looksLikeOffer {
            if let byRef = value("credential_offer_uri"), !byRef.isEmpty {
                return .credentialOfferByReference(uri: byRef)
            }
            if let json = value("credential_offer"),
               let data = json.data(using: .utf8),
               let obj = try? JSONSerialization.jsonObject(with: data) as? [String: Any],
               let issuer = obj["credential_issuer"] as? String {
                let ids = (obj["credential_configuration_ids"] as? [String]) ?? []
                return .credentialOffer(issuer: issuer, configurationIds: ids)
            }
        }

        // --- OpenID4VP presentation request ---
        let looksLikePresentation = scheme.hasPrefix("openid4vp")
            || scheme == "haip"
            || scheme == "eudi-openid4vp"
            || scheme == "mdoc-openid4vp"
            || value("request_uri") != nil
            || value("presentation_definition") != nil
            || value("presentation_definition_uri") != nil
            || value("dcql_query") != nil
        if looksLikePresentation {
            return .presentation(requestUri: value("request_uri"), clientId: value("client_id"))
        }

        return .unknown(trimmed)
    }
}
