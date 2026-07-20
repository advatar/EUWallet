import Foundation
import Darwin

public enum ResolvedIPAddress: Equatable, Sendable {
    case ipv4([UInt8])
    case ipv6([UInt8])
}

public protocol HostAddressResolving: Sendable {
    func addresses(for host: String) async throws -> [ResolvedIPAddress]
}

public struct SystemHostAddressResolver: HostAddressResolving {
    public init() {}

    public func addresses(for host: String) async throws -> [ResolvedIPAddress] {
        try await Task.detached {
            var hints = addrinfo()
            hints.ai_flags = AI_ADDRCONFIG
            hints.ai_family = AF_UNSPEC
            hints.ai_socktype = SOCK_STREAM
            hints.ai_protocol = IPPROTO_TCP

            var result: UnsafeMutablePointer<addrinfo>?
            let status = host.withCString { getaddrinfo($0, nil, &hints, &result) }
            guard status == 0, let first = result else {
                throw HttpClientError.transport("DNS resolution failed for \(host)")
            }
            defer { freeaddrinfo(first) }

            var addresses: [ResolvedIPAddress] = []
            var cursor: UnsafeMutablePointer<addrinfo>? = first
            while let current = cursor {
                if current.pointee.ai_family == AF_INET,
                   let raw = current.pointee.ai_addr {
                    var address = raw.withMemoryRebound(to: sockaddr_in.self, capacity: 1) {
                        $0.pointee.sin_addr
                    }
                    addresses.append(.ipv4(withUnsafeBytes(of: &address) { Array($0) }))
                } else if current.pointee.ai_family == AF_INET6,
                          let raw = current.pointee.ai_addr {
                    var address = raw.withMemoryRebound(to: sockaddr_in6.self, capacity: 1) {
                        $0.pointee.sin6_addr
                    }
                    addresses.append(.ipv6(withUnsafeBytes(of: &address) { Array($0) }))
                }
                cursor = current.pointee.ai_next
            }
            guard !addresses.isEmpty else {
                throw HttpClientError.transport("DNS returned no IP addresses for \(host)")
            }
            return addresses
        }.value
    }
}

/// Syntactic and destination policy shared by every production wallet HTTP entry point.
public enum ProductionURLPolicy {
    public static func validated(_ value: String) throws -> URL {
        guard value.utf8.count <= 4_096,
              let url = URL(string: value),
              !url.isFileURL,
              url.scheme?.lowercased() == "https",
              let host = url.host?.lowercased(),
              !host.isEmpty,
              url.user == nil,
              url.password == nil,
              url.fragment == nil,
              url.port.map({ (1...65_535).contains($0) }) ?? true,
              isValidHost(host),
              literalAddressIsPublic(host)
        else {
            throw HttpClientError.invalidUrl(value)
        }
        return url
    }

    public static func requirePublic(_ addresses: [ResolvedIPAddress], host: String) throws {
        guard !addresses.isEmpty, addresses.allSatisfy(isPublic) else {
            throw HttpClientError.unsafeDestination(host)
        }
    }

    public static func isLiteralAddress(_ host: String) -> Bool {
        canonicalIPv4(host) != nil || parsedIPv6(host) != nil
    }

    private static func isValidHost(_ host: String) -> Bool {
        if isLiteralAddress(host) { return true }
        if host == "localhost" || host.hasSuffix(".localhost") || host.hasSuffix(".local") {
            return false
        }
        if host.last == "." || host.utf8.count > 253 { return false }
        if host.allSatisfy({ $0.isNumber || $0 == "." }) { return false }
        if host.hasPrefix("0x") && host.dropFirst(2).allSatisfy({ $0.isHexDigit }) { return false }
        return host.split(separator: ".", omittingEmptySubsequences: false).allSatisfy { label in
            !label.isEmpty
                && label.utf8.count <= 63
                && label.first != "-"
                && label.last != "-"
                && label.allSatisfy { $0.isASCII && ($0.isLetter || $0.isNumber || $0 == "-") }
        }
    }

    private static func literalAddressIsPublic(_ host: String) -> Bool {
        if let bytes = canonicalIPv4(host) { return isPublic(.ipv4(bytes)) }
        if let bytes = parsedIPv6(host) { return isPublic(.ipv6(bytes)) }
        return true
    }

    private static func canonicalIPv4(_ host: String) -> [UInt8]? {
        let parts = host.split(separator: ".", omittingEmptySubsequences: false)
        guard parts.count == 4 else { return nil }
        var bytes: [UInt8] = []
        for part in parts {
            guard !part.isEmpty,
                  (part == "0" || part.first != "0"),
                  part.allSatisfy(\.isNumber),
                  let byte = UInt8(part)
            else { return nil }
            bytes.append(byte)
        }
        return bytes
    }

    private static func parsedIPv6(_ host: String) -> [UInt8]? {
        guard host.contains(":") else { return nil }
        var address = in6_addr()
        guard inet_pton(AF_INET6, host, &address) == 1 else { return nil }
        return withUnsafeBytes(of: &address) { Array($0) }
    }

    private static func isPublic(_ address: ResolvedIPAddress) -> Bool {
        switch address {
        case .ipv4(let b):
            guard b.count == 4 else { return false }
            if b[0] == 0 || b[0] == 10 || b[0] == 127 || b[0] >= 224 { return false }
            if b[0] == 100 && (64...127).contains(b[1]) { return false }
            if b[0] == 169 && b[1] == 254 { return false }
            if b[0] == 172 && (16...31).contains(b[1]) { return false }
            if b[0] == 192 && b[1] == 168 { return false }
            if b[0] == 192 && b[1] == 0 { return false }
            if b[0] == 192 && b[1] == 88 && b[2] == 99 { return false }
            if b[0] == 192 && b[1] == 0 && b[2] == 2 { return false }
            if b[0] == 198 && (b[1] == 18 || b[1] == 19 || b[1] == 51 && b[2] == 100) {
                return false
            }
            if b[0] == 203 && b[1] == 0 && b[2] == 113 { return false }
            return true
        case .ipv6(let b):
            guard b.count == 16 else { return false }
            if b.allSatisfy({ $0 == 0 }) { return false }
            if b.dropLast().allSatisfy({ $0 == 0 }) && b.last == 1 { return false }
            if b[0] == 0xff || (b[0] & 0xfe) == 0xfc { return false }
            if b[0] == 0xfe && (b[1] & 0xc0) == 0x80 { return false }
            if b[0] == 0x20 && b[1] == 0x01 && b[2] == 0x0d && b[3] == 0xb8 { return false }
            if b.prefix(12).elementsEqual([0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff]) {
                return isPublic(.ipv4(Array(b.suffix(4))))
            }
            // Permit assigned global-unicast space only. Future ranges need an explicit review.
            return (b[0] & 0xe0) == 0x20
        }
    }
}

private final class RejectRedirectsDelegate: NSObject, URLSessionTaskDelegate {
    func urlSession(
        _ session: URLSession,
        task: URLSessionTask,
        willPerformHTTPRedirection response: HTTPURLResponse,
        newRequest request: URLRequest,
        completionHandler: @escaping (URLRequest?) -> Void
    ) {
        completionHandler(nil)
    }
}

/// Real network transport for production flows. Replaces `StubHttpClient`: performs genuine
/// HTTPS requests (TLS handled by the OS) to issuer/verifier endpoints. The wallet's protocol
/// decisions still happen in the Rust core; this only moves bytes over the wire.
public final class URLSessionHttpClient: HttpClient {
    public static let defaultMaximumResponseBytes = 1 * 1024 * 1024

    private let session: URLSession
    private let redirectDelegate: RejectRedirectsDelegate
    private let resolver: any HostAddressResolving
    private let maximumResponseBytes: Int

    public init(
        timeout: TimeInterval = 30,
        maximumResponseBytes: Int = URLSessionHttpClient.defaultMaximumResponseBytes,
        resolver: any HostAddressResolving = SystemHostAddressResolver(),
        configuration: URLSessionConfiguration? = nil
    ) {
        precondition(timeout > 0 && maximumResponseBytes > 0)
        let cfg = configuration ?? URLSessionConfiguration.ephemeral
        cfg.timeoutIntervalForRequest = timeout
        cfg.timeoutIntervalForResource = timeout
        cfg.waitsForConnectivity = true
        cfg.httpShouldSetCookies = false // a wallet carries its own auth; no ambient cookies
        cfg.httpCookieAcceptPolicy = .never
        cfg.urlCredentialStorage = nil
        cfg.urlCache = nil
        cfg.requestCachePolicy = .reloadIgnoringLocalCacheData
        let redirectDelegate = RejectRedirectsDelegate()
        self.redirectDelegate = redirectDelegate
        self.session = URLSession(
            configuration: cfg,
            delegate: redirectDelegate,
            delegateQueue: nil)
        self.resolver = resolver
        self.maximumResponseBytes = maximumResponseBytes
    }

    /// POST `body` to `url`. Content-Type is inferred from the body shape (JSON vs. the OAuth
    /// default of form-encoding), which matches the OpenID4VCI/VP endpoints the core drives.
    public func post(url: String, body: Data) async throws -> HttpResponse {
        let u = try ProductionURLPolicy.validated(url)
        var req = URLRequest(url: u)
        req.httpMethod = "POST"
        req.httpBody = body
        req.setValue(Self.contentType(for: body), forHTTPHeaderField: "Content-Type")
        req.setValue("application/json", forHTTPHeaderField: "Accept")
        return try await perform(req, limit: maximumResponseBytes, acceptedContentTypes: nil)
    }

    /// GET `url` (issuer/verifier metadata, request objects fetched by reference, JWKS, …).
    public func get(
        url: String,
        headers: [String: String] = [:],
        maximumResponseBytes: Int? = nil,
        acceptedContentTypes: Set<String>? = nil
    ) async throws -> HttpResponse {
        let u = try ProductionURLPolicy.validated(url)
        var req = URLRequest(url: u)
        req.httpMethod = "GET"
        headers.forEach { req.setValue($0.value, forHTTPHeaderField: $0.key) }
        return try await perform(
            req,
            limit: maximumResponseBytes ?? self.maximumResponseBytes,
            acceptedContentTypes: acceptedContentTypes)
    }

    /// Fetch an OpenID4VCI issuer's metadata (`/.well-known/openid-credential-issuer`).
    public func fetchIssuerMetadata(issuer: String) async throws -> HttpResponse {
        let base = issuer.hasSuffix("/") ? String(issuer.dropLast()) : issuer
        return try await get(
            url: base + "/.well-known/openid-credential-issuer",
            acceptedContentTypes: ["application/json"])
    }

    private func perform(
        _ req: URLRequest,
        limit: Int,
        acceptedContentTypes: Set<String>?
    ) async throws -> HttpResponse {
        do {
            guard let host = req.url?.host?.lowercased() else {
                throw HttpClientError.invalidUrl(req.url?.absoluteString ?? "")
            }
            if !ProductionURLPolicy.isLiteralAddress(host) {
                let addresses = try await resolver.addresses(for: host)
                try ProductionURLPolicy.requirePublic(addresses, host: host)
            }

            let (bytes, resp) = try await session.bytes(for: req)
            guard let http = resp as? HTTPURLResponse else {
                bytes.task.cancel()
                throw HttpClientError.nonHttpResponse
            }
            if (300...399).contains(http.statusCode) {
                bytes.task.cancel()
                throw HttpClientError.redirectRejected(
                    location: http.value(forHTTPHeaderField: "Location"))
            }
            if http.expectedContentLength > Int64(limit) {
                bytes.task.cancel()
                throw HttpClientError.responseTooLarge(limit: limit)
            }
            let mime = http.mimeType?.lowercased()
            if let acceptedContentTypes,
               !acceptedContentTypes.contains(mime ?? "") {
                bytes.task.cancel()
                throw HttpClientError.unacceptableContentType(
                    expected: acceptedContentTypes.sorted(),
                    actual: mime)
            }

            var data = Data()
            if http.expectedContentLength > 0 {
                data.reserveCapacity(min(Int(http.expectedContentLength), limit))
            }
            for try await byte in bytes {
                guard data.count < limit else {
                    bytes.task.cancel()
                    throw HttpClientError.responseTooLarge(limit: limit)
                }
                data.append(byte)
            }
            return HttpResponse(
                statusCode: UInt16(clamping: http.statusCode),
                body: data,
                contentType: mime)
        } catch let error as HttpClientError {
            throw error
        } catch {
            throw HttpClientError.transport(String(describing: error))
        }
    }

    private static func contentType(for body: Data) -> String {
        if let first = body.first, first == UInt8(ascii: "{") || first == UInt8(ascii: "[") {
            return "application/json"
        }
        return "application/x-www-form-urlencoded"
    }
}

/// Resolves an EUDI-authorised status signer's certificate path for a specific list URI. The
/// implementation is backed by trusted-list metadata, never by arbitrary certificates from HTTP.
public protocol StatusProviderCertificateResolver {
    func certificateChain(for uri: String) async throws -> [Data]
}

/// Production Status List transport: HTTPS GET with the registered media type, bounded response,
/// plus an independently authenticated signer path for the Rust trust decision.
public final class URLSessionStatusListResolver: StatusListResolver {
    public static let maximumTokenBytes = 2 * 1024 * 1024

    private let http: URLSessionHttpClient
    private let certificates: StatusProviderCertificateResolver

    public init(
        http: URLSessionHttpClient = URLSessionHttpClient(),
        certificates: StatusProviderCertificateResolver
    ) {
        self.http = http
        self.certificates = certificates
    }

    public func fetch(uri: String) async throws -> StatusListResolution {
        guard let url = URL(string: uri), url.scheme == "https", url.fragment == nil else {
            throw HttpClientError.invalidUrl(uri)
        }
        let response = try await http.get(
            url: uri,
            headers: ["Accept": "application/statuslist+jwt"],
            maximumResponseBytes: Self.maximumTokenBytes,
            acceptedContentTypes: ["application/statuslist+jwt"])
        guard response.body.count <= Self.maximumTokenBytes else {
            throw HttpClientError.transport("Status List Token exceeds the 2 MiB limit")
        }
        let chain = try await certificates.certificateChain(for: uri)
        guard !chain.isEmpty else {
            throw HttpClientError.transport("Status provider has no authenticated signer chain")
        }
        return StatusListResolution(response: response, providerCertChain: chain)
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
        guard trimmed.utf8.count <= 32 * 1024 else { return .unknown("") }
        guard let comps = URLComponents(string: trimmed) else { return .unknown(trimmed) }
        let scheme = (comps.scheme ?? "").lowercased()
        let items = comps.queryItems ?? []
        func value(_ name: String) -> String? {
            items.first { $0.name == name }?.value
        }
        let securityParameters: Set<String> = [
            "credential_offer", "credential_offer_uri", "request", "request_uri",
            "presentation_definition", "presentation_definition_uri", "dcql_query",
        ]
        let duplicates = Dictionary(grouping: items.filter {
            securityParameters.contains($0.name)
        }, by: \.name).values.contains { $0.count > 1 }
        guard !duplicates else { return .unknown(trimmed) }

        // --- OpenID4VCI credential offer ---
        let looksLikeOffer = scheme == "openid-credential-offer"
            || value("credential_offer") != nil
            || value("credential_offer_uri") != nil
        if looksLikeOffer {
            if let byRef = value("credential_offer_uri"), !byRef.isEmpty {
                guard (try? ProductionURLPolicy.validated(byRef)) != nil else {
                    return .unknown(trimmed)
                }
                return .credentialOfferByReference(uri: byRef)
            }
            if let json = value("credential_offer"),
               let data = json.data(using: .utf8),
               let obj = try? JSONSerialization.jsonObject(with: data) as? [String: Any],
               let issuer = obj["credential_issuer"] as? String,
               (try? ProductionURLPolicy.validated(issuer)) != nil {
                let ids = (obj["credential_configuration_ids"] as? [String]) ?? []
                guard ids.count <= 32,
                      ids.allSatisfy({ !$0.isEmpty && $0.utf8.count <= 256 })
                else { return .unknown(trimmed) }
                return .credentialOffer(issuer: issuer, configurationIds: ids)
            }
        }

        // --- OpenID4VP presentation request ---
        let looksLikePresentation = scheme.hasPrefix("openid4vp")
            || scheme == "haip"
            || scheme == "eudi-openid4vp"
            || scheme == "mdoc-openid4vp"
            || value("request") != nil
            || value("request_uri") != nil
            || value("presentation_definition") != nil
            || value("presentation_definition_uri") != nil
            || value("dcql_query") != nil
        if looksLikePresentation {
            for name in ["request_uri", "presentation_definition_uri"] {
                if let byReference = value(name),
                   (try? ProductionURLPolicy.validated(byReference)) == nil {
                    return .unknown(trimmed)
                }
            }
            if let clientId = value("client_id"), clientId.utf8.count > 2_048 {
                return .unknown(trimmed)
            }
            return .presentation(requestUri: value("request_uri"), clientId: value("client_id"))
        }

        return .unknown(trimmed)
    }
}
