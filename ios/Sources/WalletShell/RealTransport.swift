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
    public static let maximumURLBytes = 4_096
    public static let maximumDNSAnswers = 32

    public static func validated(_ value: String) throws -> URL {
        try validated(value, allowsDebugLoopback: false)
    }

    #if DEBUG
    /// Explicit development-only seam for a loopback test server. Release builds do not expose
    /// this API, and the production validator above never falls back to it.
    public static func validatedDebugLoopback(_ value: String) throws -> URL {
        try validated(value, allowsDebugLoopback: true)
    }
    #endif

    private static func validated(
        _ value: String,
        allowsDebugLoopback: Bool
    ) throws -> URL {
        guard value.utf8.count <= maximumURLBytes,
              value == value.trimmingCharacters(in: .whitespacesAndNewlines),
              value.unicodeScalars.allSatisfy({ (0x21...0x7e).contains($0.value) }),
              value.hasPrefix("https://"),
              !value.contains("\\"),
              let rawHost = canonicalAuthorityHost(value),
              let url = URL(string: value),
              !url.isFileURL,
              url.scheme == "https",
              let parsedHost = url.host?.trimmingCharacters(in: CharacterSet(charactersIn: "[]")),
              parsedHost == rawHost,
              !rawHost.isEmpty,
              url.user == nil,
              url.password == nil,
              url.fragment == nil,
              url.port != 443,
              isValidHost(rawHost, allowsDebugLoopback: allowsDebugLoopback),
              (allowsDebugLoopback && isDebugLoopbackHost(rawHost))
                || literalAddressIsPublic(rawHost)
        else {
            throw HttpClientError.invalidUrl(value)
        }
        return url
    }

    public static func requirePublic(_ addresses: [ResolvedIPAddress], host: String) throws {
        guard !addresses.isEmpty,
              addresses.count <= maximumDNSAnswers,
              addresses.allSatisfy(isPublic)
        else {
            throw HttpClientError.unsafeDestination(host)
        }
    }

    public static func isLiteralAddress(_ host: String) -> Bool {
        canonicalIPv4(host) != nil || canonicalIPv6(host) != nil
    }

    public static func isDebugLoopbackHost(_ host: String) -> Bool {
        host == "localhost" || host == "127.0.0.1" || host == "::1"
    }

    private static func canonicalAuthorityHost(_ value: String) -> String? {
        let authorityAndRest = value.dropFirst("https://".count)
        let authority = authorityAndRest.prefix { character in
            character != "/" && character != "?" && character != "#"
        }
        guard !authority.isEmpty,
              !authority.contains("@"),
              !authority.contains("%")
        else { return nil }

        if authority.first == "[" {
            guard let close = authority.firstIndex(of: "]") else { return nil }
            let host = String(authority[authority.index(after: authority.startIndex)..<close])
            let suffix = authority[authority.index(after: close)...]
            guard suffix.isEmpty || validRawPort(suffix) else { return nil }
            return canonicalIPv6(host) == nil ? nil : host
        }

        let pieces = authority.split(separator: ":", omittingEmptySubsequences: false)
        guard pieces.count <= 2,
              pieces.count == 1 || validRawPort(Substring(":\(pieces[1])")),
              let host = pieces.first.map(String.init),
              host == host.lowercased()
        else { return nil }
        return host
    }

    private static func validRawPort(_ suffix: Substring) -> Bool {
        guard suffix.first == ":" else { return false }
        let digits = suffix.dropFirst()
        guard !digits.isEmpty,
              digits.allSatisfy({ $0.isASCII && $0.isNumber }),
              digits.count == 1 || digits.first != "0",
              let port = Int(digits),
              (1...65_535).contains(port),
              port != 443
        else { return false }
        return true
    }

    private static func isValidHost(_ host: String, allowsDebugLoopback: Bool) -> Bool {
        if allowsDebugLoopback && isDebugLoopbackHost(host) { return true }
        if isLiteralAddress(host) { return true }
        if host == "localhost" || host.hasSuffix(".localhost") || host.hasSuffix(".local") {
            return false
        }
        if host.last == "." || host.utf8.count > 253 { return false }
        if host.allSatisfy({ $0.isNumber || $0 == "." }) { return false }
        if host.hasPrefix("0x") && host.dropFirst(2).allSatisfy({ $0.isHexDigit }) { return false }
        let labels = host.split(separator: ".", omittingEmptySubsequences: false)
        return labels.count >= 2 && labels.allSatisfy { label in
            !label.isEmpty
                && label.utf8.count <= 63
                && label.first != "-"
                && label.last != "-"
                && label.allSatisfy { $0.isASCII && ($0.isLetter || $0.isNumber || $0 == "-") }
        }
    }

    private static func literalAddressIsPublic(_ host: String) -> Bool {
        if let bytes = canonicalIPv4(host) { return isPublic(.ipv4(bytes)) }
        if let bytes = canonicalIPv6(host) { return isPublic(.ipv6(bytes)) }
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

    private static func canonicalIPv6(_ host: String) -> [UInt8]? {
        guard host.contains(":") else { return nil }
        var address = in6_addr()
        guard inet_pton(AF_INET6, host, &address) == 1 else { return nil }
        var rendered = [CChar](repeating: 0, count: Int(INET6_ADDRSTRLEN))
        let result = withUnsafePointer(to: &address) { pointer in
            rendered.withUnsafeMutableBufferPointer { buffer in
                inet_ntop(AF_INET6, pointer, buffer.baseAddress, socklen_t(INET6_ADDRSTRLEN))
            }
        }
        let renderedBytes = rendered.prefix { $0 != 0 }.map { UInt8(bitPattern: $0) }
        guard result != nil, String(decoding: renderedBytes, as: UTF8.self) == host else {
            return nil
        }
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
            if b[0] == 192 && b[1] == 31 && b[2] == 196 { return false }
            if b[0] == 192 && b[1] == 52 && b[2] == 193 { return false }
            if b[0] == 192 && b[1] == 88 && b[2] == 99 { return false }
            if b[0] == 192 && b[1] == 175 && b[2] == 48 { return false }
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
            // Current RIR/global allocations are in 2000::/4. Future ranges need explicit review.
            guard (0x20...0x2f).contains(b[0]) else { return false }
            if b[0] == 0x20 && b[1] == 0x01 {
                // IETF protocol assignments in 2001:0000::/23 are not ordinary public endpoints.
                if b[2] <= 0x01 { return false }
            }
            if b[0] == 0x20 && b[1] == 0x02 { return false } // 6to4 transition range
            if b[0] == 0x26 && b[1] == 0x20
                && b[2] == 0x00 && b[3] == 0x4f
                && b[4] == 0x80 && b[5] == 0x00 {
                return false // AS112-v6 special-purpose endpoint range
            }
            return true
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
    public static let maximumMetadataBytes = 512 * 1024
    public static let maximumCredentialOfferBytes = 256 * 1024
    public static let maximumPresentationRequestBytes = 512 * 1024
    public static let maximumStatusListBytes = 2 * 1024 * 1024

    private let session: URLSession
    private let redirectDelegate: RejectRedirectsDelegate
    private let resolver: any HostAddressResolving
    private let maximumResponseBytes: Int
    private let allowsDebugLoopback: Bool

    public convenience init(
        timeout: TimeInterval = 30,
        maximumResponseBytes: Int = URLSessionHttpClient.defaultMaximumResponseBytes
    ) {
        self.init(
            timeout: timeout,
            maximumResponseBytes: maximumResponseBytes,
            resolver: SystemHostAddressResolver(),
            configuration: nil,
            allowsDebugLoopback: false)
    }

    /// Internal dependency seam used by host-side tests. Production callers cannot replace DNS
    /// validation or inject a custom URL-loading stack.
    convenience init(
        timeout: TimeInterval = 30,
        maximumResponseBytes: Int = URLSessionHttpClient.defaultMaximumResponseBytes,
        testingResolver resolver: any HostAddressResolving,
        configuration: URLSessionConfiguration
    ) {
        self.init(
            timeout: timeout,
            maximumResponseBytes: maximumResponseBytes,
            resolver: resolver,
            configuration: configuration,
            allowsDebugLoopback: false)
    }

    #if DEBUG
    /// Explicit development-only client for a canonical loopback test server. There is no
    /// production initializer flag and no automatic fallback when public DNS validation fails.
    public static func debugLocalhost(
        timeout: TimeInterval = 30,
        maximumResponseBytes: Int = URLSessionHttpClient.defaultMaximumResponseBytes,
        configuration: URLSessionConfiguration? = nil
    ) -> URLSessionHttpClient {
        URLSessionHttpClient(
            timeout: timeout,
            maximumResponseBytes: maximumResponseBytes,
            resolver: SystemHostAddressResolver(),
            configuration: configuration,
            allowsDebugLoopback: true)
    }
    #endif

    private init(
        timeout: TimeInterval,
        maximumResponseBytes: Int,
        resolver: any HostAddressResolving,
        configuration: URLSessionConfiguration?,
        allowsDebugLoopback: Bool
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
        self.allowsDebugLoopback = allowsDebugLoopback
    }

    /// POST `body` to `url`. Content-Type is inferred from the body shape (JSON vs. the OAuth
    /// default of form-encoding), which matches the OpenID4VCI/VP endpoints the core drives.
    public func post(url: String, body: Data) async throws -> HttpResponse {
        let u = try validatedURL(url)
        var req = URLRequest(url: u)
        req.httpMethod = "POST"
        req.httpBody = body
        req.setValue(Self.contentType(for: body), forHTTPHeaderField: "Content-Type")
        req.setValue("*/*", forHTTPHeaderField: "Accept")
        // The generic effect is shared by token/credential JSON endpoints, OpenID4VP
        // `direct_post`, payments and QES. Their response contracts differ, so MIME enforcement
        // belongs in a typed protocol adapter rather than this common transport boundary.
        return try await perform(req, limit: maximumResponseBytes, acceptedContentTypes: nil)
    }

    /// GET `url` (issuer/verifier metadata, request objects fetched by reference, JWKS, …).
    public func get(
        url: String,
        headers: [String: String] = [:],
        maximumResponseBytes: Int? = nil,
        acceptedContentTypes: Set<String>? = nil
    ) async throws -> HttpResponse {
        let requestedLimit = maximumResponseBytes ?? self.maximumResponseBytes
        guard requestedLimit > 0 else {
            throw HttpClientError.transport("maximum response size must be positive")
        }
        let limit = min(requestedLimit, self.maximumResponseBytes)
        let u = try validatedURL(url)
        var req = URLRequest(url: u)
        req.httpMethod = "GET"
        headers.forEach { req.setValue($0.value, forHTTPHeaderField: $0.key) }
        if let acceptedContentTypes, req.value(forHTTPHeaderField: "Accept") == nil {
            req.setValue(acceptedContentTypes.sorted().joined(separator: ", "),
                         forHTTPHeaderField: "Accept")
        }
        return try await perform(
            req,
            limit: limit,
            acceptedContentTypes: acceptedContentTypes)
    }

    /// Fetch an OpenID4VCI issuer's metadata (`/.well-known/openid-credential-issuer`).
    public func fetchIssuerMetadata(issuer: String) async throws -> HttpResponse {
        let issuerURL = try validatedURL(issuer)
        guard issuerURL.query == nil,
              var components = URLComponents(url: issuerURL, resolvingAgainstBaseURL: false)
        else { throw HttpClientError.invalidUrl(issuer) }
        let issuerPath = components.percentEncodedPath == "/"
            ? ""
            : components.percentEncodedPath
        components.percentEncodedPath = "/.well-known/openid-credential-issuer" + issuerPath
        guard let metadataURL = components.url?.absoluteString else {
            throw HttpClientError.invalidUrl(issuer)
        }
        return try await get(
            url: metadataURL,
            maximumResponseBytes: Self.maximumMetadataBytes,
            acceptedContentTypes: ["application/json"])
    }

    /// Fetch an OpenID4VCI `credential_offer_uri` under the same destination and body policy.
    public func fetchCredentialOffer(uri: String) async throws -> HttpResponse {
        try await get(
            url: uri,
            maximumResponseBytes: Self.maximumCredentialOfferBytes,
            acceptedContentTypes: ["application/json"])
    }

    /// Fetch an OpenID4VP request object by reference. Only JWT request-object media types pass.
    public func fetchPresentationRequest(uri: String) async throws -> HttpResponse {
        try await get(
            url: uri,
            maximumResponseBytes: Self.maximumPresentationRequestBytes,
            acceptedContentTypes: ["application/jwt", "application/oauth-authz-req+jwt"])
    }

    /// Fetch a Token Status List with its registered media type and independent size budget.
    public func fetchStatusListToken(uri: String) async throws -> HttpResponse {
        try await get(
            url: uri,
            maximumResponseBytes: Self.maximumStatusListBytes,
            acceptedContentTypes: ["application/statuslist+jwt"])
    }

    private func validatedURL(_ value: String) throws -> URL {
        #if DEBUG
        if allowsDebugLoopback {
            return try ProductionURLPolicy.validatedDebugLoopback(value)
        }
        #endif
        return try ProductionURLPolicy.validated(value)
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
            // URLSession performs its own connection-time DNS lookup. This preflight rejects empty
            // and mixed unsafe answer sets, but does not socket-pin the validated address; that
            // remaining rebinding/TOCTOU gap stays explicitly tracked in STATUS.md.
            if !(allowsDebugLoopback && ProductionURLPolicy.isDebugLoopbackHost(host))
                && !ProductionURLPolicy.isLiteralAddress(host) {
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
            let mime = http.value(forHTTPHeaderField: "Content-Type")?
                .split(separator: ";", maxSplits: 1, omittingEmptySubsequences: true)
                .first
                .map { $0.trimmingCharacters(in: .whitespacesAndNewlines).lowercased() }
                .flatMap { $0.isEmpty ? nil : $0 }
            if let acceptedContentTypes,
               let mime,
               !acceptedContentTypes.contains(mime) {
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
            if let acceptedContentTypes, mime == nil {
                throw HttpClientError.unacceptableContentType(
                    expected: acceptedContentTypes.sorted(),
                    actual: nil)
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
    public static let maximumTokenBytes = URLSessionHttpClient.maximumStatusListBytes

    private let http: URLSessionHttpClient
    private let certificates: StatusProviderCertificateResolver

    public init(
        http: URLSessionHttpClient = URLSessionHttpClient(
            maximumResponseBytes: URLSessionStatusListResolver.maximumTokenBytes),
        certificates: StatusProviderCertificateResolver
    ) {
        self.http = http
        self.certificates = certificates
    }

    public func fetch(uri: String) async throws -> StatusListResolution {
        let response = try await http.fetchStatusListToken(uri: uri)
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
    /// OpenID4VP presentation request fetched by GET from `request_uri`.
    case presentation(requestUri: String?, clientId: String?)
    /// Not a recognised wallet link.
    case unknown(String)

    /// Classify a scanned string. Only registered wallet schemes and explicitly configured HTTPS
    /// universal-link origins can trigger a flow; arbitrary websites cannot smuggle wallet query
    /// parameters into the classifier.
    public static func parse(
        _ text: String,
        allowedUniversalLinkOrigins: Set<String> = []
    ) -> ScannedRequest {
        let trimmed = text.trimmingCharacters(in: .whitespacesAndNewlines)
        guard text == trimmed,
              !trimmed.isEmpty,
              trimmed.utf8.count <= 32 * 1024
        else { return .unknown("") }
        guard let comps = URLComponents(string: trimmed),
              comps.fragment == nil,
              comps.user == nil,
              comps.password == nil
        else { return .unknown(trimmed) }
        let scheme = comps.scheme ?? ""
        let isCredentialOfferScheme = scheme == "openid-credential-offer"
        let presentationSchemes: Set<String> = [
            "openid4vp", "haip", "eudi-openid4vp", "mdoc-openid4vp",
        ]
        let isPresentationScheme = presentationSchemes.contains(scheme)
        let isUniversalLink = scheme == "https"
            && isAllowedUniversalLink(
                trimmed,
                allowedOrigins: allowedUniversalLinkOrigins)
        guard isCredentialOfferScheme || isPresentationScheme || isUniversalLink else {
            return .unknown(trimmed)
        }
        if isCredentialOfferScheme || isPresentationScheme {
            // Registered wallet URIs use an empty authority and path. Reject host/port/path
            // variants so Foundation and another parser cannot assign different semantics.
            guard (comps.host ?? "").isEmpty,
                  comps.port == nil,
                  comps.percentEncodedPath.isEmpty,
                  trimmed.hasPrefix("\(scheme)://?")
            else { return .unknown(trimmed) }
        }
        let items = comps.queryItems ?? []
        guard items.count <= 64,
              items.allSatisfy({ item in
                  !item.name.isEmpty
                      && item.name.utf8.count <= 128
                      && (item.value?.utf8.count ?? 0) <= 16 * 1024
              })
        else { return .unknown(trimmed) }
        func value(_ name: String) -> String? {
            items.first { $0.name == name }?.value
        }
        func has(_ name: String) -> Bool {
            items.contains { $0.name == name }
        }
        let duplicates = Dictionary(grouping: items, by: \.name).values.contains { $0.count > 1 }
        guard !duplicates else { return .unknown(trimmed) }

        let offerParameters = ["credential_offer", "credential_offer_uri"].filter {
            has($0)
        }
        let presentationParameters = [
            "request", "request_uri", "presentation_definition",
            "presentation_definition_uri", "dcql_query", "request_uri_method",
        ].filter { has($0) }
        let presentationSecurityParameters = presentationParameters + ["client_id"].filter { has($0) }
        let securityParameters = offerParameters + presentationSecurityParameters
        guard securityParameters.allSatisfy({ name in
            guard let parameter = value(name) else { return false }
            return !parameter.isEmpty
        }) else { return .unknown(trimmed) }
        guard offerParameters.isEmpty || presentationSecurityParameters.isEmpty else {
            return .unknown(trimmed)
        }
        if isCredentialOfferScheme {
            guard !offerParameters.isEmpty, presentationSecurityParameters.isEmpty else {
                return .unknown(trimmed)
            }
        } else if isPresentationScheme {
            guard offerParameters.isEmpty, !presentationParameters.isEmpty else {
                return .unknown(trimmed)
            }
        }

        // --- OpenID4VCI credential offer ---
        let looksLikeOffer = isCredentialOfferScheme
            || (isUniversalLink && !offerParameters.isEmpty)
        if looksLikeOffer {
            let supportedNames: Set<String> = ["credential_offer", "credential_offer_uri"]
            guard Set(items.map(\.name)).isSubset(of: supportedNames),
                  offerParameters.count == 1
            else { return .unknown(trimmed) }
            if let byRef = value("credential_offer_uri"), !byRef.isEmpty {
                guard (try? ProductionURLPolicy.validated(byRef)) != nil else {
                    return .unknown(trimmed)
                }
                return .credentialOfferByReference(uri: byRef)
            }
            if let json = value("credential_offer"),
               hasUniqueJSONObjectKeys(json),
               let data = json.data(using: .utf8),
               let obj = try? JSONSerialization.jsonObject(with: data) as? [String: Any],
               let issuer = obj["credential_issuer"] as? String,
               let issuerURL = try? ProductionURLPolicy.validated(issuer),
               issuerURL.query == nil {
                let ids = (obj["credential_configuration_ids"] as? [String]) ?? []
                guard (1...32).contains(ids.count),
                      Set(ids).count == ids.count,
                      ids.allSatisfy({ !$0.isEmpty && $0.utf8.count <= 256 })
                else { return .unknown(trimmed) }
                return .credentialOffer(issuer: issuer, configurationIds: ids)
            }
        }

        // --- OpenID4VP presentation request ---
        let looksLikePresentation = isPresentationScheme
            || (isUniversalLink && !presentationParameters.isEmpty)
        if looksLikePresentation {
            // The current typed result carries only a GET request_uri and client_id. Inline
            // request objects, PD/DCQL inputs and request_uri_method are rejected instead of being
            // classified and silently discarded or accidentally fetched with the wrong method.
            let supportedNames: Set<String> = ["request_uri", "client_id"]
            guard Set(items.map(\.name)).isSubset(of: supportedNames),
                  let requestUri = value("request_uri"),
                  (try? ProductionURLPolicy.validated(requestUri)) != nil
            else { return .unknown(trimmed) }
            if let clientId = value("client_id"),
               clientId.isEmpty || clientId.utf8.count > 2_048 {
                return .unknown(trimmed)
            }
            return .presentation(requestUri: requestUri, clientId: value("client_id"))
        }

        return .unknown(trimmed)
    }

    private static func isAllowedUniversalLink(
        _ value: String,
        allowedOrigins: Set<String>
    ) -> Bool {
        guard !allowedOrigins.isEmpty,
              allowedOrigins.count <= 32,
              let url = try? ProductionURLPolicy.validated(value),
              let origin = canonicalOrigin(of: url)
        else { return false }

        return allowedOrigins.contains { configured in
            guard let allowed = try? ProductionURLPolicy.validated(configured),
                  allowed.query == nil,
                  allowed.path.isEmpty || allowed.path == "/",
                  let allowedOrigin = canonicalOrigin(of: allowed)
            else { return false }
            return allowedOrigin == origin
        }
    }

    private static func canonicalOrigin(of url: URL) -> String? {
        guard let scheme = url.scheme,
              let host = url.host?.trimmingCharacters(in: CharacterSet(charactersIn: "[]"))
        else { return nil }
        var components = URLComponents()
        components.scheme = scheme
        components.host = host
        components.port = url.port
        return components.string
    }

    /// Foundation's JSON parser accepts duplicate object keys using last-value-wins semantics.
    /// Reject them before parsing so different wallet/issuer stacks cannot interpret the same
    /// security input differently. The depth cap also prevents a tiny QR from inducing extreme
    /// parser recursion.
    private static func hasUniqueJSONObjectKeys(_ json: String) -> Bool {
        struct Context {
            let isObject: Bool
            var keys: Set<String> = []
            var expectsKey: Bool
        }

        let bytes = Array(json.utf8)
        var contexts: [Context] = []
        var index = 0

        while index < bytes.count {
            switch bytes[index] {
            case 0x7b: // {
                contexts.append(Context(isObject: true, expectsKey: true))
                guard contexts.count <= 32 else { return false }
            case 0x5b: // [
                contexts.append(Context(isObject: false, expectsKey: false))
                guard contexts.count <= 32 else { return false }
            case 0x7d, 0x5d: // } or ]
                guard !contexts.isEmpty else { return false }
                contexts.removeLast()
            case 0x2c: // ,
                if let last = contexts.indices.last, contexts[last].isObject {
                    contexts[last].expectsKey = true
                }
            case 0x22: // JSON string
                let start = index
                index += 1
                var escaped = false
                while index < bytes.count {
                    let byte = bytes[index]
                    if escaped {
                        escaped = false
                    } else if byte == 0x5c {
                        escaped = true
                    } else if byte == 0x22 {
                        break
                    }
                    index += 1
                }
                guard index < bytes.count else { return false }

                if let last = contexts.indices.last,
                   contexts[last].isObject,
                   contexts[last].expectsKey {
                    let literal = Data(bytes[start...index])
                    guard let key = try? JSONDecoder().decode(String.self, from: literal) else {
                        return false
                    }
                    var lookahead = index + 1
                    while lookahead < bytes.count,
                          [0x20, 0x09, 0x0a, 0x0d].contains(bytes[lookahead]) {
                        lookahead += 1
                    }
                    guard lookahead < bytes.count, bytes[lookahead] == 0x3a else {
                        return false
                    }
                    guard contexts[last].keys.insert(key).inserted else { return false }
                    contexts[last].expectsKey = false
                }
            default:
                break
            }
            index += 1
        }
        return contexts.isEmpty
    }
}
