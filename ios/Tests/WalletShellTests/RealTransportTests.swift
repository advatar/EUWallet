import Foundation
import XCTest
@testable import WalletShell

private struct FixedHostResolver: HostAddressResolving {
    let addresses: [ResolvedIPAddress]

    func addresses(for host: String) async throws -> [ResolvedIPAddress] {
        addresses
    }
}

private final class WalletURLProtocol: URLProtocol, @unchecked Sendable {
    nonisolated(unsafe) static var response: HTTPURLResponse?
    nonisolated(unsafe) static var body = Data()
    nonisolated(unsafe) static var lastRequest: URLRequest?

    override class func canInit(with request: URLRequest) -> Bool { true }

    override class func canonicalRequest(for request: URLRequest) -> URLRequest { request }

    override func startLoading() {
        Self.lastRequest = request
        guard let response = Self.response else {
            client?.urlProtocol(self, didFailWithError: URLError(.badServerResponse))
            return
        }
        client?.urlProtocol(self, didReceive: response, cacheStoragePolicy: .notAllowed)
        if !Self.body.isEmpty {
            client?.urlProtocol(self, didLoad: Self.body)
        }
        client?.urlProtocolDidFinishLoading(self)
    }

    override func stopLoading() {}
}

final class RealTransportTests: XCTestCase {
    override func tearDown() {
        WalletURLProtocol.response = nil
        WalletURLProtocol.body = Data()
        WalletURLProtocol.lastRequest = nil
        super.tearDown()
    }

    func testProductionUrlPolicyAcceptsOnlyPublicAbsoluteHttpsDestinations() throws {
        for value in [
            "https://example.com/path?query=1",
            "https://xn--mnich-kva.de/angebot",
            "https://sandbox.example.com:8443/angebot",
            "https://8.8.8.8/status",
            "https://[2606:4700:4700::1111]/status",
        ] {
            XCTAssertNoThrow(try ProductionURLPolicy.validated(value), value)
        }

        for value in [
            "http://example.com",
            "file:///etc/passwd",
            "https://user:password@example.com",
            "https://example.com/path#fragment",
            "https://example.com:443/path",
            "https://example.com:0443/path",
            "https://example.com:08443/path",
            "https://example.com:0",
            "https://example.com:99999",
            "HTTPS://example.com/status",
            "https://EXAMPLE.com/status",
            "https://example/status",
            "https://example.com./status",
            "https://münich.de/angebot",
            "https://example.com%40attacker.invalid/status",
            "https://example.com\\@attacker.invalid/status",
            "https://localhost/status",
            "https://wallet.local/status",
            "https://127.0.0.1/status",
            "https://127.1/status",
            "https://2130706433/status",
            "https://0x7f000001/status",
            "https://1.2.3.04/status",
            "https://10.0.0.1/status",
            "https://169.254.169.254/latest/meta-data",
            "https://192.168.1.1/status",
            "https://[::1]/status",
            "https://[fe80::1]/status",
            "https://[::ffff:127.0.0.1]/status",
            "https://[2001:db8::1]/status",
            "https://[2002::1]/status",
            "https://[3fff::1]/status",
            "https://[2606:4700:4700:0:0:0:0:1111]/status",
            "https://exa_mple.com/status",
        ] {
            XCTAssertThrowsError(try ProductionURLPolicy.validated(value), value)
        }
    }

    func testDnsPolicyRejectsAnyPrivateOrMalformedResolution() {
        XCTAssertNoThrow(try ProductionURLPolicy.requirePublic(
            [.ipv4([93, 184, 216, 34]), .ipv6([
                0x26, 0x06, 0x47, 0x00, 0x47, 0x00, 0, 0, 0, 0, 0, 0, 0, 0, 0x11, 0x11,
            ])],
            host: "example.com"))
        XCTAssertThrowsError(try ProductionURLPolicy.requirePublic(
            [.ipv4([93, 184, 216, 34]), .ipv4([10, 0, 0, 1])],
            host: "rebinding.example"))
        XCTAssertThrowsError(try ProductionURLPolicy.requirePublic([], host: "empty.example"))
        XCTAssertThrowsError(try ProductionURLPolicy.requirePublic(
            [.ipv4([1, 2, 3])], host: "malformed.example"))
        let specialIPv4: [[UInt8]] = [
            [192, 31, 196, 1],
            [192, 52, 193, 1],
            [192, 175, 48, 1],
        ]
        for special in specialIPv4 {
            XCTAssertThrowsError(try ProductionURLPolicy.requirePublic(
                [.ipv4(special)], host: "special-purpose.example"))
        }
        XCTAssertThrowsError(try ProductionURLPolicy.requirePublic(
            Array(repeating: .ipv4([93, 184, 216, 34]), count: 33),
            host: "too-many.example"))
        XCTAssertThrowsError(try ProductionURLPolicy.requirePublic(
            [.ipv6([0x3f, 0xff] + Array(repeating: 0, count: 14))],
            host: "reserved-v6.example"))
        XCTAssertThrowsError(try ProductionURLPolicy.requirePublic(
            [.ipv6([0x20, 0x01, 0x0d, 0xb8] + Array(repeating: 0, count: 12))],
            host: "documentation-v6.example"))
        XCTAssertThrowsError(try ProductionURLPolicy.requirePublic(
            [.ipv6([0x26, 0x20, 0x00, 0x4f, 0x80, 0x00] + Array(repeating: 0, count: 10))],
            host: "as112-v6.example"))
    }

    func testTransportStreamsBoundedBodyAndPreservesContentType() async throws {
        let client = makeClient(limit: 4)
        setResponse(status: 200, headers: ["Content-Type": "application/json"], body: Data([1, 2, 3, 4]))

        let response = try await client.get(
            url: "https://api.example/data",
            acceptedContentTypes: ["application/json"])

        XCTAssertEqual(response.statusCode, 200)
        XCTAssertEqual(response.body, Data([1, 2, 3, 4]))
        XCTAssertEqual(response.contentType, "application/json")
    }

    func testTransportRejectsRedirectOversizeAndWrongContentType() async {
        let client = makeClient(limit: 4)

        setResponse(status: 302, headers: ["Location": "https://other.example/next"])
        await assertHttpError(.redirectRejected(location: "https://other.example/next")) {
            try await client.get(url: "https://api.example/data")
        }

        setResponse(status: 200, headers: [:], body: Data(repeating: 1, count: 5))
        await assertHttpError(.responseTooLarge(limit: 4)) {
            try await client.get(url: "https://api.example/data")
        }

        setResponse(status: 200, headers: ["Content-Type": "text/html"], body: Data([1]))
        await assertHttpError(
            .unacceptableContentType(expected: ["application/json"], actual: "text/html")
        ) {
            try await client.get(
                url: "https://api.example/data",
                acceptedContentTypes: ["application/json"])
        }

        setResponse(status: 200, headers: ["Content-Length": "5"], body: Data())
        await assertHttpError(.responseTooLarge(limit: 4)) {
            try await client.get(url: "https://api.example/data")
        }

        setResponse(status: 200, headers: [:], body: Data())
        await assertHttpError(
            .unacceptableContentType(expected: ["application/json"], actual: nil)
        ) {
            try await client.get(
                url: "https://api.example/data",
                acceptedContentTypes: ["application/json"])
        }
    }

    func testGenericPostUsesSameDestinationAndBoundedResponsePolicy() async throws {
        let client = makeClient(limit: 16)
        setResponse(
            status: 200,
            headers: ["Content-Type": "application/json; charset=utf-8"],
            body: Data("{}".utf8))

        _ = try await client.post(url: "https://api.example/token", body: Data("{}".utf8))
        XCTAssertEqual(WalletURLProtocol.lastRequest?.httpMethod, "POST")
        XCTAssertEqual(WalletURLProtocol.lastRequest?.value(forHTTPHeaderField: "Accept"),
                       "*/*")
        XCTAssertEqual(WalletURLProtocol.lastRequest?.value(forHTTPHeaderField: "Content-Type"),
                       "application/json")

        // This transport also carries direct_post, payment and QES effects whose successful
        // response contracts are not universally JSON. Typed adapters enforce endpoint MIME.
        setResponse(status: 200, headers: ["Content-Type": "text/plain"], body: Data("ok".utf8))
        let nonJSON = try await client.post(url: "https://api.example/response", body: Data())
        XCTAssertEqual(nonJSON.contentType, "text/plain")
        XCTAssertEqual(nonJSON.body, Data("ok".utf8))

        setResponse(status: 200, headers: [:], body: Data(repeating: 1, count: 17))
        await assertHttpError(.responseTooLarge(limit: 16)) {
            try await client.post(url: "https://api.example/response", body: Data())
        }
        await assertHttpError(.invalidUrl("http://api.example/response")) {
            try await client.post(url: "http://api.example/response", body: Data())
        }

        setResponse(status: 204, headers: [:])
        _ = try await client.post(url: "https://api.example/response", body: Data())
    }

    func testProtocolGetHelpersSetExactMimeAndEndpointPolicies() async throws {
        let client = makeClient(limit: 1)

        setResponse(status: 200, headers: ["Content-Type": "application/json"], body: Data([1]))
        _ = try await client.fetchIssuerMetadata(issuer: "https://issuer.example/tenant")
        XCTAssertEqual(
            WalletURLProtocol.lastRequest?.url?.absoluteString,
            "https://issuer.example/.well-known/openid-credential-issuer/tenant")
        XCTAssertEqual(WalletURLProtocol.lastRequest?.httpMethod, "GET")
        XCTAssertEqual(WalletURLProtocol.lastRequest?.value(forHTTPHeaderField: "Accept"),
                       "application/json")
        await assertHttpError(.invalidUrl("https://issuer.example/tenant?version=1")) {
            try await client.fetchIssuerMetadata(
                issuer: "https://issuer.example/tenant?version=1")
        }

        setResponse(status: 200, headers: ["Content-Type": "application/json"], body: Data([1]))
        _ = try await client.fetchCredentialOffer(uri: "https://issuer.example/offers/1")
        XCTAssertEqual(WalletURLProtocol.lastRequest?.url?.path, "/offers/1")

        setResponse(
            status: 200,
            headers: ["Content-Type": "application/oauth-authz-req+jwt"],
            body: Data([1]))
        _ = try await client.fetchPresentationRequest(uri: "https://verifier.example/request/1")
        XCTAssertEqual(
            WalletURLProtocol.lastRequest?.value(forHTTPHeaderField: "Accept"),
            "application/jwt, application/oauth-authz-req+jwt")

        setResponse(
            status: 200,
            headers: ["Content-Type": "application/statuslist+jwt"],
            body: Data([1]))
        _ = try await client.fetchStatusListToken(uri: "https://status.example/list/1")
        XCTAssertEqual(
            WalletURLProtocol.lastRequest?.value(forHTTPHeaderField: "Accept"),
            "application/statuslist+jwt")

        setResponse(status: 200, headers: ["Content-Type": "application/json"], body: Data([1]))
        await assertHttpError(
            .unacceptableContentType(
                expected: ["application/jwt", "application/oauth-authz-req+jwt"],
                actual: "application/json")
        ) {
            try await client.fetchPresentationRequest(uri: "https://verifier.example/request/1")
        }
    }

    func testTransportRejectsDnsResolutionContainingPrivateAddress() async {
        let configuration = URLSessionConfiguration.ephemeral
        configuration.protocolClasses = [WalletURLProtocol.self]
        let client = URLSessionHttpClient(
            testingResolver: FixedHostResolver(addresses: [
                .ipv4([93, 184, 216, 34]), .ipv4([127, 0, 0, 1]),
            ]),
            configuration: configuration)

        await assertHttpError(.unsafeDestination("api.example")) {
            try await client.get(url: "https://api.example/data")
        }
    }

    #if DEBUG
    func testLoopbackRequiresExplicitDebugOnlyClient() async throws {
        XCTAssertThrowsError(try ProductionURLPolicy.validated("https://localhost/data"))
        let configuration = URLSessionConfiguration.ephemeral
        configuration.protocolClasses = [WalletURLProtocol.self]
        let client = URLSessionHttpClient.debugLocalhost(
            maximumResponseBytes: 4,
            configuration: configuration)
        setResponse(status: 200, headers: ["Content-Type": "application/json"], body: Data([1]))

        let response = try await client.get(
            url: "https://localhost/data",
            acceptedContentTypes: ["application/json"])
        XCTAssertEqual(response.body, Data([1]))
    }
    #endif

    private func makeClient(limit: Int) -> URLSessionHttpClient {
        let configuration = URLSessionConfiguration.ephemeral
        configuration.protocolClasses = [WalletURLProtocol.self]
        return URLSessionHttpClient(
            maximumResponseBytes: limit,
            testingResolver: FixedHostResolver(addresses: [.ipv4([93, 184, 216, 34])]),
            configuration: configuration)
    }

    private func setResponse(
        status: Int,
        headers: [String: String],
        body: Data = Data()
    ) {
        WalletURLProtocol.response = HTTPURLResponse(
            url: URL(string: "https://api.example/data")!,
            statusCode: status,
            httpVersion: "HTTP/1.1",
            headerFields: headers)
        WalletURLProtocol.body = body
    }

    private func assertHttpError(
        _ expected: HttpClientError,
        operation: () async throws -> HttpResponse,
        file: StaticString = #filePath,
        line: UInt = #line
    ) async {
        do {
            _ = try await operation()
            XCTFail("expected HTTP failure", file: file, line: line)
        } catch let error as HttpClientError {
            XCTAssertEqual(error, expected, file: file, line: line)
        } catch {
            XCTFail("unexpected error: \(error)", file: file, line: line)
        }
    }
}
