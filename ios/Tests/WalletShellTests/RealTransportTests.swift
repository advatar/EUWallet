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

    override class func canInit(with request: URLRequest) -> Bool { true }

    override class func canonicalRequest(for request: URLRequest) -> URLRequest { request }

    override func startLoading() {
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
        super.tearDown()
    }

    func testProductionUrlPolicyAcceptsOnlyPublicAbsoluteHttpsDestinations() throws {
        for value in [
            "https://example.com/path?query=1",
            "https://münich.de/angebot",
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
            "https://example.com:0",
            "https://example.com:99999",
            "https://localhost/status",
            "https://wallet.local/status",
            "https://127.0.0.1/status",
            "https://127.1/status",
            "https://2130706433/status",
            "https://0x7f000001/status",
            "https://10.0.0.1/status",
            "https://169.254.169.254/latest/meta-data",
            "https://192.168.1.1/status",
            "https://[::1]/status",
            "https://[fe80::1]/status",
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
    }

    func testTransportRejectsDnsResolutionContainingPrivateAddress() async {
        let configuration = URLSessionConfiguration.ephemeral
        configuration.protocolClasses = [WalletURLProtocol.self]
        let client = URLSessionHttpClient(
            resolver: FixedHostResolver(addresses: [
                .ipv4([93, 184, 216, 34]), .ipv4([127, 0, 0, 1]),
            ]),
            configuration: configuration)

        await assertHttpError(.unsafeDestination("api.example")) {
            try await client.get(url: "https://api.example/data")
        }
    }

    private func makeClient(limit: Int) -> URLSessionHttpClient {
        let configuration = URLSessionConfiguration.ephemeral
        configuration.protocolClasses = [WalletURLProtocol.self]
        return URLSessionHttpClient(
            maximumResponseBytes: limit,
            resolver: FixedHostResolver(addresses: [.ipv4([93, 184, 216, 34])]),
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
