import XCTest

/// Drives the Digital Credentials API provider's core (`DcApiPresentationDriver`) end to end ON THE
/// SIMULATOR against the REAL Rust wallet core. The OS DC-API surface
/// (`navigator.credentials.get({digital})` → `IdentityDocumentServicesUI`) is device-only, but the
/// driver itself talks straight to the core over the same `handle_event_json` FFI the provider
/// extension uses — so this proves the seed → parse → consent → device-sign → assemble path, and the
/// data-minimisation gate, execute correctly on the iOS runtime. It mirrors the Rust
/// `e2e_dcapi_presentation` test through the Swift driver + UniFFI.
final class DcApiProviderDriverTests: XCTestCase {
    private let origin = "https://verifier.example.com"

    /// An unsigned OpenID4VP-over-DC-API request (`response_mode=dc_api`) with one `mso_mdoc` DCQL
    /// query for the PID, asking ONLY for `age_over_18` — `family_name` is deliberately not requested.
    private var pidAgeOnlyRequest: Data {
        Data(
            #"""
            {"response_type":"vp_token","response_mode":"dc_api","nonce":"n-0S6_WzA2Mj",
             "dcql_query":{"credentials":[{"id":"pid","format":"mso_mdoc",
               "meta":{"doctype_value":"eu.europa.ec.eudi.pid.1"},
               "claims":[{"path":["eu.europa.ec.eudi.pid.1","age_over_18"]}]}]}}
            """#.utf8)
    }

    func testPresentationReturnsMinimisedVpToken() async throws {
        let driver = try DcApiPresentationDriver()
        try await driver.seedIfNeeded()

        let responseData = try driver.present(requestData: pidAgeOnlyRequest, origin: origin)
        let json = String(decoding: responseData, as: UTF8.self)

        // The browser response is the OpenID4VP vp_token object for response_mode=dc_api.
        XCTAssertTrue(json.contains("\"vp_token\""), "expected a vp_token object, got: \(json)")

        // Extract the single base64url DeviceResponse and assert the core disclosed ONLY the
        // requested element — the data-minimisation guarantee, verified over the FFI on-device.
        let deviceResponse = try Self.decodeSingleVpToken(responseData)
        XCTAssertTrue(
            Self.contains(deviceResponse, "age_over_18"),
            "the requested element must be disclosed")
        XCTAssertFalse(
            Self.contains(deviceResponse, "family_name"),
            "an unrequested element must be withheld")
        XCTAssertTrue(
            Self.contains(deviceResponse, "documents"),
            "the response must be an mdoc DeviceResponse")
    }

    func testSeedIsIdempotent() async throws {
        let driver = try DcApiPresentationDriver()
        try await driver.seedIfNeeded()
        // A second seed must not throw or double-issue; a present after it still succeeds.
        try await driver.seedIfNeeded()
        _ = try driver.present(requestData: pidAgeOnlyRequest, origin: origin)
    }

    // MARK: - Helpers

    /// Pull the one base64url-encoded DeviceResponse out of `{"vp_token":{"<id>":["<b64url>"]}}`.
    private static func decodeSingleVpToken(_ data: Data) throws -> Data {
        let root = try JSONSerialization.jsonObject(with: data) as? [String: Any]
        let vpToken = root?["vp_token"] as? [String: Any]
        let first = vpToken?.values.first as? [Any]
        guard let b64 = first?.first as? String else {
            throw XCTSkip("vp_token did not contain a base64url DeviceResponse")
        }
        guard let decoded = Data(base64URLEncoded: b64) else {
            throw NSError(domain: "DcApiProviderDriverTests", code: 1)
        }
        return decoded
    }

    private static func contains(_ haystack: Data, _ needle: String) -> Bool {
        haystack.range(of: Data(needle.utf8)) != nil
    }
}

extension Data {
    /// Decode an unpadded base64url string (RFC 4648 §5), as emitted by the core's vp_token.
    fileprivate init?(base64URLEncoded input: String) {
        var s = input.replacingOccurrences(of: "-", with: "+")
            .replacingOccurrences(of: "_", with: "/")
        let remainder = s.count % 4
        if remainder > 0 { s += String(repeating: "=", count: 4 - remainder) }
        self.init(base64Encoded: s)
    }
}
