import CryptoKit
import DeviceCheck
import Foundation

/// App Attest for the PID-capture companion: registers this companion instance with VCIssuer (a
/// genuine, unmodified build on genuine Apple hardware) and signs a per-request assertion bound to
/// the exact evidence body it submits.
///
/// The companion is a distinct app bundle (`eu.advatar.wallet.pidcapture`), so it attests under its
/// OWN App Attest app id — VCIssuer accepts a list of app ids (wallet + companion). Runtime is
/// device-only: `DCAppAttestService` is unsupported in the Simulator, so registration and assertion
/// both no-op there (and the issuer only enforces the assertion when App Attest is configured).
public struct AppAttestAssertor: Sendable {
    public let issuerBaseURL: URL
    private let urlSession: URLSession
    private static let keyIdDefaultsKey = "appattest.capture.keyId"

    public init(issuerBaseURL: URL, urlSession: URLSession = .shared) {
        self.issuerBaseURL = issuerBaseURL
        self.urlSession = urlSession
    }

    private var service: DCAppAttestService { .shared }

    public var isSupported: Bool { service.isSupported }

    /// Generate a key once, attest it against a fresh VCIssuer challenge, and register the instance.
    /// Idempotent and best-effort; a no-op on the Simulator or when already registered.
    public func register() async throws {
        guard service.isSupported else { return }
        if UserDefaults.standard.string(forKey: Self.keyIdDefaultsKey) != nil { return }
        let keyId = try await service.generateKey()
        let challenge = try await fetchChallenge()
        let clientDataHash = Data(SHA256.hash(data: Data(challenge.utf8)))
        let attestation = try await service.attestKey(keyId, clientDataHash: clientDataHash)
        try await post(
            "v1/app-attest/register",
            body: [
                "key_id": keyId,
                "attestation": attestation.base64EncodedString(),
                "challenge": challenge,
            ])
        UserDefaults.standard.set(keyId, forKey: Self.keyIdDefaultsKey)
    }

    /// Headers binding a genuine app instance to `body` (the EXACT request bytes): an App Attest
    /// assertion over `SHA256(body)`, plus the keyId. Empty when unsupported or not registered — the
    /// request then proceeds without them (the issuer rejects it only when App Attest is configured).
    public func assertionHeaders(over body: Data) async -> [String: String] {
        guard service.isSupported,
              let keyId = UserDefaults.standard.string(forKey: Self.keyIdDefaultsKey)
        else { return [:] }
        let clientDataHash = Data(SHA256.hash(data: body))
        guard let assertion = try? await service.generateAssertion(keyId, clientDataHash: clientDataHash)
        else { return [:] }
        return [
            "x-app-attest-key-id": keyId,
            "x-app-attest-assertion": assertion.base64EncodedString(),
        ]
    }

    // MARK: - Networking

    private func fetchChallenge() async throws -> String {
        var request = URLRequest(
            url: issuerBaseURL.appendingPathComponent("v1/app-attest/challenge"))
        request.httpMethod = "POST"
        request.setValue("application/json", forHTTPHeaderField: "Accept")
        let (data, response) = try await urlSession.data(for: request)
        try Self.check(response, data)
        return try JSONDecoder().decode(ChallengeResponse.self, from: data).challenge
    }

    private func post(_ path: String, body: [String: String]) async throws {
        var request = URLRequest(url: issuerBaseURL.appendingPathComponent(path))
        request.httpMethod = "POST"
        request.setValue("application/json", forHTTPHeaderField: "Content-Type")
        request.httpBody = try JSONSerialization.data(withJSONObject: body)
        let (data, response) = try await urlSession.data(for: request)
        try Self.check(response, data)
    }

    private static func check(_ response: URLResponse, _ data: Data) throws {
        guard let http = response as? HTTPURLResponse else { return }
        guard (200..<300).contains(http.statusCode) else {
            throw NSError(
                domain: "AppAttestAssertor", code: http.statusCode,
                userInfo: [NSLocalizedDescriptionKey: String(data: data, encoding: .utf8) ?? ""])
        }
    }

    private struct ChallengeResponse: Decodable { let challenge: String }
}
