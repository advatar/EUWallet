import CryptoKit
import DeviceCheck
import Foundation

/// Apple App Attest client: registers this app instance with VCIssuer (proving a genuine, unmodified
/// build on genuine Apple hardware) and signs per-request assertions.
///
/// Runtime is device-only — `DCAppAttestService` is unsupported in the Simulator, so `register()`
/// no-ops there. The keyId (an identifier, not secret; the private key lives in the Secure Enclave)
/// is persisted so the instance is registered once. Verified server-side by VCIssuer's
/// `/v1/app-attest/*` endpoints (see issuer-service `app_attest.rs`).
struct AppAttestClient {
    let issuerBaseURL: URL
    private let service = DCAppAttestService.shared
    private let urlSession: URLSession
    private static let keyIdDefaultsKey = "appattest.keyId"

    init(issuerBaseURL: URL, urlSession: URLSession = .shared) {
        self.issuerBaseURL = issuerBaseURL
        self.urlSession = urlSession
    }

    enum AppAttestError: LocalizedError {
        case unsupported
        case http(status: Int, body: String)

        var errorDescription: String? {
            switch self {
            case .unsupported: return "App Attest is not supported on this device."
            case let .http(status, body): return "App Attest server error \(status): \(body)"
            }
        }
    }

    var isSupported: Bool { service.isSupported }

    /// Whether this instance has already registered a key.
    var isRegistered: Bool { UserDefaults.standard.string(forKey: Self.keyIdDefaultsKey) != nil }

    /// Generate a key (once), attest it against a fresh VCIssuer challenge, and register the
    /// instance. Idempotent and best-effort; a no-op on the Simulator.
    func register() async throws {
        guard service.isSupported else { throw AppAttestError.unsupported }
        if isRegistered { return }

        let keyId = try await service.generateKey()
        let challenge = try await fetchChallenge()
        // Apple binds the challenge via nonce = SHA256(authData || SHA256(clientData)); clientData is
        // the challenge string bytes, matching the issuer's verification.
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

    /// Prove a genuine app instance made this call by asserting over `clientData` (e.g. the request
    /// body). Sends the assertion to VCIssuer, which verifies it and advances the replay counter.
    func assert(clientData: Data) async throws {
        guard let keyId = UserDefaults.standard.string(forKey: Self.keyIdDefaultsKey) else {
            throw AppAttestError.unsupported
        }
        let clientDataHash = Data(SHA256.hash(data: clientData))
        let assertion = try await service.generateAssertion(keyId, clientDataHash: clientDataHash)
        try await post(
            "v1/app-attest/assert",
            body: [
                "key_id": keyId,
                "assertion": assertion.base64EncodedString(),
                "client_data": clientData.base64EncodedString(),
            ])
    }

    // MARK: - Networking

    private func fetchChallenge() async throws -> String {
        var request = URLRequest(url: issuerBaseURL.appendingPathComponent("v1/app-attest/challenge"))
        request.httpMethod = "POST"
        request.setValue("application/json", forHTTPHeaderField: "Accept")
        let (data, response) = try await urlSession.data(for: request)
        try Self.check(response, data)
        let decoded = try JSONDecoder().decode(ChallengeResponse.self, from: data)
        return decoded.challenge
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
            throw AppAttestError.http(
                status: http.statusCode, body: String(data: data, encoding: .utf8) ?? "")
        }
    }

    private struct ChallengeResponse: Decodable { let challenge: String }
}
