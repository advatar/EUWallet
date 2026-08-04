import Foundation

/// Client for VCIssuer's cross-wallet PID capture endpoints (`/v1/pid-capture/*`).
///
/// The companion is launched by scanning a QR whose invocation URL carries only the session id.
/// It then:
///   1. `fetchParameters` — GET the session to learn the attestation-binding nonce and the iProov
///      launch parameters (token + streaming URL + assurance).
///   2. reads the eMRTD chip + runs the iProov capture with those parameters.
///   3. `submitEvidence` — POST the trusted-reader attestation; VCIssuer validates liveness itself
///      (authoritative), verifies the chip attestation, runs its Lean-proved gate, and mints the PID
///      bound to the target wallet's key.
public struct CaptureSessionClient: Sendable {
    public let issuerBaseURL: URL
    private let urlSession: URLSession

    public init(issuerBaseURL: URL, urlSession: URLSession = .shared) {
        self.issuerBaseURL = issuerBaseURL
        self.urlSession = urlSession
    }

    public enum CaptureError: LocalizedError {
        case invalidInvocationURL
        case http(status: Int, body: String)
        case decoding(String)

        public var errorDescription: String? {
            switch self {
            case .invalidInvocationURL:
                return "The capture link did not contain a session id."
            case let .http(status, body):
                return "Capture server returned HTTP \(status): \(body)"
            case let .decoding(message):
                return "Could not read the capture server response: \(message)"
            }
        }
    }

    /// Session lifecycle mirrored from the server's `CaptureStatus`.
    public enum Status: String, Sendable, Decodable {
        case awaitingEvidence = "awaiting_evidence"
        case issued
        case failed
    }

    /// What the companion needs to run a capture, returned by `GET /v1/pid-capture/{id}` while the
    /// session is awaiting evidence.
    public struct CaptureParameters: Sendable, Decodable {
        public let status: Status
        public let nonce: String?
        /// Target wallet key thumbprint the reader must weld the attestation to.
        public let holderJkt: String?
        /// Issuer origin the attestation's `aud` must equal.
        public let audience: String?
        public let iproovToken: String?
        public let iproovStreamingURL: String?
        public let iproovAssuranceType: String?

        enum CodingKeys: String, CodingKey {
            case status
            case nonce
            case holderJkt = "holder_jkt"
            case audience
            case iproovToken = "iproov_token"
            case iproovStreamingURL = "iproov_streaming_url"
            case iproovAssuranceType = "iproov_assurance_type"
        }
    }

    /// The issuance outcome from `POST /v1/pid-capture/{id}/evidence` (and from a later poll).
    public struct IssuanceResult: Sendable, Decodable {
        public let status: Status
        public let credential: String?
        public let format: String?
    }

    /// Extract the `session` query item from a companion invocation URL
    /// (`https://issuer.example/pid-capture?session=<id>`). Pure + unit-testable.
    public static func sessionID(fromInvocation url: URL) -> String? {
        guard
            let components = URLComponents(url: url, resolvingAgainstBaseURL: false),
            let session = components.queryItems?.first(where: { $0.name == "session" })?.value,
            !session.isEmpty
        else {
            return nil
        }
        return session
    }

    private func sessionURL(_ sessionID: String, suffix: String = "") -> URL {
        issuerBaseURL
            .appendingPathComponent("v1")
            .appendingPathComponent("pid-capture")
            .appendingPathComponent(sessionID + suffix)
    }

    /// GET the capture parameters for a session.
    public func fetchParameters(sessionID: String) async throws -> CaptureParameters {
        var request = URLRequest(url: sessionURL(sessionID))
        request.httpMethod = "GET"
        request.setValue("application/json", forHTTPHeaderField: "Accept")
        return try await send(request)
    }

    /// POST the trusted-reader eMRTD attestation for a session → the issuance result.
    ///
    /// When `appAttestor` is supplied (device only), a per-request App Attest assertion is computed
    /// over the EXACT body bytes and attached as `x-app-attest-*` headers, so VCIssuer can bind this
    /// mint request to a genuine, registered companion instance. The body is serialized once and both
    /// hashed and sent, so the client-signed and server-verified bytes are identical.
    public func submitEvidence(
        sessionID: String,
        attestation: String,
        clientIP: String? = nil,
        appAttestor: AppAttestAssertor? = nil
    ) async throws -> IssuanceResult {
        var body: [String: String] = ["attestation": attestation]
        if let clientIP { body["client_ip"] = clientIP }
        let bodyData = try JSONSerialization.data(withJSONObject: body)

        var request = URLRequest(url: sessionURL(sessionID, suffix: "/evidence"))
        request.httpMethod = "POST"
        request.setValue("application/json", forHTTPHeaderField: "Content-Type")
        request.setValue("application/json", forHTTPHeaderField: "Accept")
        if let appAttestor {
            for (field, value) in await appAttestor.assertionHeaders(over: bodyData) {
                request.setValue(value, forHTTPHeaderField: field)
            }
        }
        request.httpBody = bodyData
        return try await send(request)
    }

    private func send<T: Decodable>(_ request: URLRequest) async throws -> T {
        let (data, response) = try await urlSession.data(for: request)
        guard let http = response as? HTTPURLResponse else {
            throw CaptureError.decoding("no HTTP response")
        }
        guard (200..<300).contains(http.statusCode) else {
            throw CaptureError.http(
                status: http.statusCode,
                body: String(data: data, encoding: .utf8) ?? "<binary>"
            )
        }
        do {
            return try JSONDecoder().decode(T.self, from: data)
        } catch {
            throw CaptureError.decoding(error.localizedDescription)
        }
    }
}
