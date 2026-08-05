import Foundation

/// Minimal target-wallet client for VCIssuer's PID-capture endpoints. This test wallet only plays the
/// *receiving* wallet: it creates a session bound to its own public key, then polls for the issued PID.
/// It never captures (that's the PIDCapture companion), so it stays dependency-free — no CaptureKit,
/// no iProov/ChipmunkNFC SDKs.
struct CaptureClient {
    let issuerBaseURL: URL
    var urlSession: URLSession = .shared

    struct CreateResult: Decodable {
        let sessionID: String
        let invocationURL: String
        let expiresIn: UInt64
        enum CodingKeys: String, CodingKey {
            case sessionID = "session_id"
            case invocationURL = "invocation_url"
            case expiresIn = "expires_in"
        }
    }

    struct Result: Decodable {
        let status: String
        let credential: String?
        let format: String?
        let deepLink: String?
        enum CodingKeys: String, CodingKey {
            case status, credential, format
            case deepLink = "deep_link"
        }
    }

    enum ClientError: LocalizedError {
        case http(Int, String)
        case decoding(String)
        var errorDescription: String? {
            switch self {
            case let .http(code, body): return "Issuer returned HTTP \(code): \(body)"
            case let .decoding(message): return "Could not read the issuer response: \(message)"
            }
        }
    }

    private func endpoint(_ last: String) -> URL {
        issuerBaseURL
            .appendingPathComponent("v1")
            .appendingPathComponent("pid-capture")
            .appendingPathComponent(last)
    }

    /// `POST /v1/pid-capture/session` — open a session bound to this wallet's public JWK.
    func createSession(holderJwk: [String: String]) async throws -> CreateResult {
        var request = URLRequest(url: endpoint("session"))
        request.httpMethod = "POST"
        request.setValue("application/json", forHTTPHeaderField: "Content-Type")
        request.setValue("application/json", forHTTPHeaderField: "Accept")
        request.httpBody = try JSONSerialization.data(withJSONObject: ["holder_jwk": holderJwk])
        return try await send(request)
    }

    /// `GET /v1/pid-capture/{id}` — poll for the issued PID (`status == "issued"`).
    func fetchResult(sessionID: String) async throws -> Result {
        var request = URLRequest(url: endpoint(sessionID))
        request.httpMethod = "GET"
        request.setValue("application/json", forHTTPHeaderField: "Accept")
        request.cachePolicy = .reloadIgnoringLocalCacheData
        return try await send(request)
    }

    private func send<T: Decodable>(_ request: URLRequest) async throws -> T {
        let (data, response) = try await urlSession.data(for: request)
        guard let http = response as? HTTPURLResponse else {
            throw ClientError.decoding("no HTTP response")
        }
        guard (200..<300).contains(http.statusCode) else {
            throw ClientError.http(http.statusCode, String(data: data, encoding: .utf8) ?? "<binary>")
        }
        do {
            return try JSONDecoder().decode(T.self, from: data)
        } catch {
            throw ClientError.decoding(error.localizedDescription)
        }
    }
}
