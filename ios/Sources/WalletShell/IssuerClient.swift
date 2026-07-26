import CryptoKit
import Foundation
import Security

public enum IssuerClientError: Error, Equatable {
    case unsupportedFlow
    case invalidConfiguration
    case invalidResponse
    case invalidCallback
    case invalidState
    case httpStatus(Int)
}

@MainActor
public protocol IssuerAuthorizationPresenting: Sendable {
    func authorize(url: URL, callbackScheme: String) async throws -> URL
}

public struct LiveIssuerContext: Equatable {
    public let offer: Data
    public let issuer: String

    public init(offer: Data, issuer: String) {
        self.offer = offer
        self.issuer = issuer
    }
}

public protocol IssuerRequesting {
    func fetchCredentialOffer(uri: String) async throws -> HttpResponse
    func fetchIssuerMetadata(issuer: String) async throws -> HttpResponse
    func issuerRequest(
        url: String,
        method: String,
        body: Data?,
        headers: [String: String],
        maximumResponseBytes: Int
    ) async throws -> HttpResponse
}

extension URLSessionHttpClient: IssuerRequesting {}

/// One-use OpenID4VCI authorization-code client. Discovery values are admitted only when they
/// match the by-reference offer and the wallet's exact TLSNotary development policy.
public final class LiveIssuerClient: IssuerResponder {
    private enum Stage { case initial, parPending, parReady, authorizationPending, authorized,
        tokenPending, tokenReady, credentialPending, complete }
    public static let tlsnotaryConfiguration = "dev.advatar.tlsn.evidence.sd-jwt"
    public static let tlsnotaryVct = "dev.advatar.tlsn.evidence.1"
    private static let maximumProtocolResponseBytes = 256 * 1024

    private let transport: IssuerRequesting
    private let authorizer: IssuerAuthorizationPresenting
    private let signer: Signer
    private let keyReference: String
    private let publicKey: Data
    private let issuer: String
    private let offer: Data
    private let configurationId: String
    private let scope: String
    private let issuerState: String
    private let authorizationEndpoint: String
    private let parEndpoint: String
    private let tokenEndpoint: String
    private let nonceEndpoint: String
    private let credentialEndpoint: String
    private let clientId: String
    private let redirectUri: String
    private let callbackScheme: String
    private let verifier: String
    private let challenge: String
    private let state: String

    private var requestUri: String?
    private var authorizationCode: String?
    private var accessToken: String?
    private var credentialNonce: String?
    private var consumed = false
    private var stage = Stage.initial

    public static func discover(
        offerUri: String,
        clientId: String,
        redirectUri: String,
        keyReference: String,
        publicKey: Data,
        signer: Signer,
        transport: IssuerRequesting,
        authorizer: IssuerAuthorizationPresenting
    ) async throws -> LiveIssuerClient {
        let offerResponse = try await transport.fetchCredentialOffer(uri: offerUri)
        let offer = try json(offerResponse)
        guard let issuer = offer["credential_issuer"] as? String,
              let ids = offer["credential_configuration_ids"] as? [String],
              ids == [tlsnotaryConfiguration],
              let grants = offer["grants"] as? [String: Any],
              let authorizationCode = grants["authorization_code"] as? [String: Any],
              let issuerState = authorizationCode["issuer_state"] as? String,
              !issuerState.isEmpty
        else { throw IssuerClientError.invalidConfiguration }

        let issuerMetadata = try json(try await transport.fetchIssuerMetadata(issuer: issuer))
        guard issuerMetadata["credential_issuer"] as? String == issuer,
              let endpoint = issuerMetadata["credential_endpoint"] as? String,
              let nonce = issuerMetadata["nonce_endpoint"] as? String,
              let configs = issuerMetadata["credential_configurations_supported"]
                as? [String: Any],
              let config = configs[tlsnotaryConfiguration] as? [String: Any],
              config["format"] as? String == "dc+sd-jwt",
              config["vct"] as? String == tlsnotaryVct,
              let scope = config["scope"] as? String,
              scope == tlsnotaryConfiguration
        else { throw IssuerClientError.invalidConfiguration }

        let oauth = try json(try await transport.issuerRequest(
            url: issuer + "/.well-known/oauth-authorization-server",
            method: "GET", body: nil, headers: [:],
            maximumResponseBytes: URLSessionHttpClient.maximumMetadataBytes))
        guard oauth["issuer"] as? String == issuer,
              let authorizationEndpoint = oauth["authorization_endpoint"] as? String,
              let tokenEndpoint = oauth["token_endpoint"] as? String,
              let parEndpoint = oauth["pushed_authorization_request_endpoint"] as? String,
              (oauth["require_pushed_authorization_requests"] as? Bool) == true,
              sameOrigin(endpoint, issuer), sameOrigin(nonce, issuer),
              sameOrigin(authorizationEndpoint, issuer), sameOrigin(tokenEndpoint, issuer),
              sameOrigin(parEndpoint, issuer)
        else { throw IssuerClientError.invalidConfiguration }

        let verifier = randomBase64Url(count: 32)
        return try LiveIssuerClient(
            transport: transport, authorizer: authorizer, signer: signer,
            keyReference: keyReference, publicKey: publicKey, issuer: issuer, offer: offerResponse.body,
            configurationId: tlsnotaryConfiguration, scope: scope, issuerState: issuerState,
            authorizationEndpoint: authorizationEndpoint, parEndpoint: parEndpoint,
            tokenEndpoint: tokenEndpoint, nonceEndpoint: nonce, credentialEndpoint: endpoint,
            clientId: clientId, redirectUri: redirectUri,
            verifier: verifier, state: randomBase64Url(count: 24))
    }

    private init(
        transport: IssuerRequesting, authorizer: IssuerAuthorizationPresenting, signer: Signer,
        keyReference: String, publicKey: Data, issuer: String, offer: Data, configurationId: String,
        scope: String, issuerState: String, authorizationEndpoint: String, parEndpoint: String,
        tokenEndpoint: String, nonceEndpoint: String, credentialEndpoint: String, clientId: String,
        redirectUri: String, verifier: String, state: String
    ) throws {
        guard publicKey.count == 65, publicKey.first == 4,
              let callback = URL(string: redirectUri),
              let scheme = callback.scheme, !scheme.isEmpty
        else { throw IssuerClientError.invalidConfiguration }
        self.transport = transport
        self.authorizer = authorizer
        self.signer = signer
        self.keyReference = keyReference
        self.publicKey = publicKey
        self.issuer = issuer
        self.offer = offer
        self.configurationId = configurationId
        self.scope = scope
        self.issuerState = issuerState
        self.authorizationEndpoint = authorizationEndpoint
        self.parEndpoint = parEndpoint
        self.tokenEndpoint = tokenEndpoint
        self.nonceEndpoint = nonceEndpoint
        self.credentialEndpoint = credentialEndpoint
        self.clientId = clientId
        self.redirectUri = redirectUri
        self.callbackScheme = scheme
        self.verifier = verifier
        self.challenge = Self.base64url(Data(SHA256.hash(data: Data(verifier.utf8))))
        self.state = state
    }

    public func context() -> LiveIssuerContext {
        LiveIssuerContext(offer: offer, issuer: issuer)
    }

    public func pushAuthorizationRequest() async throws -> Bool {
        guard stage == .initial else {
            throw IssuerClientError.invalidState
        }
        stage = .parPending
        let response = try await formRequest(url: parEndpoint, fields: [
            "client_id": clientId, "redirect_uri": redirectUri, "response_type": "code",
            "scope": scope, "state": state, "code_challenge": challenge,
            "code_challenge_method": "S256", "issuer_state": issuerState,
        ])
        let object = try Self.json(response)
        guard let uri = object["request_uri"] as? String,
              uri.hasPrefix("urn:ietf:params:oauth:request_uri:"), !uri.isEmpty
        else { throw IssuerClientError.invalidResponse }
        requestUri = uri
        stage = .parReady
        return true
    }

    public func authorize() async throws -> Data {
        guard stage == .parReady, let requestUri else {
            throw IssuerClientError.invalidState
        }
        stage = .authorizationPending
        var components = URLComponents(string: authorizationEndpoint)
        components?.queryItems = [
            URLQueryItem(name: "client_id", value: clientId),
            URLQueryItem(name: "request_uri", value: requestUri),
        ]
        guard let url = components?.url else { throw IssuerClientError.invalidConfiguration }
        let callback = try await authorizer.authorize(url: url, callbackScheme: callbackScheme)
        guard Self.sameCallback(callback, redirectUri),
              let items = URLComponents(url: callback, resolvingAgainstBaseURL: false)?.queryItems,
              items.first(where: { $0.name == "state" })?.value == state,
              let code = items.first(where: { $0.name == "code" })?.value,
              !code.isEmpty
        else { throw IssuerClientError.invalidCallback }
        authorizationCode = code
        stage = .authorized
        return Data(code.utf8)
    }

    public func token() async throws -> (bound: Bool, cNonce: UInt64) {
        guard stage == .authorized, let authorizationCode else {
            throw IssuerClientError.invalidState
        }
        stage = .tokenPending
        let proof = try dpop(method: "POST", endpoint: tokenEndpoint, accessToken: nil)
        let response = try await formRequest(url: tokenEndpoint, fields: [
            "grant_type": "authorization_code", "code": authorizationCode,
            "redirect_uri": redirectUri, "client_id": clientId, "code_verifier": verifier,
        ], headers: ["DPoP": proof])
        let object = try Self.json(response)
        guard object["token_type"] as? String == "DPoP",
              let token = object["access_token"] as? String, !token.isEmpty
        else { throw IssuerClientError.invalidResponse }
        accessToken = token

        let nonceResponse = try await transport.issuerRequest(
            url: nonceEndpoint, method: "POST", body: Data(),
            headers: ["Accept": "application/json"],
            maximumResponseBytes: Self.maximumProtocolResponseBytes)
        let nonceObject = try Self.json(nonceResponse)
        guard let nonce = nonceObject["c_nonce"] as? String,
              let numericNonce = UInt64(nonce)
        else { throw IssuerClientError.invalidResponse }
        credentialNonce = nonce
        stage = .tokenReady
        return (true, numericNonce)
    }

    public func credential(proofJwt: Data) async throws -> (format: String, bytes: Data) {
        guard stage == .tokenReady, let token = accessToken, credentialNonce != nil, !consumed,
              let proof = String(data: proofJwt, encoding: .utf8), !proof.isEmpty
        else { throw IssuerClientError.invalidState }
        stage = .credentialPending
        let dpop = try dpop(method: "POST", endpoint: credentialEndpoint, accessToken: token)
        let body = try JSONSerialization.data(withJSONObject: [
            "credential_configuration_id": configurationId,
            "proofs": ["jwt": [proof]],
        ])
        let response = try await transport.issuerRequest(
            url: credentialEndpoint, method: "POST", body: body,
            headers: [
                "Authorization": "DPoP \(token)", "DPoP": dpop,
                "Content-Type": "application/json", "Accept": "application/json",
            ], maximumResponseBytes: Self.maximumProtocolResponseBytes)
        let object = try Self.json(response)
        guard let credentials = object["credentials"] as? [[String: Any]],
              credentials.count == 1,
              let compact = credentials[0]["credential"] as? String, !compact.isEmpty
        else { throw IssuerClientError.invalidResponse }
        consumed = true
        stage = .complete
        return ("dc+sd-jwt", Data(compact.utf8))
    }

    private func formRequest(
        url: String, fields: [String: String], headers: [String: String] = [:]
    ) async throws -> HttpResponse {
        let body = fields.sorted(by: { $0.key < $1.key }).map {
            "\(Self.form($0.key))=\(Self.form($0.value))"
        }.joined(separator: "&")
        var requestHeaders = headers
        requestHeaders["Content-Type"] = "application/x-www-form-urlencoded"
        requestHeaders["Accept"] = "application/json"
        return try await transport.issuerRequest(
            url: url, method: "POST", body: Data(body.utf8), headers: requestHeaders,
            maximumResponseBytes: Self.maximumProtocolResponseBytes)
    }

    private func dpop(method: String, endpoint: String, accessToken: String?) throws -> String {
        let header: [String: Any] = [
            "alg": "ES256", "typ": "dpop+jwt", "jwk": [
                "kty": "EC", "crv": "P-256",
                "x": Self.base64url(publicKey.subdata(in: 1..<33)),
                "y": Self.base64url(publicKey.subdata(in: 33..<65)),
            ],
        ]
        var payload: [String: Any] = [
            "htm": method, "htu": endpoint, "iat": Int(Date().timeIntervalSince1970),
            "jti": Self.randomBase64Url(count: 18),
        ]
        if let accessToken {
            payload["ath"] = Self.base64url(Data(SHA256.hash(data: Data(accessToken.utf8))))
        }
        let encodedHeader = Self.base64url(try JSONSerialization.data(withJSONObject: header))
        let encodedPayload = Self.base64url(try JSONSerialization.data(withJSONObject: payload))
        let input = "\(encodedHeader).\(encodedPayload)"
        let signature = try signer.sign(keyRef: keyReference, payload: Data(input.utf8))
        guard signature.count == 64 else { throw IssuerClientError.invalidResponse }
        return "\(input).\(Self.base64url(signature))"
    }

    private static func json(_ response: HttpResponse) throws -> [String: Any] {
        guard (200...299).contains(response.statusCode) else {
            throw IssuerClientError.httpStatus(Int(response.statusCode))
        }
        guard response.body.count <= maximumProtocolResponseBytes,
              let object = try JSONSerialization.jsonObject(with: response.body)
                as? [String: Any]
        else { throw IssuerClientError.invalidResponse }
        return object
    }

    private static func form(_ value: String) -> String {
        value.addingPercentEncoding(withAllowedCharacters: .alphanumerics) ?? ""
    }

    private static func sameOrigin(_ endpoint: String, _ issuer: String) -> Bool {
        guard let endpoint = URLComponents(string: endpoint),
              let issuer = URLComponents(string: issuer)
        else { return false }
        return endpoint.scheme == issuer.scheme && endpoint.host == issuer.host
            && (endpoint.port ?? 443) == (issuer.port ?? 443)
    }

    private static func sameCallback(_ callback: URL, _ redirectUri: String) -> Bool {
        guard var actual = URLComponents(url: callback, resolvingAgainstBaseURL: false),
              var expected = URLComponents(string: redirectUri)
        else { return false }
        actual.query = nil
        expected.query = nil
        return actual == expected
    }

    private static func base64url(_ data: Data) -> String {
        data.base64EncodedString()
            .replacingOccurrences(of: "+", with: "-")
            .replacingOccurrences(of: "/", with: "_")
            .replacingOccurrences(of: "=", with: "")
    }

    private static func randomBase64Url(count: Int) -> String {
        var bytes = [UInt8](repeating: 0, count: count)
        precondition(SecRandomCopyBytes(kSecRandomDefault, count, &bytes) == errSecSuccess)
        return base64url(Data(bytes))
    }
}
