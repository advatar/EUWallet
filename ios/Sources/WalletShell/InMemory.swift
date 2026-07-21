import Foundation

/// Test/preview doubles. Production replaces these with URLSession + Keychain + a real
/// trusted-list resolver (plan Section 8).
public final class InMemoryStorage: SecureStorage {
    private var store: [String: Data] = [:]
    public init() {}
    public func put(key: String, value: Data) throws { store[key] = value }
    public func get(key: String) throws -> Data? { store[key] }
}

public final class StubHttpClient: HttpClient {
    public private(set) var posted: [(String, Data, HttpDeliveryProfile)] = []
    public init() {}
    public func post(
        url: String,
        body: Data,
        profile: HttpDeliveryProfile
    ) async throws -> HttpResponse {
        posted.append((url, body, profile))
        return HttpResponse(
            statusCode: 200,
            body: Data("{}".utf8),
            contentType: "application/json")
    }
}

public final class StubSigner: Signer {
    public private(set) var signedPayloads: [Data] = []
    private let signature: Data
    public init(signature: Data = Data("stub-signature".utf8)) { self.signature = signature }
    public func sign(keyRef: String, payload: Data) throws -> Data {
        signedPayloads.append(payload)
        return signature
    }
}

/// A fixed trust resolver for tests/previews (returns a canned RP certificate chain).
public final class StubTrustResolver: TrustResolver {
    private let chain: [Data]
    private let uris: [String]
    public init(certChain: [Data] = [], redirectUris: [String] = []) {
        self.chain = certChain
        self.uris = redirectUris
    }
    public func resolve(clientId: String) async -> (certChain: [Data], redirectUris: [String]) {
        (chain, uris)
    }
}
