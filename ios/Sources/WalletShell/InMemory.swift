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
    public private(set) var posted: [(String, Data)] = []
    public init() {}
    public func post(url: String, body: Data) async -> (UInt16, Data) {
        posted.append((url, body))
        return (200, Data())
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

/// A fixed trust resolver for tests/previews.
public final class StubTrustResolver: TrustResolver {
    private let result: (Bool, Data, [String])
    public init(registered: Bool = true, rpPublicKey: Data = Data(), redirectUris: [String] = []) {
        self.result = (registered, rpPublicKey, redirectUris)
    }
    public func resolve(clientId: String) async -> (registered: Bool, rpPublicKey: Data, redirectUris: [String]) {
        result
    }
}
