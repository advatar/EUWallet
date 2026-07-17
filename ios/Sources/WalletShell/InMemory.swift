import Foundation

/// Test/preview doubles. Production replaces these with URLSession + Keychain (plan Section 8).
public final class InMemoryStorage: SecureStorage {
    private var store: [String: Data] = [:]
    public init() {}
    public func put(key: String, value: Data) throws { store[key] = value }
    public func get(key: String) throws -> Data? { store[key] }
}

public final class StubHttpClient: HttpClient {
    public init() {}
    public func post(url: String, body: Data) async -> (UInt16, Data) { (200, Data()) }
}

public final class StubSigner: Signer {
    public init() {}
    public func sign(keyRef: String, payload: Data) throws -> Data { Data("stub-signature".utf8) }
}
