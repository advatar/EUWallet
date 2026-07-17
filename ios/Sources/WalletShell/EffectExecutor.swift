import Foundation

/// Drives the sans-IO Rust core: feed it a JSON event, decode the JSON effects it returns,
/// execute each, and feed any results back as new events — until the cascade drains.
/// This is the whole "shell" contract (plan Section 2/8). Device signing (`.sign`) goes to the
/// Secure Enclave; the private key never crosses the FFI.
public final class EffectExecutor {
    private let engine: WalletEngineDriving
    private let signer: Signer
    private let http: HttpClient
    private let storage: SecureStorage
    private let trust: TrustResolver
    private let render: (ScreenDescription) -> Void

    public init(
        engine: WalletEngineDriving,
        signer: Signer,
        http: HttpClient,
        storage: SecureStorage,
        trust: TrustResolver,
        render: @escaping (ScreenDescription) -> Void
    ) {
        self.engine = engine
        self.signer = signer
        self.http = http
        self.storage = storage
        self.trust = trust
        self.render = render
    }

    /// Send one JSON event and fully drain the resulting effect cascade.
    public func send(eventJson: String) async {
        var queue = decode(engine.handleEventJson(eventJson: eventJson))
        while !queue.isEmpty {
            let effect = queue.removeFirst()
            if let followUp = await execute(effect) {
                queue.append(contentsOf: decode(engine.handleEventJson(eventJson: followUp)))
            }
        }
    }

    private func decode(_ json: String) -> [WalletEffect] {
        guard let data = json.data(using: .utf8),
              let effects = try? JSONDecoder().decode([WalletEffect].self, from: data)
        else { return [] } // an `{"error":...}` object (or malformed) decodes to no effects
        return effects
    }

    /// Execute one effect; return a follow-up event (JSON) when it produces a result.
    private func execute(_ effect: WalletEffect) async -> String? {
        switch effect {
        case .render(let screen):
            render(screen)
            return nil
        case .sign(let keyRef, let payload):
            do {
                let sig = try signer.sign(keyRef: keyRef, payload: Data(payload))
                return WalletEventJSON.deviceSignatureProduced(sig)
            } catch {
                return WalletEventJSON.userDeclined() // e.g. biometric cancelled
            }
        case .http(let url, let body):
            _ = await http.post(url: url, body: Data(body))
            return WalletEventJSON.presentationDelivered()
        case .resolveRpTrust(let clientId):
            let t = await trust.resolve(clientId: clientId)
            return WalletEventJSON.rpCertChainResolved(chain: t.certChain, redirectUris: t.redirectUris)
        case .persistNonce(let nonce):
            try? storage.put(key: "nonce:\(nonce)", value: Data())
            return nil
        case .close:
            return nil
        }
    }
}

public protocol HttpClient {
    func post(url: String, body: Data) async -> (UInt16, Data)
}

public protocol SecureStorage {
    func put(key: String, value: Data) throws
    func get(key: String) throws -> Data?
}
