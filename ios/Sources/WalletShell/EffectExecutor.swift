import Foundation

/// Drives the sans-IO core: hand it an event, execute the returned effects, feed any
/// results back as new events. This is the whole "shell" contract (plan Section 2/8).
public final class EffectExecutor {
    private let core: WalletCore
    private let signer: Signer
    private let http: HttpClient
    private let storage: SecureStorage
    private let render: (ScreenDescription) -> Void

    public init(
        core: WalletCore,
        signer: Signer,
        http: HttpClient,
        storage: SecureStorage,
        render: @escaping (ScreenDescription) -> Void
    ) {
        self.core = core
        self.signer = signer
        self.http = http
        self.storage = storage
        self.render = render
    }

    /// Send one event and fully drain the resulting effect cascade.
    public func send(_ event: WalletEvent) async {
        var queue = core.handle(event)
        while !queue.isEmpty {
            let effect = queue.removeFirst()
            if let followUp = await execute(effect) {
                queue.append(contentsOf: core.handle(followUp))
            }
        }
    }

    /// Execute one effect. Returns a follow-up event when the effect produces a result.
    private func execute(_ effect: WalletEffect) async -> WalletEvent? {
        switch effect {
        case .render(let screen):
            render(screen)                     // never blocks the core
            return nil
        case .sign(let id, let keyRef, let payload):
            do {
                let sig = try signer.sign(keyRef: keyRef, payload: payload)
                return .signatureProduced(id: id, signature: sig)
            } catch {
                return .userDeclined            // e.g. biometric cancelled
            }
        case .http(let id, let url, let body):
            let (status, data) = await http.post(url: url, body: body)
            return .httpResponse(id: id, status: status, body: data)
        case .store(let key, let value):
            try? storage.put(key: key, value: value)
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
