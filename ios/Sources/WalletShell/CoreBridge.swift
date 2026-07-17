import Foundation

/// Skeleton mirror of the Rust core's public types. Section 3 of the implementation plan
/// replaces this file with the UniFFI-generated Swift bindings (same shapes).

public typealias EffectId = UInt64

/// Mirror of `presenter::ScreenDescription` (the closed screen vocabulary).
public enum ScreenDescription: Equatable {
    case loading
    case error(code: String, message: String)
    case consent(ConsentScreen)
    case credentialList
    case credentialDetail
    case issuanceOffer
    case presentQr
    case scanQr
    case authPrompt
    case transactionHistory
}

public struct ConsentScreen: Equatable {
    public let relyingPartyName: String
    public let purpose: String
    public let requestedClaims: [String]
    public init(relyingPartyName: String, purpose: String, requestedClaims: [String]) {
        self.relyingPartyName = relyingPartyName
        self.purpose = purpose
        self.requestedClaims = requestedClaims
    }
}

/// Mirror of `wallet_core::Event`.
public enum WalletEvent {
    case authorizationRequestReceived(Data)
    case userConsented
    case userDeclined
    case signatureProduced(id: EffectId, signature: Data)
    case httpResponse(id: EffectId, status: UInt16, body: Data)
}

/// Mirror of `wallet_core::Effect`.
public enum WalletEffect: Equatable {
    case render(ScreenDescription)
    case sign(id: EffectId, keyRef: String, payload: Data)
    case http(id: EffectId, url: String, body: Data)
    case store(key: String, value: Data)
}

/// Skeleton core. In production this is `WalletEngine` from UniFFI wrapping the Rust `Core`.
/// Here it implements just enough to exercise the shell end to end.
public final class WalletCore {
    private var nextId: EffectId = 0
    public init() {}

    public func handle(_ event: WalletEvent) -> [WalletEffect] {
        switch event {
        case .authorizationRequestReceived:
            let screen = ConsentScreen(
                relyingPartyName: "Example Relying Party",
                purpose: "Age verification",
                requestedClaims: ["age_over_18"]
            )
            return [.render(.consent(screen))]
        case .userConsented:
            nextId += 1
            return [.sign(id: nextId, keyRef: "device-key", payload: Data("vp_token".utf8))]
        case .userDeclined:
            return [.render(.error(code: "user_declined", message: "You declined the request."))]
        case .signatureProduced:
            nextId += 1
            return [.http(id: nextId, url: "https://rp.example/response", body: Data())]
        case .httpResponse:
            return [.render(.credentialList)]
        }
    }
}
