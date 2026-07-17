import Foundation

/// The FFI contract with the Rust core. The generated UniFFI `WalletEngine`
/// (ios/Generated/wallet_core.swift, built into the WalletCore.xcframework) conforms to this
/// protocol as-is; a mock conforms for on-host tests. See docs/IMPLEMENTATION_PLAN.md Section 3.
public protocol WalletEngineDriving: AnyObject {
    /// Drive one event (JSON) → a JSON array of effects (or a `{"error":...}` object).
    func handleEventJson(eventJson: String) -> String
    /// Load a held credential: issuer JWT + JSON object mapping claim name → disclosure.
    func loadCredential(issuerJwt: String, disclosuresByClaimJson: String)
}

/// Mirror of `presenter::ScreenDescription` (internally tagged by `screen`).
public enum ScreenDescription: Decodable, Equatable {
    case loading
    case error(code: String, message: String)
    case consent(relyingPartyName: String, purpose: String, requestedClaims: [String])
    case paymentConfirmation(payee: String, amountMinor: UInt64, currency: String)
    case other(String)

    private enum CodingKeys: String, CodingKey {
        case screen, code, message, rpDisplayName, purpose, requestedClaims
        case payee, amountMinor, currency
    }

    public init(from decoder: Decoder) throws {
        let c = try decoder.container(keyedBy: CodingKeys.self)
        switch try c.decode(String.self, forKey: .screen) {
        case "loading": self = .loading
        case "error":
            self = .error(
                code: try c.decode(String.self, forKey: .code),
                message: try c.decode(String.self, forKey: .message))
        case "consent":
            self = .consent(
                relyingPartyName: try c.decode(String.self, forKey: .rpDisplayName),
                purpose: try c.decode(String.self, forKey: .purpose),
                requestedClaims: try c.decode([String].self, forKey: .requestedClaims))
        case "paymentConfirmation":
            self = .paymentConfirmation(
                payee: try c.decode(String.self, forKey: .payee),
                amountMinor: try c.decode(UInt64.self, forKey: .amountMinor),
                currency: try c.decode(String.self, forKey: .currency))
        case let other: self = .other(other)
        }
    }
}

/// Mirror of `wallet_core::Effect` (internally tagged by `type`, camelCase).
public enum WalletEffect: Decodable {
    case resolveRpTrust(clientId: String)
    case persistNonce(nonce: UInt64)
    case render(screen: ScreenDescription)
    case sign(keyRef: String, payload: [UInt8])
    case http(url: String, body: [UInt8])
    case close

    private enum CodingKeys: String, CodingKey {
        case type, clientId, nonce, screen, keyRef, payload, url, body
    }

    public init(from decoder: Decoder) throws {
        let c = try decoder.container(keyedBy: CodingKeys.self)
        switch try c.decode(String.self, forKey: .type) {
        case "resolveRpTrust":
            self = .resolveRpTrust(clientId: try c.decode(String.self, forKey: .clientId))
        case "persistNonce":
            self = .persistNonce(nonce: try c.decode(UInt64.self, forKey: .nonce))
        case "render":
            self = .render(screen: try c.decode(ScreenDescription.self, forKey: .screen))
        case "sign":
            self = .sign(
                keyRef: try c.decode(String.self, forKey: .keyRef),
                payload: try c.decode([UInt8].self, forKey: .payload))
        case "http":
            self = .http(
                url: try c.decode(String.self, forKey: .url),
                body: try c.decode([UInt8].self, forKey: .body))
        case "close": self = .close
        default: self = .close
        }
    }
}

/// Builders for the JSON events the shell feeds back to the core.
public enum WalletEventJSON {
    public static func setClock(epoch: Int64) -> String {
        #"{"type":"setClock","epoch":\#(epoch)}"#
    }
    public static func authorizationRequestReceived(_ request: Data) -> String {
        #"{"type":"authorizationRequestReceived","request":\#(byteArray(request))}"#
    }
    public static func rpTrustResolved(registered: Bool, rpPublicKey: Data, redirectUris: [String]) -> String {
        let uris = redirectUris.map { "\"\($0)\"" }.joined(separator: ",")
        return #"{"type":"rpTrustResolved","registered":\#(registered),"rpPublicKey":\#(byteArray(rpPublicKey)),"registeredRedirectUris":[\#(uris)]}"#
    }
    public static func userConsented() -> String { #"{"type":"userConsented"}"# }
    public static func userDeclined() -> String { #"{"type":"userDeclined"}"# }
    public static func deviceSignatureProduced(_ signature: Data) -> String {
        #"{"type":"deviceSignatureProduced","signature":\#(byteArray(signature))}"#
    }
    public static func presentationDelivered() -> String { #"{"type":"presentationDelivered"}"# }
    public static func paymentAuthorizationRequestReceived(_ request: Data) -> String {
        #"{"type":"paymentAuthorizationRequestReceived","request":\#(byteArray(request))}"#
    }
    public static func paymentApproved() -> String { #"{"type":"paymentApproved"}"# }
    public static func paymentDeclined() -> String { #"{"type":"paymentDeclined"}"# }

    private static func byteArray(_ data: Data) -> String {
        "[" + data.map { String($0) }.joined(separator: ",") + "]"
    }
}

/// Resolves an RP's registration + JWKS (network I/O; injected so it can be stubbed in tests).
public protocol TrustResolver {
    func resolve(clientId: String) async -> (registered: Bool, rpPublicKey: Data, redirectUris: [String])
}
