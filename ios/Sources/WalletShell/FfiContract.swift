import Foundation

/// The FFI contract with the Rust core. The generated UniFFI `WalletEngine`
/// (ios/Generated/wallet_core.swift, built into the WalletCore.xcframework) conforms to this
/// protocol as-is; a mock conforms for on-host tests. See docs/IMPLEMENTATION_PLAN.md Section 3.
public protocol WalletEngineDriving: AnyObject {
    /// Drive one event (JSON) → a JSON array of effects (or a `{"error":...}` object).
    func handleEventJson(eventJson: String) -> String
}

/// Failures at the JSON boundary with the Rust core. A core error object and malformed output are
/// deliberately distinct: neither may be interpreted as an empty effect list.
public enum FfiContractError: Error, Equatable {
    case coreRejected(String)
    case malformedCoreOutput(String)
}

extension FfiContractError: LocalizedError {
    public var errorDescription: String? {
        switch self {
        case .coreRejected(let message):
            return "Wallet core rejected the event: \(message)"
        case .malformedCoreOutput(let reason):
            return "Wallet core returned malformed output: \(reason)"
        }
    }
}

/// Mirror of `presenter::ScreenDescription` (internally tagged by `screen`).
public enum ScreenDescription: Decodable, Equatable {
    case loading
    case error(code: String, message: String)
    case consent(relyingPartyName: String, purpose: String, requestedClaims: [String])
    case paymentConfirmation(creditorName: String, creditorAccount: String, amountMinor: UInt64, currency: String)
    case other(String)

    private enum CodingKeys: String, CodingKey {
        case screen, code, message, rpDisplayName, purpose, requestedClaims
        case creditorName, creditorAccount, amountMinor, currency
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
                creditorName: try c.decode(String.self, forKey: .creditorName),
                creditorAccount: try c.decode(String.self, forKey: .creditorAccount),
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
    // --- Issuance (OpenID4VCI) ---
    case pushPar
    case openAuthBrowser
    case promptTxCode
    case requestToken
    case requestCredential(proofJwt: [UInt8])
    // --- Credential status ---
    case fetchStatusList(uri: String)
    // --- Wallet-to-wallet (TS09) ---
    case publishTransferOffer(offeredKey: [UInt8])
    case close

    private enum CodingKeys: String, CodingKey {
        case type, clientId, nonce, screen, keyRef, payload, url, body, proofJwt, offeredKey
        case uri
    }

    private struct CoreErrorEnvelope: Decodable {
        let error: String
    }

    /// Decode the core's complete response. The response must be either an effect array or the
    /// documented `{ "error": "..." }` envelope; unknown effect types are malformed contract data.
    public static func decodeCoreOutput(_ json: String) throws -> [WalletEffect] {
        let data = Data(json.utf8)
        let decoder = JSONDecoder()
        if let envelope = try? decoder.decode(CoreErrorEnvelope.self, from: data) {
            throw FfiContractError.coreRejected(envelope.error)
        }
        do {
            return try decoder.decode([WalletEffect].self, from: data)
        } catch {
            throw FfiContractError.malformedCoreOutput(String(describing: error))
        }
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
        case "pushPar": self = .pushPar
        case "openAuthBrowser": self = .openAuthBrowser
        case "promptTxCode": self = .promptTxCode
        case "requestToken": self = .requestToken
        case "requestCredential":
            self = .requestCredential(proofJwt: try c.decode([UInt8].self, forKey: .proofJwt))
        case "fetchStatusList":
            self = .fetchStatusList(uri: try c.decode(String.self, forKey: .uri))
        case "publishTransferOffer":
            self = .publishTransferOffer(offeredKey: try c.decode([UInt8].self, forKey: .offeredKey))
        case "close": self = .close
        default:
            throw DecodingError.dataCorruptedError(
                forKey: .type,
                in: c,
                debugDescription: "Unknown wallet effect type")
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
    public static func rpCertChainResolved(chain: [Data], redirectUris: [String]) -> String {
        let certs = chain.map { byteArray($0) }.joined(separator: ",")
        let uris = redirectUris.map { "\"\($0)\"" }.joined(separator: ",")
        return #"{"type":"rpCertChainResolved","rpCertChain":[\#(certs)],"registeredRedirectUris":[\#(uris)]}"#
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

    // --- Issuance (OpenID4VCI) ---
    public static func credentialOfferReceived(
        offer: Data, issuerCertChain: [Data], issuerId: String
    ) -> String {
        let chain = issuerCertChain.map { byteArray($0) }.joined(separator: ",")
        return #"{"type":"credentialOfferReceived","offer":\#(byteArray(offer)),"issuerCertChain":[\#(chain)],"issuerId":\#(jsonString(issuerId))}"#
    }
    public static func tokenReceived(bound: Bool, cNonce: UInt64) -> String {
        #"{"type":"tokenReceived","bound":\#(bound),"cNonce":\#(cNonce)}"#
    }
    public static func credentialReceived(format: String, bytes: Data) -> String {
        #"{"type":"credentialReceived","format":\#(jsonString(format)),"bytes":\#(byteArray(bytes))}"#
    }
    public static func statusListReceived(
        uri: String,
        httpStatus: UInt16,
        token: Data,
        providerCertChain: [Data]
    ) -> String {
        let chain = providerCertChain.map { byteArray($0) }.joined(separator: ",")
        return #"{"type":"statusListReceived","uri":\#(jsonString(uri)),"httpStatus":\#(httpStatus),"token":\#(byteArray(token)),"providerCertChain":[\#(chain)]}"#
    }

    private static func byteArray(_ data: Data) -> String {
        "[" + data.map { String($0) }.joined(separator: ",") + "]"
    }

    /// JSON-encode a string (quotes + escapes) so issuer ids / formats are always well-formed.
    private static func jsonString(_ s: String) -> String {
        let data = (try? JSONEncoder().encode(s)) ?? Data("\"\"".utf8)
        return String(data: data, encoding: .utf8) ?? "\"\""
    }
}

/// Answers the (stubbed here) OpenID4VCI issuer endpoints the core drives via `RequestToken` /
/// `RequestCredential`. A production shell POSTs these over TLS; the demo returns an issuer-signed
/// credential in-process. The core still runs the whole issuance machine either way.
public protocol IssuerResponder {
    /// The `/token` response: whether the token is sender-bound, and a fresh `c_nonce`.
    func token() async throws -> (bound: Bool, cNonce: UInt64)
    /// The `/credential` response for the assembled proof: the format + credential bytes.
    func credential(proofJwt: Data) async throws -> (format: String, bytes: Data)
}

/// Fetches an RP's certificate chain (network I/O; injected so it can be stubbed in tests). The
/// registration DECISION is made in the Rust core against the trusted list — not here.
public protocol TrustResolver {
    func resolve(clientId: String) async -> (certChain: [Data], redirectUris: [String])
}

public struct StatusListResolution: Equatable {
    public let response: HttpResponse
    public let providerCertChain: [Data]

    public init(response: HttpResponse, providerCertChain: [Data]) {
        self.response = response
        self.providerCertChain = providerCertChain
    }
}

/// Fetches a Status List Token and resolves its signer's certificate path from authenticated EUDI
/// trust metadata. Rust independently validates the path, exact URI binding, signature and age.
public protocol StatusListResolver {
    func fetch(uri: String) async throws -> StatusListResolution
}
