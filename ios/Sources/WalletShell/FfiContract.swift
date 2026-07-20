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
    case signConfirmation(documentName: String, qtspId: String, documentHashHex: String)
    case other(String)

    private enum CodingKeys: String, CodingKey {
        case screen, code, message, rpDisplayName, purpose, requestedClaims
        case creditorName, creditorAccount, amountMinor, currency
        case documentName, qtspId, documentHashHex
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
        case "signConfirmation":
            self = .signConfirmation(
                documentName: try c.decode(String.self, forKey: .documentName),
                qtspId: try c.decode(String.self, forKey: .qtspId),
                documentHashHex: try c.decode(String.self, forKey: .documentHashHex))
        case let other: self = .other(other)
        }
    }
}

/// The protocol decision represented by an interactive core-rendered screen. Keeping this routing
/// next to the wire builders prevents a QES authorization from being mislabeled as presentation
/// consent merely because all three screens share the same native buttons.
public enum WalletDecisionKind: Equatable {
    case presentation
    case payment
    case qes

    public init?(screen: ScreenDescription) {
        switch screen {
        case .consent: self = .presentation
        case .paymentConfirmation: self = .payment
        case .signConfirmation: self = .qes
        default: return nil
        }
    }

    public func approvalEvent(operationId: UInt64, authorizationHash: Data) -> String {
        switch self {
        case .presentation:
            return WalletEventJSON.userConsented(
                operationId: operationId,
                authorizationHash: authorizationHash)
        case .payment:
            return WalletEventJSON.paymentApproved(
                operationId: operationId,
                authorizationHash: authorizationHash)
        case .qes:
            return WalletEventJSON.qesAuthorized(
                operationId: operationId,
                authorizationHash: authorizationHash)
        }
    }

    public func declineEvent(operationId: UInt64) -> String {
        switch self {
        case .presentation: return WalletEventJSON.userDeclined(operationId: operationId)
        case .payment: return WalletEventJSON.paymentDeclined(operationId: operationId)
        case .qes: return WalletEventJSON.qesDeclined(operationId: operationId)
        }
    }
}

/// Mirror of `wallet_core::Effect` (internally tagged by `type`, camelCase).
public enum WalletEffect: Decodable {
    case resolveRpTrust(operationId: UInt64, clientId: String)
    case persistNonce(operationId: UInt64, nonce: UInt64)
    case render(operationId: UInt64?, authorizationHash: [UInt8]?, screen: ScreenDescription)
    case sign(operationId: UInt64, keyRef: String, payload: [UInt8])
    case http(
        operationId: UInt64,
        resultType: HttpResultType,
        profile: HttpDeliveryProfile,
        url: String,
        body: [UInt8])
    // --- Issuance (OpenID4VCI) ---
    case pushPar(operationId: UInt64)
    case openAuthBrowser(operationId: UInt64)
    case promptTxCode(operationId: UInt64)
    case requestToken(operationId: UInt64)
    case requestCredential(operationId: UInt64, proofJwt: [UInt8])
    // --- Credential status ---
    case fetchStatusList(operationId: UInt64, uri: String)
    // --- Wallet-to-wallet (TS09) ---
    case publishTransferOffer(operationId: UInt64, offeredKey: [UInt8])
    case close

    private enum CodingKeys: String, CodingKey {
        case type, clientId, nonce, screen, keyRef, payload, url, body, proofJwt, offeredKey
        case uri, operationId, resultType, profile, authorizationHash
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
            self = .resolveRpTrust(
                operationId: try c.decode(UInt64.self, forKey: .operationId),
                clientId: try c.decode(String.self, forKey: .clientId))
        case "persistNonce":
            self = .persistNonce(
                operationId: try c.decode(UInt64.self, forKey: .operationId),
                nonce: try c.decode(UInt64.self, forKey: .nonce))
        case "render":
            let screen = try c.decode(ScreenDescription.self, forKey: .screen)
            let operationId = try c.decodeIfPresent(UInt64.self, forKey: .operationId)
            let authorizationHash = try c.decodeIfPresent(
                [UInt8].self,
                forKey: .authorizationHash)
            switch screen {
            case .consent, .paymentConfirmation, .signConfirmation:
                guard operationId != nil, authorizationHash?.count == 32 else {
                    throw DecodingError.keyNotFound(
                        operationId == nil ? CodingKeys.operationId : CodingKeys.authorizationHash,
                        .init(
                            codingPath: c.codingPath,
                            debugDescription:
                                "Interactive render requires operationId and 32-byte authorizationHash"))
                }
            default:
                break
            }
            self = .render(
                operationId: operationId,
                authorizationHash: authorizationHash,
                screen: screen)
        case "sign":
            self = .sign(
                operationId: try c.decode(UInt64.self, forKey: .operationId),
                keyRef: try c.decode(String.self, forKey: .keyRef),
                payload: try c.decode([UInt8].self, forKey: .payload))
        case "http":
            let resultType = try c.decode(HttpResultType.self, forKey: .resultType)
            let profile = try c.decode(HttpDeliveryProfile.self, forKey: .profile)
            guard profile.resultType == resultType else {
                throw DecodingError.dataCorruptedError(
                    forKey: .profile,
                    in: c,
                    debugDescription: "HTTP delivery profile does not match resultType")
            }
            self = .http(
                operationId: try c.decode(UInt64.self, forKey: .operationId),
                resultType: resultType,
                profile: profile,
                url: try c.decode(String.self, forKey: .url),
                body: try c.decode([UInt8].self, forKey: .body))
        case "pushPar":
            self = .pushPar(operationId: try c.decode(UInt64.self, forKey: .operationId))
        case "openAuthBrowser":
            self = .openAuthBrowser(operationId: try c.decode(UInt64.self, forKey: .operationId))
        case "promptTxCode":
            self = .promptTxCode(operationId: try c.decode(UInt64.self, forKey: .operationId))
        case "requestToken":
            self = .requestToken(operationId: try c.decode(UInt64.self, forKey: .operationId))
        case "requestCredential":
            self = .requestCredential(
                operationId: try c.decode(UInt64.self, forKey: .operationId),
                proofJwt: try c.decode([UInt8].self, forKey: .proofJwt))
        case "fetchStatusList":
            self = .fetchStatusList(
                operationId: try c.decode(UInt64.self, forKey: .operationId),
                uri: try c.decode(String.self, forKey: .uri))
        case "publishTransferOffer":
            self = .publishTransferOffer(
                operationId: try c.decode(UInt64.self, forKey: .operationId),
                offeredKey: try c.decode([UInt8].self, forKey: .offeredKey))
        case "close": self = .close
        default:
            throw DecodingError.dataCorruptedError(
                forKey: .type,
                in: c,
                debugDescription: "Unknown wallet effect type")
        }
    }
}

public enum HttpResultType: String, Decodable, Equatable {
    case presentationDelivered
    case paymentAuthorizationDelivered
    case qesAuthorizationDelivered
}

/// Closed protocol-delivery discriminator emitted by the Rust core. It prevents opaque POST bytes
/// from being interpreted under a different protocol's success contract.
public enum HttpDeliveryProfile: String, Decodable, Equatable, Sendable {
    case openid4vpDirectPost
    case paymentAuthorization
    case qesAuthorization

    public var resultType: HttpResultType {
        switch self {
        case .openid4vpDirectPost: return .presentationDelivered
        case .paymentAuthorization: return .paymentAuthorizationDelivered
        case .qesAuthorization: return .qesAuthorizationDelivered
        }
    }
}

public enum WalletOperationFailure: String {
    case trust
    case storage
    case signing
    case transport
    case httpStatus
    case issuer
    case status
    case rendering
    case missingDependency
    case unsupported
}

/// Builders for the JSON events the shell feeds back to the core.
public enum WalletEventJSON {
    public static func setClock(epoch: Int64) -> String {
        #"{"type":"setClock","epoch":\#(epoch)}"#
    }
    public static func authorizationRequestReceived(_ request: Data) -> String {
        #"{"type":"authorizationRequestReceived","request":\#(byteArray(request))}"#
    }
    public static func rpCertChainResolved(
        operationId: UInt64, chain: [Data], redirectUris: [String]
    ) -> String {
        let certs = chain.map { byteArray($0) }.joined(separator: ",")
        let uris = redirectUris.map(jsonString).joined(separator: ",")
        return #"{"type":"rpCertChainResolved","operationId":\#(operationId),"rpCertChain":[\#(certs)],"registeredRedirectUris":[\#(uris)]}"#
    }
    public static func userConsented(operationId: UInt64, authorizationHash: Data) -> String {
        #"{"type":"userConsented","operationId":\#(operationId),"authorizationHash":\#(byteArray(authorizationHash))}"#
    }
    public static func userDeclined(operationId: UInt64) -> String {
        #"{"type":"userDeclined","operationId":\#(operationId)}"#
    }
    public static func deviceSignatureProduced(operationId: UInt64, signature: Data) -> String {
        #"{"type":"deviceSignatureProduced","operationId":\#(operationId),"signature":\#(byteArray(signature))}"#
    }
    public static func presentationDelivered(operationId: UInt64) -> String {
        #"{"type":"presentationDelivered","operationId":\#(operationId)}"#
    }
    public static func paymentAuthorizationDelivered(operationId: UInt64) -> String {
        #"{"type":"paymentAuthorizationDelivered","operationId":\#(operationId)}"#
    }
    public static func qesAuthorizationDelivered(operationId: UInt64) -> String {
        #"{"type":"qesAuthorizationDelivered","operationId":\#(operationId)}"#
    }
    public static func paymentAuthorizationRequestReceived(_ request: Data) -> String {
        #"{"type":"paymentAuthorizationRequestReceived","request":\#(byteArray(request))}"#
    }
    public static func paymentApproved(operationId: UInt64, authorizationHash: Data) -> String {
        #"{"type":"paymentApproved","operationId":\#(operationId),"authorizationHash":\#(byteArray(authorizationHash))}"#
    }
    public static func paymentDeclined(operationId: UInt64) -> String {
        #"{"type":"paymentDeclined","operationId":\#(operationId)}"#
    }
    public static func qesAuthorized(operationId: UInt64, authorizationHash: Data) -> String {
        #"{"type":"qesAuthorized","operationId":\#(operationId),"authorizationHash":\#(byteArray(authorizationHash))}"#
    }
    public static func qesDeclined(operationId: UInt64) -> String {
        #"{"type":"qesDeclined","operationId":\#(operationId)}"#
    }

    // --- Issuance (OpenID4VCI) ---
    public static func credentialOfferReceived(
        offer: Data, issuerCertChain: [Data], issuerId: String
    ) -> String {
        let chain = issuerCertChain.map { byteArray($0) }.joined(separator: ",")
        return #"{"type":"credentialOfferReceived","offer":\#(byteArray(offer)),"issuerCertChain":[\#(chain)],"issuerId":\#(jsonString(issuerId))}"#
    }
    public static func parPushed(operationId: UInt64, pkceS256: Bool) -> String {
        #"{"type":"parPushed","operationId":\#(operationId),"pkceS256":\#(pkceS256)}"#
    }
    public static func authorizationCodeReturned(operationId: UInt64, code: Data) -> String {
        #"{"type":"authorizationCodeReturned","operationId":\#(operationId),"code":\#(byteArray(code))}"#
    }
    public static func transactionCodeEntered(operationId: UInt64, code: Data) -> String {
        #"{"type":"transactionCodeEntered","operationId":\#(operationId),"code":\#(byteArray(code))}"#
    }
    public static func tokenReceived(operationId: UInt64, bound: Bool, cNonce: UInt64) -> String {
        #"{"type":"tokenReceived","operationId":\#(operationId),"bound":\#(bound),"cNonce":\#(cNonce)}"#
    }
    public static func credentialReceived(
        operationId: UInt64, format: String, bytes: Data
    ) -> String {
        #"{"type":"credentialReceived","operationId":\#(operationId),"format":\#(jsonString(format)),"bytes":\#(byteArray(bytes))}"#
    }
    public static func statusListReceived(
        operationId: UInt64,
        uri: String,
        httpStatus: UInt16,
        token: Data,
        providerCertChain: [Data]
    ) -> String {
        let chain = providerCertChain.map { byteArray($0) }.joined(separator: ",")
        return #"{"type":"statusListReceived","operationId":\#(operationId),"uri":\#(jsonString(uri)),"httpStatus":\#(httpStatus),"token":\#(byteArray(token)),"providerCertChain":[\#(chain)]}"#
    }

    public static func operationSucceeded(operationId: UInt64) -> String {
        #"{"type":"operationSucceeded","operationId":\#(operationId)}"#
    }

    public static func operationFailed(
        operationId: UInt64, failure: WalletOperationFailure
    ) -> String {
        #"{"type":"operationFailed","operationId":\#(operationId),"failure":"\#(failure.rawValue)"}"#
    }

    public static func operationCancelled(operationId: UInt64) -> String {
        #"{"type":"operationCancelled","operationId":\#(operationId)}"#
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
    func resolve(clientId: String) async throws -> (certChain: [Data], redirectUris: [String])
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
