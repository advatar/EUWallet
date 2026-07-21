import Foundation

public struct HttpResponse: Equatable {
    public let statusCode: UInt16
    public let body: Data
    public let contentType: String?

    public init(statusCode: UInt16, body: Data, contentType: String? = nil) {
        self.statusCode = statusCode
        self.body = body
        self.contentType = contentType
    }
}

public enum HttpClientError: Error, Equatable {
    case invalidUrl(String)
    case unsafeDestination(String)
    case nonHttpResponse
    case responseTooLarge(limit: Int)
    case redirectRejected(location: String?)
    case unacceptableContentType(expected: [String], actual: String?)
    case transport(String)
}

extension HttpClientError: LocalizedError {
    public var errorDescription: String? {
        switch self {
        case .invalidUrl(let url): return "Invalid HTTP URL: \(url)"
        case .unsafeDestination(let host): return "Unsafe network destination: \(host)"
        case .nonHttpResponse: return "Transport returned a non-HTTP response"
        case .responseTooLarge(let limit):
            return "HTTP response exceeded the \(limit)-byte limit"
        case .redirectRejected(let location):
            return "HTTP redirect was rejected\(location.map { ": \($0)" } ?? "")"
        case .unacceptableContentType(let expected, let actual):
            return "Unexpected HTTP content type \(actual ?? "<missing>"); expected \(expected.joined(separator: ", "))"
        case .transport(let message): return "HTTP transport failed: \(message)"
        }
    }
}

/// A stopped effect cascade. Infrastructure failures are never translated into semantic wallet
/// events such as `userDeclined` or `presentationDelivered`.
public enum EffectExecutorError: Error, Equatable {
    case ffi(FfiContractError)
    case signingFailed(String)
    case storageFailed(String)
    case transportFailed(HttpClientError)
    case httpStatusFailed(statusCode: UInt16, body: Data)
    case missingDependency(String)
    case issuerFailed(String)
    case renderingFailed(String)
    case unsupportedEffect(String)
    case effectCascadeLimitExceeded(Int)
}

extension EffectExecutorError: LocalizedError {
    public var errorDescription: String? {
        switch self {
        case .ffi(let error): return error.localizedDescription
        case .signingFailed(let reason): return "Device signing failed: \(reason)"
        case .storageFailed(let reason): return "Secure storage failed: \(reason)"
        case .transportFailed(let error): return error.localizedDescription
        case .httpStatusFailed(let statusCode, _):
            return "Wallet delivery failed with HTTP status \(statusCode)"
        case .missingDependency(let dependency):
            return "Wallet flow is missing required dependency: \(dependency)"
        case .issuerFailed(let reason): return "Credential issuer request failed: \(reason)"
        case .renderingFailed(let reason): return "Wallet screen rendering failed: \(reason)"
        case .unsupportedEffect(let effect):
            return "Wallet shell does not implement required effect: \(effect)"
        case .effectCascadeLimitExceeded(let limit):
            return "Wallet core effect cascade exceeded the \(limit)-effect safety limit"
        }
    }
}

public enum EffectAbortReason: Equatable {
    case coreError(code: String, message: String)
    case closedWithoutSuccess
    case missingTerminalOutcome
    case effectAfterClose

    public var message: String {
        switch self {
        case .coreError(_, let message): return message
        case .closedWithoutSuccess:
            return "Wallet flow closed without a protocol acknowledgement"
        case .missingTerminalOutcome:
            return "Wallet flow produced no terminal outcome"
        case .effectAfterClose:
            return "Wallet core emitted an effect after closing the flow"
        }
    }
}

/// Semantic result of one fully drained effect cascade. Queue exhaustion itself is never success.
public enum EffectCascadeOutcome: Equatable {
    case idle
    case awaitingInput
    case succeeded
    case declined
    case aborted(EffectAbortReason)
}

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
    private let statusLists: StatusListResolver?
    private let issuer: IssuerResponder?
    private let transferOffers: TransferOfferPublisher?
    private let render: (UInt64?, Data?, ScreenDescription) throws -> Void

    public init(
        engine: WalletEngineDriving,
        signer: Signer,
        http: HttpClient,
        storage: SecureStorage,
        trust: TrustResolver,
        statusLists: StatusListResolver? = nil,
        issuer: IssuerResponder? = nil,
        transferOffers: TransferOfferPublisher? = nil,
        render: @escaping (UInt64?, Data?, ScreenDescription) throws -> Void
    ) {
        self.engine = engine
        self.signer = signer
        self.http = http
        self.storage = storage
        self.trust = trust
        self.statusLists = statusLists
        self.issuer = issuer
        self.transferOffers = transferOffers
        self.render = render
    }

    /// Send one JSON event and fully drain the resulting effect cascade.
    @discardableResult
    public func send(eventJson: String) async throws -> EffectCascadeOutcome {
        var queue = try decode(engine.handleEventJson(eventJson: eventJson))
        let initialEventType = Self.eventType(eventJson)
        var acknowledged = false
        var renderedInput = false
        var awaitingExternalInput = false
        var abortReason: EffectAbortReason?
        var closed = false
        var executedEffects = 0

        while !queue.isEmpty {
            executedEffects += 1
            guard executedEffects <= Self.maximumEffectsPerCascade else {
                throw EffectExecutorError.effectCascadeLimitExceeded(
                    Self.maximumEffectsPerCascade)
            }
            let effect = queue.removeFirst()
            if closed {
                return .aborted(.effectAfterClose)
            }
            switch effect {
            case .render(_, _, .error(let code, let message)):
                abortReason = .coreError(code: code, message: message)
            case .render:
                renderedInput = true
            case .close:
                closed = true
            default:
                break
            }
            if let followUp = try await execute(effect) {
                let followUpType = Self.eventType(followUp)
                switch followUpType {
                case "presentationDelivered", "paymentAuthorizationDelivered",
                     "qesAuthorizationDelivered", "credentialReceived":
                    acknowledged = true
                default:
                    break
                }
                if case .publishTransferOffer = effect,
                   followUpType == "operationSucceeded" {
                    awaitingExternalInput = true
                }
                queue.append(contentsOf: try decode(engine.handleEventJson(eventJson: followUp)))
            }
        }

        if let abortReason {
            return .aborted(abortReason)
        }
        if closed {
            if Self.declineEventTypes.contains(initialEventType ?? "") {
                return .declined
            }
            return acknowledged ? .succeeded : .aborted(.closedWithoutSuccess)
        }
        if renderedInput || awaitingExternalInput {
            return .awaitingInput
        }
        if Self.idleEventTypes.contains(initialEventType ?? "") {
            return .idle
        }
        return .aborted(.missingTerminalOutcome)
    }

    private static func eventType(_ json: String) -> String? {
        guard let object = try? JSONSerialization.jsonObject(with: Data(json.utf8)),
              let dictionary = object as? [String: Any]
        else { return nil }
        return dictionary["type"] as? String
    }

    private func decode(_ json: String) throws -> [WalletEffect] {
        do {
            return try WalletEffect.decodeCoreOutput(json)
        } catch let error as FfiContractError {
            throw EffectExecutorError.ffi(error)
        } catch {
            // `decodeCoreOutput` normalizes decoding failures, but remain fail-closed if that
            // implementation changes.
            throw EffectExecutorError.ffi(.malformedCoreOutput(String(describing: error)))
        }
    }

    /// Execute one effect; return a follow-up event (JSON) when it produces a result.
    private func execute(_ effect: WalletEffect) async throws -> String? {
        switch effect {
        case .render(let operationId, let authorizationHash, let screen):
            do {
                try render(operationId, authorizationHash.map { Data($0) }, screen)
                return nil
            } catch is CancellationError {
                guard let operationId else { throw CancellationError() }
                return WalletEventJSON.operationCancelled(operationId: operationId)
            } catch {
                guard let operationId else {
                    throw EffectExecutorError.renderingFailed(String(describing: error))
                }
                return WalletEventJSON.operationFailed(
                    operationId: operationId, failure: .rendering)
            }
        case .sign(let operationId, let keyRef, let payload):
            do {
                let sig = try signer.sign(keyRef: keyRef, payload: Data(payload))
                return WalletEventJSON.deviceSignatureProduced(
                    operationId: operationId, signature: sig)
            } catch is CancellationError {
                return WalletEventJSON.operationCancelled(operationId: operationId)
            } catch {
                return WalletEventJSON.operationFailed(
                    operationId: operationId, failure: .signing)
            }
        case .http(let operationId, let resultType, let url, let body):
            let response: HttpResponse
            do {
                response = try await http.post(url: url, body: Data(body))
            } catch is CancellationError {
                return WalletEventJSON.operationCancelled(operationId: operationId)
            } catch {
                return WalletEventJSON.operationFailed(
                    operationId: operationId, failure: .transport)
            }
            guard (200...299).contains(response.statusCode) else {
                return WalletEventJSON.operationFailed(
                    operationId: operationId, failure: .httpStatus)
            }
            switch resultType {
            case .presentationDelivered:
                return WalletEventJSON.presentationDelivered(operationId: operationId)
            case .paymentAuthorizationDelivered:
                return WalletEventJSON.paymentAuthorizationDelivered(operationId: operationId)
            case .qesAuthorizationDelivered:
                return WalletEventJSON.qesAuthorizationDelivered(operationId: operationId)
            }
        case .resolveRpTrust(let operationId, let clientId):
            do {
                let t = try await trust.resolve(clientId: clientId)
                return WalletEventJSON.rpCertChainResolved(
                    operationId: operationId,
                    chain: t.certChain,
                    redirectUris: t.redirectUris)
            } catch is CancellationError {
                return WalletEventJSON.operationCancelled(operationId: operationId)
            } catch {
                return WalletEventJSON.operationFailed(operationId: operationId, failure: .trust)
            }
        case .persistNonce(let operationId, let nonce):
            do {
                try storage.put(key: "nonce:\(nonce)", value: Data())
                return WalletEventJSON.operationSucceeded(operationId: operationId)
            } catch {
                return WalletEventJSON.operationFailed(operationId: operationId, failure: .storage)
            }
        // --- Issuance (OpenID4VCI). The demo's pre-authorized flow uses only token + credential;
        //     PAR / browser / tx-code are unreachable here and safely no-op. ---
        case .requestToken(let operationId):
            guard let issuer else {
                return WalletEventJSON.operationFailed(
                    operationId: operationId, failure: .missingDependency)
            }
            do {
                let t = try await issuer.token()
                return WalletEventJSON.tokenReceived(
                    operationId: operationId, bound: t.bound, cNonce: t.cNonce)
            } catch is CancellationError {
                return WalletEventJSON.operationCancelled(operationId: operationId)
            } catch {
                return WalletEventJSON.operationFailed(operationId: operationId, failure: .issuer)
            }
        case .requestCredential(let operationId, let proofJwt):
            guard let issuer else {
                return WalletEventJSON.operationFailed(
                    operationId: operationId, failure: .missingDependency)
            }
            do {
                let c = try await issuer.credential(proofJwt: Data(proofJwt))
                return WalletEventJSON.credentialReceived(
                    operationId: operationId, format: c.format, bytes: c.bytes)
            } catch is CancellationError {
                return WalletEventJSON.operationCancelled(operationId: operationId)
            } catch {
                return WalletEventJSON.operationFailed(operationId: operationId, failure: .issuer)
            }
        case .fetchStatusList(let operationId, let uri):
            guard let statusLists else {
                return WalletEventJSON.operationFailed(operationId: operationId, failure: .status)
            }
            do {
                let resolution = try await statusLists.fetch(uri: uri)
                return WalletEventJSON.statusListReceived(
                    operationId: operationId,
                    uri: uri,
                    httpStatus: resolution.response.statusCode,
                    token: resolution.response.body,
                    providerCertChain: resolution.providerCertChain)
            } catch is CancellationError {
                return WalletEventJSON.operationCancelled(operationId: operationId)
            } catch {
                return WalletEventJSON.operationFailed(operationId: operationId, failure: .status)
            }
        case .publishTransferOffer(let operationId, let offeredKey):
            guard let transferOffers else {
                return WalletEventJSON.operationFailed(
                    operationId: operationId, failure: .missingDependency)
            }
            do {
                try await transferOffers.publish(offeredKey: Data(offeredKey))
                return WalletEventJSON.operationSucceeded(operationId: operationId)
            } catch is CancellationError {
                return WalletEventJSON.operationCancelled(operationId: operationId)
            } catch {
                return WalletEventJSON.operationFailed(
                    operationId: operationId, failure: .transport)
            }
        case .pushPar(let operationId), .openAuthBrowser(let operationId),
             .promptTxCode(let operationId):
            return WalletEventJSON.operationFailed(
                operationId: operationId, failure: .unsupported)
        case .close:
            return nil
        }
    }

    private static let maximumEffectsPerCascade = 1_024
    private static let declineEventTypes: Set<String> = [
        "userDeclined", "paymentDeclined", "qesDeclined",
    ]
    private static let idleEventTypes: Set<String> = ["setClock"]
}

public protocol HttpClient {
    func post(url: String, body: Data) async throws -> HttpResponse
}

public protocol SecureStorage {
    func put(key: String, value: Data) throws
    func get(key: String) throws -> Data?
}

/// Publishes the encrypted TS09 transfer offer to the chosen peer/transport. A successful publish
/// means the wallet is waiting for the peer's next message; it does not complete the transfer.
public protocol TransferOfferPublisher {
    func publish(offeredKey: Data) async throws
}
