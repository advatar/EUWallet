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

/// The only platform action permitted after a successful OpenID4VP `direct_post`. The host owns
/// browser/app routing and its scheme/origin policy; the shell passes one parsed absolute URI.
public protocol OpenID4VPRedirectHandler {
    func handle(redirectUri: URL) async throws
}

public struct OpenID4VPDirectPostResponse: Equatable {
    public static let maximumResponseBytes = 64 * 1_024
    public static let maximumRedirectUriBytes = 4_096

    public let redirectUri: URL?

    static func parse(_ response: HttpResponse) throws -> OpenID4VPDirectPostResponse {
        guard response.statusCode == 200 else {
            throw HttpClientError.invalidProtocolResponse(
                "OpenID4VP direct_post requires HTTP 200")
        }
        guard response.body.count <= maximumResponseBytes else {
            throw HttpClientError.responseTooLarge(limit: maximumResponseBytes)
        }
        guard normalizedMediaType(response.contentType) == "application/json" else {
            throw HttpClientError.unacceptableContentType(
                expected: ["application/json"], actual: response.contentType)
        }
        guard let jsonText = String(data: response.body, encoding: .utf8) else {
            throw HttpClientError.invalidProtocolResponse(
                "OpenID4VP direct_post response is not UTF-8 JSON")
        }
        let value: Any
        do {
            value = try JSONSerialization.jsonObject(with: response.body)
        } catch {
            throw HttpClientError.invalidProtocolResponse(
                "OpenID4VP direct_post response is not JSON")
        }
        guard let object = value as? [String: Any] else {
            throw HttpClientError.invalidProtocolResponse(
                "OpenID4VP direct_post response must be a JSON object")
        }
        guard hasUniqueRedirectUriKey(jsonText) else {
            throw HttpClientError.invalidProtocolResponse(
                "OpenID4VP direct_post response contains duplicate redirect_uri members")
        }
        guard let rawRedirect = object["redirect_uri"] else {
            return OpenID4VPDirectPostResponse(redirectUri: nil)
        }
        guard let redirect = rawRedirect as? String,
              let redirectUri = absoluteUri(redirect)
        else {
            throw HttpClientError.invalidProtocolResponse(
                "OpenID4VP redirect_uri must be a bounded absolute URI")
        }
        return OpenID4VPDirectPostResponse(redirectUri: redirectUri)
    }

    static func isUtf8(_ body: Data) -> Bool {
        String(data: body, encoding: .utf8) != nil
    }

    private static func normalizedMediaType(_ raw: String?) -> String? {
        guard let raw, !raw.contains(",") else { return nil }
        let base = raw.split(separator: ";", maxSplits: 1, omittingEmptySubsequences: false)[0]
            .trimmingCharacters(in: .whitespacesAndNewlines)
            .lowercased()
        return base.isEmpty ? nil : base
    }

    private static func absoluteUri(_ value: String) -> URL? {
        guard !value.isEmpty,
              value.utf8.count <= maximumRedirectUriBytes,
              value.utf8.allSatisfy({ $0 >= 0x21 && $0 <= 0x7e }),
              !value.contains("\\"),
              hasValidPercentEscapes(value.utf8),
              let colon = value.firstIndex(of: ":")
        else { return nil }
        let scheme = value[..<colon]
        guard let first = scheme.utf8.first,
              (first >= UInt8(ascii: "A") && first <= UInt8(ascii: "Z")) ||
                (first >= UInt8(ascii: "a") && first <= UInt8(ascii: "z")),
              scheme.utf8.dropFirst().allSatisfy({ byte in
                  (byte >= UInt8(ascii: "A") && byte <= UInt8(ascii: "Z")) ||
                    (byte >= UInt8(ascii: "a") && byte <= UInt8(ascii: "z")) ||
                    (byte >= UInt8(ascii: "0") && byte <= UInt8(ascii: "9")) ||
                    byte == UInt8(ascii: "+") || byte == UInt8(ascii: "-") ||
                    byte == UInt8(ascii: ".")
              }),
              let url = URL(string: value),
              url.scheme != nil
        else { return nil }
        return url
    }

    private static func hasValidPercentEscapes(_ bytes: String.UTF8View) -> Bool {
        let bytes = Array(bytes)
        var index = 0
        while index < bytes.count {
            if bytes[index] == UInt8(ascii: "%") {
                guard index + 2 < bytes.count,
                      bytes[index + 1].isAsciiHexDigit,
                      bytes[index + 2].isAsciiHexDigit
                else { return false }
                index += 3
            } else {
                index += 1
            }
        }
        return true
    }

    /// Foundation's JSON parser intentionally applies last-member-wins semantics. Navigation is a
    /// security-relevant action, so scan the already-validated, bounded top-level object and reject
    /// duplicate spellings, including escaped equivalents such as `\u0072edirect_uri`.
    private static func hasUniqueRedirectUriKey(_ json: String) -> Bool {
        let bytes = Array(json.utf8)
        var index = 0

        func skipWhitespace() {
            while index < bytes.count,
                  bytes[index] == 0x20 || bytes[index] == 0x09 ||
                    bytes[index] == 0x0a || bytes[index] == 0x0d {
                index += 1
            }
        }

        func consumeStringToken() -> Range<Int>? {
            guard index < bytes.count, bytes[index] == UInt8(ascii: "\"") else { return nil }
            let start = index
            index += 1
            var escaped = false
            while index < bytes.count {
                let byte = bytes[index]
                index += 1
                if escaped {
                    escaped = false
                } else if byte == UInt8(ascii: "\\") {
                    escaped = true
                } else if byte == UInt8(ascii: "\"") {
                    return start..<index
                }
            }
            return nil
        }

        func skipValue() -> Bool {
            var objectDepth = 0
            var arrayDepth = 0
            var inString = false
            var escaped = false
            while index < bytes.count {
                let byte = bytes[index]
                if inString {
                    index += 1
                    if escaped {
                        escaped = false
                    } else if byte == UInt8(ascii: "\\") {
                        escaped = true
                    } else if byte == UInt8(ascii: "\"") {
                        inString = false
                    }
                    continue
                }
                switch byte {
                case UInt8(ascii: "\""):
                    inString = true
                    index += 1
                case UInt8(ascii: "{"):
                    objectDepth += 1
                    index += 1
                case UInt8(ascii: "["):
                    arrayDepth += 1
                    index += 1
                case UInt8(ascii: "}"):
                    if objectDepth == 0 && arrayDepth == 0 { return true }
                    objectDepth -= 1
                    if objectDepth < 0 { return false }
                    index += 1
                case UInt8(ascii: "]"):
                    arrayDepth -= 1
                    if arrayDepth < 0 { return false }
                    index += 1
                case UInt8(ascii: ",") where objectDepth == 0 && arrayDepth == 0:
                    return true
                default:
                    index += 1
                }
            }
            return false
        }

        skipWhitespace()
        guard index < bytes.count, bytes[index] == UInt8(ascii: "{") else { return false }
        index += 1
        skipWhitespace()
        if index < bytes.count, bytes[index] == UInt8(ascii: "}") { return true }

        var redirectCount = 0
        while index < bytes.count {
            skipWhitespace()
            guard let keyRange = consumeStringToken(),
                  let key = try? JSONDecoder().decode(
                      String.self,
                      from: Data(bytes[keyRange]))
            else { return false }
            if key == "redirect_uri" {
                redirectCount += 1
                if redirectCount > 1 { return false }
            }
            skipWhitespace()
            guard index < bytes.count, bytes[index] == UInt8(ascii: ":") else { return false }
            index += 1
            skipWhitespace()
            guard skipValue() else { return false }
            skipWhitespace()
            guard index < bytes.count else { return false }
            if bytes[index] == UInt8(ascii: ",") {
                index += 1
                continue
            }
            guard bytes[index] == UInt8(ascii: "}") else { return false }
            index += 1
            skipWhitespace()
            return index == bytes.count
        }
        return false
    }
}

private extension UInt8 {
    var isAsciiHexDigit: Bool {
        (self >= UInt8(ascii: "0") && self <= UInt8(ascii: "9")) ||
            (self >= UInt8(ascii: "A") && self <= UInt8(ascii: "F")) ||
            (self >= UInt8(ascii: "a") && self <= UInt8(ascii: "f"))
    }
}

public enum HttpClientError: Error, Equatable {
    case invalidUrl(String)
    case unsafeDestination(String)
    case nonHttpResponse
    case responseTooLarge(limit: Int)
    case redirectRejected(location: String?)
    case unacceptableContentType(expected: [String], actual: String?)
    case invalidProtocolBody(String)
    case invalidProtocolResponse(String)
    case unsupportedDeliveryProfile(HttpDeliveryProfile)
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
        case .invalidProtocolBody(let message): return "Invalid HTTP protocol body: \(message)"
        case .invalidProtocolResponse(let message):
            return "Invalid HTTP protocol response: \(message)"
        case .unsupportedDeliveryProfile(let profile):
            return "No production HTTP adapter is configured for \(profile.rawValue)"
        case .transport(let message): return "HTTP transport failed: \(message)"
        }
    }
}

/// A stopped effect cascade. Infrastructure failures are never translated into semantic wallet
/// events such as `userDeclined` or `presentationDelivered`.
public enum EffectExecutorError: Error, Equatable {
    case ffi(FfiContractError)
    case coreInvocationFailed
    case noPendingDurableCommit
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
        case .coreInvocationFailed: return "Wallet core invocation failed"
        case .noPendingDurableCommit: return "No durable wallet transition is awaiting retry"
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
    private let lifecycle: DurableLifecycleCoordinator
    private let signer: Signer
    private let http: HttpClient
    private let storage: SecureStorage
    private let trust: TrustResolver
    private let statusLists: StatusListResolver?
    private let issuer: IssuerResponder?
    private let transferOffers: TransferOfferPublisher?
    private let presentationRedirectHandler: OpenID4VPRedirectHandler?
    private let render: (UInt64?, Data?, ScreenDescription) throws -> Void
    private let durableStateLock = NSLock()
    private var pendingDurableEventJson: String?

    public init(
        lifecycle: DurableLifecycleCoordinator,
        signer: Signer,
        http: HttpClient,
        storage: SecureStorage,
        trust: TrustResolver,
        statusLists: StatusListResolver? = nil,
        issuer: IssuerResponder? = nil,
        transferOffers: TransferOfferPublisher? = nil,
        presentationRedirectHandler: OpenID4VPRedirectHandler? = nil,
        render: @escaping (UInt64?, Data?, ScreenDescription) throws -> Void
    ) {
        self.lifecycle = lifecycle
        self.signer = signer
        self.http = http
        self.storage = storage
        self.trust = trust
        self.statusLists = statusLists
        self.issuer = issuer
        self.transferOffers = transferOffers
        self.presentationRedirectHandler = presentationRedirectHandler
        self.render = render
    }

    /// Send one JSON event and fully drain the resulting effect cascade.
    @discardableResult
    public func send(eventJson: String) async throws -> EffectCascadeOutcome {
        let output = try invokeCore(eventJson)
        return try await drain(
            initialCoreOutput: output,
            initialEventType: Self.eventType(eventJson))
    }

    /// Retry the exact Core transition whose durable commit blocked this executor. The lifecycle
    /// coordinator commits its retained checkpoint and returns its retained effect batch without
    /// invoking Core again; draining then continues from that batch.
    @discardableResult
    public func retryPendingDurableCommit() async throws -> EffectCascadeOutcome {
        let (eventJson, output) = try retryPendingCoreOutput()
        return try await drain(
            initialCoreOutput: output,
            initialEventType: Self.eventType(eventJson))
    }

    /// Present the core's post-restore projection without treating it as a resumable effect
    /// cascade. Process-death recovery is deliberately limited to one non-interactive render.
    public func presentRestoredState(coreOutput: String) throws {
        let effects = try decode(coreOutput)
        guard effects.count <= 1 else {
            throw EffectExecutorError.ffi(
                .malformedCoreOutput("durable recovery contains multiple effects"))
        }
        for effect in effects {
            guard case .render(let operationId, let authorizationHash, let screen) = effect,
                operationId == nil, authorizationHash == nil,
                case .issuanceRecovery(let recovery) = screen,
                recovery.reason == .sessionInterrupted,
                recovery.canResume == false
            else {
                throw EffectExecutorError.ffi(
                    .malformedCoreOutput("durable recovery is not a safe interruption screen"))
            }
            try render(nil, nil, screen)
        }
    }

    private func drain(
        initialCoreOutput: String,
        initialEventType: String?
    ) async throws -> EffectCascadeOutcome {
        var queue = try decode(initialCoreOutput)
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
                // A native completion callback is only an acknowledgement after Core has
                // durably accepted it and its returned batch has decoded without an error render.
                // Marking success before this boundary can turn a rejected credential callback
                // into a false-positive issuance result.
                let followUpEffects = try decode(invokeCore(followUp))
                if Self.completionEventTypes.contains(followUpType ?? ""),
                   !followUpEffects.contains(where: Self.isErrorRender)
                {
                    acknowledged = true
                }
                if case .publishTransferOffer = effect,
                   followUpType == "operationSucceeded" {
                    awaitingExternalInput = true
                }
                queue.append(contentsOf: followUpEffects)
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

    private func invokeCore(_ eventJson: String) throws -> String {
        durableStateLock.lock()
        defer { durableStateLock.unlock() }
        // Never replace the exact event associated with a retained checkpoint/effect batch. A
        // second event cannot be handled until the first event's commit has succeeded or failed
        // terminally.
        guard pendingDurableEventJson == nil else {
            throw DurableLifecycleError.commitPending
        }
        // A newly-created executor must also respect a transition retained by the coordinator;
        // never adopt the new event as if it were the original pending event.
        guard !lifecycle.hasPendingCommit else {
            throw DurableLifecycleError.commitPending
        }
        pendingDurableEventJson = eventJson
        do {
            let output = try lifecycle.handleEventJson(eventJson: eventJson)
            pendingDurableEventJson = nil
            return output
        } catch let error as DurableLifecycleError {
            if !lifecycle.hasPendingCommit {
                pendingDurableEventJson = nil
            }
            // Preserve the stable lifecycle category so callers can distinguish an exact retry
            // from a poisoned lifecycle or persistence divergence.
            throw error
        } catch {
            pendingDurableEventJson = nil
            throw EffectExecutorError.coreInvocationFailed
        }
    }

    private func retryPendingCoreOutput() throws -> (eventJson: String, output: String) {
        durableStateLock.lock()
        defer { durableStateLock.unlock() }
        guard let eventJson = pendingDurableEventJson else {
            throw EffectExecutorError.noPendingDurableCommit
        }
        do {
            let output = try lifecycle.retryPendingEvent(eventJson: eventJson)
            pendingDurableEventJson = nil
            return (eventJson, output)
        } catch let error as DurableLifecycleError {
            if !lifecycle.hasPendingCommit {
                pendingDurableEventJson = nil
            }
            throw error
        } catch {
            throw EffectExecutorError.coreInvocationFailed
        }
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
        case .http(let operationId, let resultType, let profile, let url, let body):
            guard profile.resultType == resultType else {
                return WalletEventJSON.operationFailed(
                    operationId: operationId, failure: .unsupported)
            }
            if profile == .openid4vpDirectPost,
               !OpenID4VPDirectPostResponse.isUtf8(Data(body)) {
                return WalletEventJSON.operationFailed(
                    operationId: operationId, failure: .transport)
            }
            let response: HttpResponse
            do {
                response = try await http.post(
                    url: url,
                    body: Data(body),
                    profile: profile)
            } catch is CancellationError {
                return WalletEventJSON.operationCancelled(operationId: operationId)
            } catch {
                return WalletEventJSON.operationFailed(
                    operationId: operationId, failure: .transport)
            }
            switch profile {
            case .openid4vpDirectPost:
                guard response.statusCode == 200 else {
                    return WalletEventJSON.operationFailed(
                        operationId: operationId, failure: .httpStatus)
                }
                let parsed: OpenID4VPDirectPostResponse
                do {
                    parsed = try OpenID4VPDirectPostResponse.parse(response)
                } catch {
                    return WalletEventJSON.operationFailed(
                        operationId: operationId, failure: .transport)
                }
                if let redirectUri = parsed.redirectUri {
                    guard let presentationRedirectHandler else {
                        return WalletEventJSON.operationFailed(
                            operationId: operationId, failure: .missingDependency)
                    }
                    do {
                        try await presentationRedirectHandler.handle(redirectUri: redirectUri)
                    } catch is CancellationError {
                        return WalletEventJSON.operationCancelled(operationId: operationId)
                    } catch {
                        return WalletEventJSON.operationFailed(
                            operationId: operationId, failure: .transport)
                    }
                }
                return WalletEventJSON.presentationDelivered(operationId: operationId)
            case .paymentAuthorization:
                guard (200...299).contains(response.statusCode) else {
                    return WalletEventJSON.operationFailed(
                        operationId: operationId, failure: .httpStatus)
                }
                return WalletEventJSON.paymentAuthorizationDelivered(operationId: operationId)
            case .qesAuthorization:
                guard (200...299).contains(response.statusCode) else {
                    return WalletEventJSON.operationFailed(
                        operationId: operationId, failure: .httpStatus)
                }
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
    private static let completionEventTypes: Set<String> = [
        "credentialReceived", "paymentAuthorizationDelivered", "presentationDelivered",
        "qesAuthorizationDelivered",
    ]
    private static let declineEventTypes: Set<String> = [
        "userDeclined", "paymentDeclined", "qesDeclined",
    ]
    private static let idleEventTypes: Set<String> = [
        "redactTransaction", "setClock", "wipeTransactionLog",
    ]

    private static func isErrorRender(_ effect: WalletEffect) -> Bool {
        if case .render(_, _, .error) = effect { return true }
        return false
    }
}

public protocol HttpClient {
    func post(
        url: String,
        body: Data,
        profile: HttpDeliveryProfile
    ) async throws -> HttpResponse
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
