import Foundation

public struct HttpResponse: Equatable {
    public let statusCode: UInt16
    public let body: Data

    public init(statusCode: UInt16, body: Data) {
        self.statusCode = statusCode
        self.body = body
    }
}

public enum HttpClientError: Error, Equatable {
    case invalidUrl(String)
    case nonHttpResponse
    case transport(String)
}

extension HttpClientError: LocalizedError {
    public var errorDescription: String? {
        switch self {
        case .invalidUrl(let url): return "Invalid HTTP URL: \(url)"
        case .nonHttpResponse: return "Transport returned a non-HTTP response"
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
        }
    }
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
    private let issuer: IssuerResponder?
    private let render: (ScreenDescription) -> Void

    public init(
        engine: WalletEngineDriving,
        signer: Signer,
        http: HttpClient,
        storage: SecureStorage,
        trust: TrustResolver,
        issuer: IssuerResponder? = nil,
        render: @escaping (ScreenDescription) -> Void
    ) {
        self.engine = engine
        self.signer = signer
        self.http = http
        self.storage = storage
        self.trust = trust
        self.issuer = issuer
        self.render = render
    }

    /// Send one JSON event and fully drain the resulting effect cascade.
    public func send(eventJson: String) async throws {
        var queue = try decode(engine.handleEventJson(eventJson: eventJson))
        while !queue.isEmpty {
            let effect = queue.removeFirst()
            if let followUp = try await execute(effect) {
                queue.append(contentsOf: try decode(engine.handleEventJson(eventJson: followUp)))
            }
        }
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
        case .render(let screen):
            render(screen)
            return nil
        case .sign(let keyRef, let payload):
            do {
                let sig = try signer.sign(keyRef: keyRef, payload: Data(payload))
                return WalletEventJSON.deviceSignatureProduced(sig)
            } catch {
                throw EffectExecutorError.signingFailed(String(describing: error))
            }
        case .http(let url, let body):
            let response: HttpResponse
            do {
                response = try await http.post(url: url, body: Data(body))
            } catch let error as HttpClientError {
                throw EffectExecutorError.transportFailed(error)
            } catch {
                throw EffectExecutorError.transportFailed(.transport(String(describing: error)))
            }
            guard (200...299).contains(response.statusCode) else {
                throw EffectExecutorError.httpStatusFailed(
                    statusCode: response.statusCode,
                    body: response.body)
            }
            return WalletEventJSON.presentationDelivered()
        case .resolveRpTrust(let clientId):
            let t = await trust.resolve(clientId: clientId)
            return WalletEventJSON.rpCertChainResolved(chain: t.certChain, redirectUris: t.redirectUris)
        case .persistNonce(let nonce):
            do {
                try storage.put(key: "nonce:\(nonce)", value: Data())
            } catch {
                throw EffectExecutorError.storageFailed(String(describing: error))
            }
            return nil
        // --- Issuance (OpenID4VCI). The demo's pre-authorized flow uses only token + credential;
        //     PAR / browser / tx-code are unreachable here and safely no-op. ---
        case .requestToken:
            guard let issuer else { return nil }
            let t = await issuer.token()
            return WalletEventJSON.tokenReceived(bound: t.bound, cNonce: t.cNonce)
        case .requestCredential(let proofJwt):
            guard let issuer else { return nil }
            let c = await issuer.credential(proofJwt: Data(proofJwt))
            return WalletEventJSON.credentialReceived(format: c.format, bytes: c.bytes)
        case .pushPar, .openAuthBrowser, .promptTxCode, .publishTransferOffer:
            return nil
        case .close:
            return nil
        }
    }
}

public protocol HttpClient {
    func post(url: String, body: Data) async throws -> HttpResponse
}

public protocol SecureStorage {
    func put(key: String, value: Data) throws
    func get(key: String) throws -> Data?
}
