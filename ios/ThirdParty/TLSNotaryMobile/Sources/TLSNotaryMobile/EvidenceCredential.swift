import CryptoKit
import Foundation
import TLSNMobileFFI

public struct EvidenceRequest: Sendable {
    public var url: URL
    public var method: String
    public var retrievedAt: Date
    public var responseBody: Data
    public var disclosedFields: [String]
    public var notaryAttestation: Data?

    public init(
        url: URL,
        method: String = "GET",
        retrievedAt: Date = .now,
        responseBody: Data,
        disclosedFields: [String] = [],
        notaryAttestation: Data? = nil
    ) {
        self.url = url
        self.method = method
        self.retrievedAt = retrievedAt
        self.responseBody = responseBody
        self.disclosedFields = disclosedFields
        self.notaryAttestation = notaryAttestation
    }
}
public struct EvidenceCredential: Codable, Sendable {
    public let credential: String
    public let holderPublicKey: String
    public let holderSignature: String
    public let signatureAlgorithm: String

    public func verifyHolderSignature() -> Bool {
        guard
            let publicKeyBytes = Data(base64URLEncoded: holderPublicKey),
            let signatureBytes = Data(base64URLEncoded: holderSignature),
            let publicKey = try? P256.Signing.PublicKey(x963Representation: publicKeyBytes),
            let signature = try? P256.Signing.ECDSASignature(derRepresentation: signatureBytes)
        else {
            return false
        }
        return publicKey.isValidSignature(signature, for: Data(credential.utf8))
    }
}

public struct NotaryConfiguration: Sendable {
    public var baseURL: URL
    public var trustedPublicKeyX963: Data
    public var maximumResponseBytes: Int

    public init(
        baseURL: URL,
        trustedPublicKeyX963: Data,
        maximumResponseBytes: Int = 512 * 1024
    ) {
        self.baseURL = baseURL
        self.trustedPublicKeyX963 = trustedPublicKeyX963
        self.maximumResponseBytes = maximumResponseBytes
    }
}

public struct IssuerConfiguration: Sendable {
    public var baseURL: URL

    public init(baseURL: URL) {
        self.baseURL = baseURL
    }
}

public struct WalletCredentialOffer: Codable, Sendable {
    public let credentialOfferURI: URL
    public let walletURI: URL
    public let expiresIn: Int

    enum CodingKeys: String, CodingKey {
        case credentialOfferURI = "credential_offer_uri"
        case walletURI = "deep_link"
        case expiresIn = "expires_in"
    }
}

public enum TLSNotaryMobileError: Error, Equatable, LocalizedError {
    case invalidRequest(String)
    case rustFailure(String)
    case invalidRustResponse
    case signingFailure(String)

    public var errorDescription: String? {
        switch self {
        case let .invalidRequest(message), let .rustFailure(message), let .signingFailure(message):
            message
        case .invalidRustResponse:
            "The Rust engine returned an invalid response."
        }
    }
}

public protocol HolderSigningKey: Sendable {
    var did: String { get }
    var publicKeyX963: Data { get }
    func sign(_ data: Data) throws -> Data
}

public struct SoftwareHolderKey: HolderSigningKey {
    private let key: P256.Signing.PrivateKey

    public init() {
        key = P256.Signing.PrivateKey()
    }

    public var publicKeyX963: Data { key.publicKey.x963Representation }
    public var did: String { Self.didJwk(publicKey: publicKeyX963) }

    public func sign(_ data: Data) throws -> Data {
        try key.signature(for: data).derRepresentation
    }

    static func didJwk(publicKey: Data) -> String {
        precondition(publicKey.count == 65 && publicKey.first == 0x04)
        let x = publicKey[1..<33].base64URLEncodedString()
        let y = publicKey[33..<65].base64URLEncodedString()
        let jwk = "{\"crv\":\"P-256\",\"kty\":\"EC\",\"x\":\"\(x)\",\"y\":\"\(y)\"}"
        return "did:jwk:\(Data(jwk.utf8).base64URLEncodedString())"
    }
}

public actor TLSNotaryMobileClient {
    private let holderKey: any HolderSigningKey
    private let notary: NotaryConfiguration?
    private let issuer: IssuerConfiguration?

    public init(
        notary: NotaryConfiguration? = nil,
        issuer: IssuerConfiguration? = nil,
        holderKey: any HolderSigningKey = SoftwareHolderKey()
    ) throws {
        guard tlsn_mobile_abi_version() == 1 else {
            throw TLSNotaryMobileError.rustFailure("Unsupported Rust ABI version.")
        }
        self.notary = notary
        self.issuer = issuer
        self.holderKey = holderKey
    }

    /// Runs a GET through the Rust TLSNotary prover, then holder-signs the
    /// verifier result as an evidence credential.
    public func notarize(
        url: URL,
        headers: [String: String] = [:],
        disclosedFields: [String] = []
    ) async throws -> EvidenceCredential {
        guard let notary else {
            throw TLSNotaryMobileError.invalidRequest("A notary URL is required.")
        }
        let request: [String: Any] = [
            "url": url.absoluteString,
            "notaryUrl": notary.baseURL.absoluteString,
            "headers": headers,
            "maxRecvData": notary.maximumResponseBytes,
            "trustedNotaryPublicKey": notary.trustedPublicKeyX963.base64URLEncodedString(),
        ]
        let input = try JSONSerialization.data(withJSONObject: request, options: [.sortedKeys])
        let output = try await Self.callNotary(input)
        guard
            let object = try JSONSerialization.jsonObject(with: output) as? [String: Any],
            let status = object["responseStatus"] as? Int,
            let bodyString = object["responseBody"] as? String,
            let body = Data(base64Encoded: bodyString),
            let attestation = object["notaryAttestation"]
        else {
            throw TLSNotaryMobileError.invalidRustResponse
        }
        guard 200..<400 ~= status else {
            throw TLSNotaryMobileError.rustFailure(
                "The notarized server returned HTTP \(status)."
            )
        }
        let attestationData = try JSONSerialization.data(
            withJSONObject: attestation,
            options: [.sortedKeys]
        )
        return try await createEvidence(
            EvidenceRequest(
                url: url,
                responseBody: body,
                disclosedFields: disclosedFields,
                notaryAttestation: attestationData
            )
        )
    }

    public func createEvidence(_ request: EvidenceRequest) async throws -> EvidenceCredential {
        let input = try Self.encode(request: request, holder: holderKey.did)
        let credential = try await Task.detached {
            try Self.callRust(input)
        }.value

        do {
            let signature = try holderKey.sign(Data(credential.utf8))
            return EvidenceCredential(
                credential: credential,
                holderPublicKey: holderKey.publicKeyX963.base64URLEncodedString(),
                holderSignature: signature.base64URLEncodedString(),
                signatureAlgorithm: "ES256"
            )
        } catch {
            throw TLSNotaryMobileError.signingFailure(error.localizedDescription)
        }
    }

    /// Submits the already verified notary artifact to the configured issuer
    /// and returns an OpenID4VCI offer that can be opened by a wallet.
    public func prepareWalletOffer(
        from evidence: EvidenceCredential
    ) async throws -> WalletCredentialOffer {
        guard let issuer else {
            throw TLSNotaryMobileError.invalidRequest("An issuer URL is required.")
        }
        guard
            let credentialData = evidence.credential.data(using: .utf8),
            let credential = try JSONSerialization.jsonObject(with: credentialData)
                as? [String: Any],
            let evidenceItems = credential["evidence"] as? [[String: Any]],
            let artifact = evidenceItems.first?["notaryAttestation"]
        else {
            throw TLSNotaryMobileError.invalidRequest(
                "The credential has no portable notary artifact."
            )
        }
        let endpoint = issuer.baseURL
            .appendingPathComponent("evidence-offers")
            .appendingPathComponent("tlsnotary")
        var request = URLRequest(url: endpoint)
        request.httpMethod = "POST"
        request.setValue("application/json", forHTTPHeaderField: "Content-Type")
        request.httpBody = try JSONSerialization.data(
            withJSONObject: ["artifact": artifact],
            options: [.sortedKeys]
        )
        let (data, response) = try await URLSession.shared.data(for: request)
        guard
            let http = response as? HTTPURLResponse,
            http.statusCode == 200
        else {
            let message = String(data: data, encoding: .utf8) ?? "Issuer rejected evidence."
            throw TLSNotaryMobileError.rustFailure(message)
        }
        do {
            return try JSONDecoder().decode(WalletCredentialOffer.self, from: data)
        } catch {
            throw TLSNotaryMobileError.invalidRustResponse
        }
    }

    private static func encode(request: EvidenceRequest, holder: String) throws -> Data {
        guard request.url.scheme?.lowercased() == "https" else {
            throw TLSNotaryMobileError.invalidRequest("Only HTTPS pages can be notarized.")
        }
        var object: [String: Any] = [
            "url": request.url.absoluteString,
            "method": request.method,
            "retrievedAt": ISO8601DateFormatter().string(from: request.retrievedAt),
            "responseBody": request.responseBody.base64EncodedString(),
            "disclosedFields": request.disclosedFields,
            "holder": holder,
        ]
        if let attestation = request.notaryAttestation {
            object["notaryAttestation"] = try JSONSerialization.jsonObject(with: attestation)
        }
        return try JSONSerialization.data(withJSONObject: object, options: [.sortedKeys])
    }

    private nonisolated static func callRust(_ input: Data) throws -> String {
        guard let inputString = String(data: input, encoding: .utf8) else {
            throw TLSNotaryMobileError.invalidRequest("Request is not UTF-8.")
        }
        let pointer = inputString.withCString { tlsn_mobile_create_evidence($0) }
        guard let pointer else { throw TLSNotaryMobileError.invalidRustResponse }
        defer { tlsn_mobile_string_free(pointer) }
        let output = String(cString: pointer)
        guard let data = output.data(using: .utf8),
              let object = try? JSONSerialization.jsonObject(with: data) as? [String: Any]
        else {
            throw TLSNotaryMobileError.invalidRustResponse
        }
        if let error = object["error"] as? String {
            throw TLSNotaryMobileError.rustFailure(error)
        }
        return output
    }

    private nonisolated static func callNotary(_ input: Data) async throws -> Data {
        guard let inputString = String(data: input, encoding: .utf8) else {
            throw TLSNotaryMobileError.invalidRequest("Request is not UTF-8.")
        }
        return try await withCheckedThrowingContinuation { continuation in
            let box = Unmanaged.passRetained(NotarizationContinuation(continuation))
            inputString.withCString {
                _ = tlsn_mobile_notarize(
                    $0,
                    tlsNotaryMobileCompletion,
                    box.toOpaque()
                )
            }
        }
    }
}

private final class NotarizationContinuation: @unchecked Sendable {
    let value: CheckedContinuation<Data, any Error>

    init(_ value: CheckedContinuation<Data, any Error>) {
        self.value = value
    }
}

private let tlsNotaryMobileCompletion:
    @convention(c) (UnsafeMutableRawPointer?, UnsafeMutablePointer<CChar>?) -> Void = {
        context,
        result in
        guard let context else { return }
        let box = Unmanaged<NotarizationContinuation>.fromOpaque(context).takeRetainedValue()
        guard let result else {
            box.value.resume(throwing: TLSNotaryMobileError.invalidRustResponse)
            return
        }
        defer { tlsn_mobile_string_free(result) }
        let data = Data(String(cString: result).utf8)
        guard
            let object = try? JSONSerialization.jsonObject(with: data) as? [String: Any]
        else {
            box.value.resume(throwing: TLSNotaryMobileError.invalidRustResponse)
            return
        }
        if let error = object["error"] as? String {
            box.value.resume(throwing: TLSNotaryMobileError.rustFailure(error))
        } else {
            box.value.resume(returning: data)
        }
    }

private extension Data {
    init?(base64URLEncoded value: String) {
        var base64 = value.replacingOccurrences(of: "-", with: "+")
            .replacingOccurrences(of: "_", with: "/")
        base64.append(String(repeating: "=", count: (4 - base64.count % 4) % 4))
        self.init(base64Encoded: base64)
    }

    func base64URLEncodedString() -> String {
        base64EncodedString()
            .replacingOccurrences(of: "+", with: "-")
            .replacingOccurrences(of: "/", with: "_")
            .replacingOccurrences(of: "=", with: "")
    }
}
