import Foundation

/// How the BAC/PACE access key is supplied to the reader: the three typed data-page fields, or the
/// raw MRZ captured by the camera (the reader O/0-corrects against the printed check digit).
public enum MRZInput: Sendable {
    case fields(number: String, dateOfBirth: String, dateOfExpiry: String)
    case raw(String)
}

/// Everything the trusted reader/liveness backend needs to produce a VCIssuer-verifiable eMRTD
/// attestation for a capture session. The nonce, holder key, and audience come from the capture
/// session (fetched by `CaptureSessionClient`); binding the attestation to them is what lets
/// `verify_emrtd_evidence` accept it for THIS session and THIS target wallet.
public struct ChipReadRequest: Sendable {
    /// The `service-nfc` relay endpoint (e.g. `wss://nfc.dev-eu.iproov.id/channel`).
    public let nfcServerURL: String
    public let mrz: MRZInput
    /// Session nonce welded into the attestation (replay + session binding).
    public let sessionNonce: String
    /// Target wallet key thumbprint welded into the attestation (`new_holder_jkt`).
    public let holderJkt: String
    /// Issuer origin the attestation's `aud` must equal.
    public let audience: String

    public init(
        nfcServerURL: String,
        mrz: MRZInput,
        sessionNonce: String,
        holderJkt: String,
        audience: String
    ) {
        self.nfcServerURL = nfcServerURL
        self.mrz = mrz
        self.sessionNonce = sessionNonce
        self.holderJkt = holderJkt
        self.audience = audience
    }
}

/// The reader's output: a compact JWS attestation signed by the trusted reader/liveness backend,
/// carrying the SOD Passive-Authentication + anti-cloning verdicts and the DG1 identity, welded to
/// the request's nonce + holder key + audience. VCIssuer re-runs Passive Authentication and makes the
/// authoritative allow/deny; this is only the transport.
public struct ChipReadResult: Sendable {
    public let attestation: String
    public let portrait: Data?

    public init(attestation: String, portrait: Data? = nil) {
        self.attestation = attestation
        self.portrait = portrait
    }
}

/// Reads an eMRTD chip and returns a VCIssuer-verifiable attestation.
public protocol ChipReader: Sendable {
    func read(_ request: ChipReadRequest) async throws -> ChipReadResult
}

/// Parameters for a client-side iProov Genuine-Presence capture. The result is validated
/// server-side by VCIssuer (authoritative), so a completed capture is all this needs to signal.
public struct LivenessRequest: Sendable {
    public let iproovToken: String
    public let streamingURL: String

    public init(iproovToken: String, streamingURL: String) {
        self.iproovToken = iproovToken
        self.streamingURL = streamingURL
    }
}

/// Runs an iProov capture with a server-issued token.
public protocol LivenessCapturing: Sendable {
    func capture(_ request: LivenessRequest) async throws
}

/// Shared error surface for the capture providers.
public enum CaptureProviderError: LocalizedError {
    /// The reader SDK (ChipmunkNFC) is not linked into this build — add it via `project.local.yml`.
    case readerNotLinked
    /// The liveness SDK (iProov) is not linked into this build — add it via `project.local.yml`.
    case livenessNotLinked
    case invalidServerURL
    case missingParameter(String)
    case underlying(String)

    public var errorDescription: String? {
        switch self {
        case .readerNotLinked:
            return "The NFC reader (ChipmunkNFC) isn't linked into this build. Generate the project "
                + "with project.local.yml on a machine with the credentials-platform submodule."
        case .livenessNotLinked:
            return "The liveness SDK (iProov) isn't linked into this build. Add it via "
                + "project.local.yml on a machine with the licensed iProov xcframework."
        case .invalidServerURL:
            return "Enter a valid NFC server URL, e.g. wss://your-host/channel."
        case let .missingParameter(name):
            return "The capture session did not provide \(name)."
        case let .underlying(message):
            return message
        }
    }
}
