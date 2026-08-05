import Foundation

/// Drives one cross-wallet PID capture end to end. The companion is launched with an invocation URL
/// carrying the session id; the coordinator fetches the session parameters, reads the eMRTD chip,
/// runs the iProov capture, and submits the attestation to VCIssuer, which mints the PID bound to
/// the target wallet.
public actor CaptureCoordinator {
    private let client: CaptureSessionClient
    private let chipReader: ChipReader
    private let liveness: LivenessCapturing
    private let nfcServerURL: String
    /// App Attest for the companion instance; when set (device only), the evidence submit carries a
    /// body-bound assertion so VCIssuer can require a genuine, registered companion.
    private let appAttestor: AppAttestAssertor?

    public init(
        client: CaptureSessionClient,
        chipReader: ChipReader = ChipmunkChipReader(),
        liveness: LivenessCapturing = IProovLivenessCapture(),
        nfcServerURL: String,
        appAttestor: AppAttestAssertor? = nil
    ) {
        self.client = client
        self.chipReader = chipReader
        self.liveness = liveness
        self.nfcServerURL = nfcServerURL
        self.appAttestor = appAttestor
    }

    /// Coarse progress for a capture, suitable for driving UI.
    public enum Stage: Sendable, Equatable {
        case fetchingSession
        case readingChip
        case capturingLiveness
        case submitting
        case issued
        case failed(String)
    }

    /// The MRZ is captured (by camera or manual entry) on the UI before the flow runs; pass it in.
    public func run(
        sessionID: String,
        mrz: MRZInput,
        onStage: @Sendable (Stage) -> Void = { _ in }
    ) async -> CaptureSessionClient.IssuanceResult? {
        do {
            onStage(.fetchingSession)
            let params = try await client.fetchParameters(sessionID: sessionID)
            guard params.status == .awaitingEvidence else {
                onStage(.failed("session is not awaiting evidence (\(params.status.rawValue))"))
                return nil
            }
            guard
                let nonce = params.nonce,
                let holderJkt = params.holderJkt,
                let audience = params.audience
            else {
                onStage(.failed("session is missing binding parameters"))
                return nil
            }

            // The session must offer a liveness token, else fail closed before any capture.
            guard let token = params.iproovToken, let streaming = params.iproovStreamingURL else {
                onStage(.failed("session has no iProov capture token"))
                return nil
            }

            // Read the chip FIRST: its DG2 portrait is the reference for the 1:1 likeness match, so it
            // must exist before the face scan. VCIssuer re-runs Passive Authentication authoritatively.
            onStage(.readingChip)
            let read = try await chipReader.read(
                ChipReadRequest(
                    nfcServerURL: nfcServerURL,
                    mrz: mrz,
                    sessionNonce: nonce,
                    holderJkt: holderJkt,
                    audience: audience))

            // Then the liveness scan: iProov GPA proves a live, present human and matches that face 1:1
            // against the chip's DG2 portrait (registered as the reference server-side for this token).
            onStage(.capturingLiveness)
            try await liveness.capture(
                LivenessRequest(
                    iproovToken: token, streamingURL: streaming,
                    referencePortrait: read.portrait))

            onStage(.submitting)
            let result = try await client.submitEvidence(
                sessionID: sessionID, attestation: read.attestation, appAttestor: appAttestor)
            switch result.status {
            case .issued:
                onStage(.issued)
            case .failed, .awaitingEvidence:
                onStage(.failed("issuer did not issue (\(result.status.rawValue))"))
            }
            return result
        } catch {
            onStage(.failed(error.localizedDescription))
            return nil
        }
    }
}
