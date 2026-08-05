import Foundation

#if canImport(iProov)
    import iProov
#endif

/// `LivenessCapturing` backed by the iProov Biometrics SDK (Genuine Presence Assurance). The capture
/// runs client-side with a VCIssuer-issued token; VCIssuer then validates it server-side, so the
/// authoritative pass/fail is decided there — this only reports whether the capture completed.
///
/// The SDK is linked via `project.local.yml` (licensed xcframework). Without it, this compiles to a
/// fail-closed stub so CI still builds every capture target. The exact `IProov.launch` surface tracks
/// the linked SDK version; adjust here if it differs.
public struct IProovLivenessCapture: LivenessCapturing {
    public init() {}

    public func capture(_ request: LivenessRequest) async throws {
        #if canImport(iProov)
            guard let url = URL(string: request.streamingURL) else {
                throw CaptureProviderError.invalidServerURL
            }
            // `request.referencePortrait` (the chip's DG2 image) is the 1:1 likeness reference. It is
            // registered with iProov server-side against this session's token, so the launch below
            // carries only the token; the SP settles liveness + likeness when VCIssuer validates.
            // (This SDK version's `launch` takes streamingURL + token.)
            try await withCheckedThrowingContinuation { (continuation: CheckedContinuation<Void, Error>) in
                // IProov presents UI — launch on the main thread.
                DispatchQueue.main.async {
                    IProov.launch(streamingURL: url, token: request.iproovToken) { status in
                        switch status {
                        case .success:
                            continuation.resume()
                        case let .failure(result):
                            continuation.resume(
                                throwing: CaptureProviderError.underlying(
                                    "liveness capture did not pass: \(result.reason.feedbackCode)"))
                        case let .error(error):
                            continuation.resume(
                                throwing: CaptureProviderError.underlying(error.localizedDescription))
                        case let .canceled(canceler):
                            continuation.resume(
                                throwing: CaptureProviderError.underlying(
                                    "liveness capture canceled (\(canceler))"))
                        case .connecting, .connected, .processing:
                            break  // in-progress — keep waiting for a terminal status
                        @unknown default:
                            break
                        }
                    }
                }
            }
        #else
            _ = request
            throw CaptureProviderError.livenessNotLinked
        #endif
    }
}
