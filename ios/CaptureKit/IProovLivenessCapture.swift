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
            try await withCheckedThrowingContinuation { (continuation: CheckedContinuation<Void, Error>) in
                // IProov presents UI — launch on the main thread.
                DispatchQueue.main.async {
                    IProov.launch(streamingURL: url, token: request.iproovToken) { status in
                        switch status {
                        case .success:
                            continuation.resume()
                        case .failure:
                            continuation.resume(
                                throwing: CaptureProviderError.underlying(
                                    "liveness capture did not pass"))
                        case let .error(error):
                            continuation.resume(
                                throwing: CaptureProviderError.underlying(error.localizedDescription))
                        case .cancelled:
                            continuation.resume(
                                throwing: CaptureProviderError.underlying("liveness capture cancelled"))
                        default:
                            // connecting / connected / processing — keep waiting.
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
