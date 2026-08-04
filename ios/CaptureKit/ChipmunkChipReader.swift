import Foundation

#if canImport(ChipmunkNFC)
    import ChipmunkNFC
#endif

/// `ChipReader` backed by the ChipmunkNFC SDK (CoreNFC + `service-nfc` WebSocket relay). Requires a
/// physical device — CoreNFC is unavailable in the Simulator — and the SDK linked via
/// `project.local.yml`. Without the SDK it compiles to a fail-closed stub so CI (which has neither
/// the private submodule nor a device) still builds every capture target.
public struct ChipmunkChipReader: ChipReader {
    public init() {}

    public func read(_ request: ChipReadRequest) async throws -> ChipReadResult {
        #if canImport(ChipmunkNFC)
            guard let url = URL(string: request.nfcServerURL), url.scheme?.hasPrefix("ws") == true
            else {
                throw CaptureProviderError.invalidServerURL
            }
            let reader = NFCPassportReader(serverURL: url)
            let credentials: DocumentCredentials
            switch request.mrz {
            case let .fields(number, dateOfBirth, dateOfExpiry):
                credentials = DocumentCredentials(
                    passportNumber: number, dateOfBirth: dateOfBirth, dateOfExpiry: dateOfExpiry)
            case let .raw(rawMrz):
                credentials = DocumentCredentials(rawMrz: rawMrz)
            }
            // A PID-grade read: DG2 portrait + Passive Authentication + anti-cloning. The `service-nfc`
            // relay is responsible for welding the VCIssuer binding (session nonce, target holder
            // key, audience) into the signed attestation it returns as `resultToken`; that binding
            // context is carried on `request` and conveyed to the relay out of band (channel setup).
            // VCIssuer then re-runs Passive Authentication and makes the authoritative decision.
            let options = ReadOptions(skipDG2: false, doAA: true, doPA: true)
            let display = DisplayOptions(
                nfcAlertMessage: "Hold your passport to the top of your iPhone")
            do {
                let result = try await reader.readDocument(
                    credentials: credentials, options: options, display: display)
                guard let attestation = result.resultToken, !attestation.isEmpty else {
                    throw CaptureProviderError.underlying(
                        "the reader returned no attestation token for this session")
                }
                return ChipReadResult(attestation: attestation, portrait: result.document?.imgdata)
            } catch let error as CaptureProviderError {
                throw error
            } catch {
                throw CaptureProviderError.underlying(error.localizedDescription)
            }
        #else
            _ = request
            throw CaptureProviderError.readerNotLinked
        #endif
    }
}
