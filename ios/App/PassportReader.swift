import Foundation

#if canImport(ChipmunkNFC)
    import ChipmunkNFC
#endif

/// The outcome of an eMRTD (passport / eID) NFC read, reduced to what the wallet shows and forwards.
struct PassportReadResult: Sendable {
    let holderName: String
    let documentNumber: String
    let dateOfBirth: String
    let dateOfExpiry: String
    let nationality: String
    let issuingState: String
    /// DG2 portrait (JPEG/JP2), when DG2 was read.
    let portrait: Data?
    /// Set on the reader-token / ship flow when the server returns a token instead of an inline
    /// document — this is what gets redeemed / forwarded to VCIssuer for minting.
    let resultToken: String?
}

enum PassportReaderError: LocalizedError {
    /// The ChipmunkNFC reader package isn't linked into this build yet.
    case readerNotLinked
    case invalidServerURL
    case underlying(String)

    var errorDescription: String? {
        switch self {
        case .readerNotLinked:
            return "The NFC reader isn't linked into this build. Add the local ChipmunkNFC "
                + "Swift package to the EUWalletDemo target (File ▸ Add Package Dependencies ▸ "
                + "Add Local ▸ third_party/credentials-platform/service-nfc/reader-ios/ChipmunkNFC)."
        case .invalidServerURL:
            return "Enter a valid NFC server URL, e.g. wss://your-host/channel."
        case let .underlying(message):
            return message
        }
    }
}

/// How the BAC/PACE access key is supplied: either the three typed data-page fields, or the raw MRZ
/// captured by the camera (the server parses it and O/0-corrects against the printed check digit).
enum PassportMrzInput: Sendable {
    case fields(number: String, dateOfBirth: String, dateOfExpiry: String)
    case raw(String)
}

/// Reads an eMRTD chip over NFC by relaying to a `service-nfc` backend. The device is a pure relay:
/// it needs the server URL (wss://host/channel) — the server runs BAC/PACE, secure messaging,
/// Passive/Chip/Active Authentication and returns the document (or a reader-token to redeem).
protocol PassportReading: Sendable {
    func read(serverURL: String, mrz: PassportMrzInput) async throws -> PassportReadResult
}

/// Production reader backed by the ChipmunkNFC SDK (CoreNFC + WebSocket relay). Requires a physical
/// device — CoreNFC is unavailable in the Simulator.
struct ChipmunkPassportReader: PassportReading {
    func read(serverURL: String, mrz: PassportMrzInput) async throws -> PassportReadResult {
        #if canImport(ChipmunkNFC)
            guard let url = URL(string: serverURL), url.scheme?.hasPrefix("ws") == true else {
                throw PassportReaderError.invalidServerURL
            }
            let reader = NFCPassportReader(serverURL: url)
            let credentials: DocumentCredentials
            switch mrz {
            case let .fields(number, dateOfBirth, dateOfExpiry):
                credentials = DocumentCredentials(
                    passportNumber: number, dateOfBirth: dateOfBirth, dateOfExpiry: dateOfExpiry)
            case let .raw(rawMrz):
                credentials = DocumentCredentials(rawMrz: rawMrz)
            }
            // A PID-grade read: pull the DG2 portrait and run Passive Authentication.
            let options = ReadOptions(skipDG2: false, doAA: true, doPA: true)
            let display = DisplayOptions(nfcAlertMessage: "Hold your passport to the top of your iPhone")
            do {
                let result = try await reader.readDocument(
                    credentials: credentials, options: options, display: display)
                guard let doc = result.document else {
                    // Ship / reader-token flow: no inline document — surface the token so the caller
                    // can redeem it (or forward it to VCIssuer). Echo the typed number if we have it.
                    let echoedNumber: String
                    if case let .fields(number, _, _) = mrz { echoedNumber = number } else { echoedNumber = "" }
                    return PassportReadResult(
                        holderName: "", documentNumber: echoedNumber, dateOfBirth: "",
                        dateOfExpiry: "", nationality: "", issuingState: "", portrait: nil,
                        resultToken: result.resultToken)
                }
                return PassportReadResult(
                    holderName: doc.holderName, documentNumber: doc.documentNumber,
                    dateOfBirth: doc.dateOfBirth, dateOfExpiry: doc.dateOfExpiry,
                    nationality: doc.nationality, issuingState: doc.issuingState,
                    portrait: doc.imgdata.isEmpty ? nil : doc.imgdata,
                    resultToken: result.resultToken)
            } catch {
                throw PassportReaderError.underlying(error.localizedDescription)
            }
        #else
            _ = (serverURL, mrz)
            throw PassportReaderError.readerNotLinked
        #endif
    }
}
