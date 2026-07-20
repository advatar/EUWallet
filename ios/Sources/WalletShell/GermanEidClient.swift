import Foundation
import Security

/// Native-only boundary for the AusweisApp SDK protocol. None of these types conform to Codable
/// or cross the Rust/UniFFI event boundary.
public enum GermanEidClientError: Error, Equatable {
    case invalidConfiguration
    case invalidTransition
    case unsupportedApiLevel
    case invalidAccessRights
    case invalidCertificate
    case invalidCardState
    case invalidSecret
    case secretAlreadyConsumed
    case invalidResult
    case adapterFailure
    case staleSession
    case staleInteraction
    case alreadyTerminal
}

/// A state-machine rejection. If `recovery.commands` contains CANCEL, the native adapter must send
/// it and continue waiting for the terminal AUTH result; the coordinator deliberately remains in
/// its cancelling state so a live NFC workflow cannot be orphaned.
public struct GermanEidFlowFailure: Error, @unchecked Sendable {
    public let reason: GermanEidClientError
    public let recovery: GermanEidOutput
}

/// Opaque 256-bit adapter generation chosen with the platform CSPRNG. It is correlation data, not
/// an authentication secret, and is redacted so stale-session diagnostics cannot become tracking.
public struct GermanEidSessionID: Hashable, Sendable, CustomStringConvertible,
    CustomDebugStringConvertible
{
    fileprivate let bytes: [UInt8]

    init(_ bytes: [UInt8]) throws {
        guard bytes.count == 32, bytes.contains(where: { $0 != 0 }) else {
            throw GermanEidClientError.invalidConfiguration
        }
        self.bytes = bytes
    }

    public static func random() throws -> GermanEidSessionID {
        var bytes = [UInt8](repeating: 0, count: 32)
        let status = bytes.withUnsafeMutableBytes { raw in
            SecRandomCopyBytes(kSecRandomDefault, raw.count, raw.baseAddress!)
        }
        guard status == errSecSuccess else {
            throw GermanEidClientError.invalidConfiguration
        }
        return try GermanEidSessionID(bytes)
    }

    public var description: String { "GermanEidSessionID([REDACTED])" }
    public var debugDescription: String { description }
}

/// Coordinator-issued holder-interaction generation. Callers must echo it exactly once.
public struct GermanEidInteractionID: Hashable, Sendable, CustomStringConvertible,
    CustomDebugStringConvertible
{
    fileprivate let value: UInt64

    fileprivate init(_ value: UInt64) { self.value = value }

    public var description: String { "GermanEidInteractionID([REDACTED])" }
    public var debugDescription: String { description }
}

private func germanEidCanonicalOrigin(_ value: String) throws -> String {
    let url: URL
    do {
        url = try ProductionURLPolicy.validated(value)
    } catch {
        throw GermanEidClientError.invalidConfiguration
    }
    guard url.query == nil,
          url.path.isEmpty || url.path == "/",
          let scheme = url.scheme,
          let host = url.host?.trimmingCharacters(in: CharacterSet(charactersIn: "[]"))
    else { throw GermanEidClientError.invalidConfiguration }
    var components = URLComponents()
    components.scheme = scheme
    components.host = host
    components.port = url.port
    guard let origin = components.string else {
        throw GermanEidClientError.invalidConfiguration
    }
    return origin
}

private func germanEidOrigin(of value: String) throws -> String {
    let url: URL
    do {
        url = try ProductionURLPolicy.validated(value)
    } catch {
        throw GermanEidClientError.invalidConfiguration
    }
    guard let scheme = url.scheme,
          let host = url.host?.trimmingCharacters(in: CharacterSet(charactersIn: "[]"))
    else { throw GermanEidClientError.invalidConfiguration }
    var components = URLComponents()
    components.scheme = scheme
    components.host = host
    components.port = url.port
    guard let origin = components.string else {
        throw GermanEidClientError.invalidConfiguration
    }
    return origin
}

/// The closed AusweisApp 2.5.4 access-right vocabulary used for holder-visible minimisation.
public enum GermanEidAccessRight: String, CaseIterable, Hashable {
    case address = "Address"
    case birthName = "BirthName"
    case familyName = "FamilyName"
    case givenNames = "GivenNames"
    case placeOfBirth = "PlaceOfBirth"
    case dateOfBirth = "DateOfBirth"
    case doctoralDegree = "DoctoralDegree"
    case artisticName = "ArtisticName"
    case pseudonym = "Pseudonym"
    case validUntil = "ValidUntil"
    case nationality = "Nationality"
    case issuingCountry = "IssuingCountry"
    case documentType = "DocumentType"
    case residencePermitI = "ResidencePermitI"
    case residencePermitII = "ResidencePermitII"
    case communityID = "CommunityID"
    case addressVerification = "AddressVerification"
    case ageVerification = "AgeVerification"
    case writeAddress = "WriteAddress"
    case writeCommunityID = "WriteCommunityID"
    case writeResidencePermitI = "WriteResidencePermitI"
    case writeResidencePermitII = "WriteResidencePermitII"
    case canAllowed = "CanAllowed"
    case pinManagement = "PinManagement"
}

/// An authenticated PID-provider contract. This PID-onboarding slice never permits write or
/// PIN-management rights. It also prohibits RUN_AUTH custom headers: AusweisApp forwards them to
/// the RefreshAddress selected inside the TcToken before the wallet can validate that origin.
public struct GermanEidProviderContract: Equatable, CustomStringConvertible,
    CustomDebugStringConvertible
{
    public let requiredRights: Set<GermanEidAccessRight>
    public let optionalRights: Set<GermanEidAccessRight>
    public let expectedTransactionInfo: String?
    public let expectedAuxiliaryData: GermanEidAuxiliaryData?
    fileprivate let tcTokenOrigin: String
    fileprivate let refreshOrigin: String
    fileprivate let communicationOrigins: Set<String>
    fileprivate let certificateSubjectName: String
    fileprivate let certificateSubjectOrigin: String

    public init(
        tcTokenOrigin: String,
        refreshOrigin: String,
        communicationOrigins: Set<String> = [],
        certificateSubjectName: String,
        certificateSubjectURLOrigin: String,
        requiredRights: Set<GermanEidAccessRight>,
        optionalRights: Set<GermanEidAccessRight> = [],
        expectedTransactionInfo: String? = nil,
        expectedAuxiliaryData: GermanEidAuxiliaryData? = nil
    ) throws {
        let administrativeRights: Set<GermanEidAccessRight> = [
            .writeAddress, .writeCommunityID, .writeResidencePermitI, .writeResidencePermitII,
            .pinManagement,
        ]
        guard !requiredRights.isEmpty,
              requiredRights.isDisjoint(with: optionalRights),
              requiredRights.union(optionalRights).isDisjoint(with: administrativeRights),
              communicationOrigins.count <= 8,
              !certificateSubjectName.isEmpty,
              certificateSubjectName.utf8.count <= 4 * 1_024,
              !certificateSubjectName.unicodeScalars.contains(where: {
                  $0.value < 0x20 || $0.value == 0x7f
              }),
              expectedTransactionInfo.map({
                  !$0.isEmpty && $0.utf8.count <= 8 * 1_024
              }) ?? true
        else { throw GermanEidClientError.invalidConfiguration }

        self.tcTokenOrigin = try germanEidCanonicalOrigin(tcTokenOrigin)
        self.refreshOrigin = try germanEidCanonicalOrigin(refreshOrigin)
        self.communicationOrigins = try Set(communicationOrigins.map(germanEidCanonicalOrigin))
        self.certificateSubjectName = certificateSubjectName
        self.certificateSubjectOrigin = try germanEidCanonicalOrigin(
            certificateSubjectURLOrigin)
        self.requiredRights = requiredRights
        self.optionalRights = optionalRights
        self.expectedTransactionInfo = expectedTransactionInfo
        self.expectedAuxiliaryData = expectedAuxiliaryData
    }

    fileprivate func permitsResult(outcome: GermanEidAuthenticationOutcome, url: String) -> Bool {
        guard let origin = try? germanEidOrigin(of: url) else { return false }
        switch outcome {
        case .success:
            return origin == refreshOrigin
        case .failure:
            return origin == refreshOrigin || communicationOrigins.contains(origin)
        }
    }

    fileprivate func permitsCertificate(_ certificate: GermanEidCertificate) -> Bool {
        certificate.subjectName == certificateSubjectName &&
            (try? germanEidOrigin(of: certificate.subjectURL)) == certificateSubjectOrigin
    }

    public var description: String { "GermanEidProviderContract([REDACTED])" }
    public var debugDescription: String { description }
}

public enum GermanEidSecretKind: String, Equatable {
    case pin
    case can
    case puk

    fileprivate var digitCount: Int {
        switch self {
        case .pin, .can: return 6
        case .puk: return 10
        }
    }
}

/// Owned secret memory with one-shot access and redacted diagnostics. The caller still owns and
/// must clear any source buffer it used to construct this value.
public final class GermanEidSensitiveBytes: CustomStringConvertible, CustomDebugStringConvertible {
    private var storage: [UInt8]
    private var consumed = false
    private let lock = NSRecursiveLock()

    public init(_ bytes: [UInt8], maximumBytes: Int = 32 * 1_024) throws {
        guard !bytes.isEmpty, maximumBytes > 0, bytes.count <= maximumBytes else {
            throw GermanEidClientError.invalidConfiguration
        }
        storage = bytes
    }

    deinit {
        _ = storage.withUnsafeMutableBytes { raw in
            raw.initializeMemory(as: UInt8.self, repeating: 0)
        }
    }

    public var isConsumed: Bool {
        lock.lock()
        defer { lock.unlock() }
        return consumed
    }

    public func clear() {
        lock.lock()
        defer { lock.unlock() }
        consumed = true
        _ = storage.withUnsafeMutableBytes { raw in
            raw.initializeMemory(as: UInt8.self, repeating: 0)
        }
    }

    /// Gives a trusted native adapter one synchronous view, then clears the owned storage even if
    /// the adapter throws. Retaining or copying the buffer is outside this boundary's guarantee.
    public func consume<Result>(
        _ body: (UnsafeRawBufferPointer) throws -> Result
    ) throws -> Result {
        lock.lock()
        defer { lock.unlock() }
        guard !consumed else { throw GermanEidClientError.secretAlreadyConsumed }
        consumed = true
        defer {
            _ = storage.withUnsafeMutableBytes { raw in
                raw.initializeMemory(as: UInt8.self, repeating: 0)
            }
        }
        return try storage.withUnsafeBytes { raw in try body(raw) }
    }

    public var description: String { "GermanEidSensitiveBytes([REDACTED])" }
    public var debugDescription: String { description }
}

public final class GermanEidCardSecret: CustomStringConvertible, CustomDebugStringConvertible {
    public let kind: GermanEidSecretKind
    private let bytes: GermanEidSensitiveBytes

    public init(kind: GermanEidSecretKind, digits: [UInt8]) throws {
        guard digits.count == kind.digitCount,
              digits.allSatisfy({ (48...57).contains($0) })
        else { throw GermanEidClientError.invalidSecret }
        self.kind = kind
        bytes = try GermanEidSensitiveBytes(digits, maximumBytes: kind.digitCount)
    }

    public var isConsumed: Bool { bytes.isConsumed }

    public func clear() { bytes.clear() }

    public func consume<Result>(
        _ body: (UnsafeRawBufferPointer) throws -> Result
    ) throws -> Result {
        try bytes.consume(body)
    }

    fileprivate func transferredCopy() throws -> GermanEidCardSecret {
        try consume { raw in
            var copy = Array(raw)
            defer {
                _ = copy.withUnsafeMutableBytes { bytes in
                    bytes.initializeMemory(as: UInt8.self, repeating: 0)
                }
            }
            return try GermanEidCardSecret(kind: kind, digits: copy)
        }
    }

    public var description: String { "GermanEidCardSecret(\(kind.rawValue), [REDACTED])" }
    public var debugDescription: String { description }
}

public struct GermanEidStartRequest: CustomStringConvertible, CustomDebugStringConvertible {
    fileprivate let tcTokenURL: GermanEidSensitiveBytes
    fileprivate let contract: GermanEidProviderContract
    fileprivate let sessionID: GermanEidSessionID

    public init(
        tcTokenURL: [UInt8],
        contract: GermanEidProviderContract,
        sessionID: GermanEidSessionID
    ) throws {
        guard !tcTokenURL.isEmpty,
              tcTokenURL.count <= ProductionURLPolicy.maximumURLBytes,
              tcTokenURL.allSatisfy({ (0x21...0x7e).contains($0) })
        else { throw GermanEidClientError.invalidConfiguration }
        let validatedURL = String(decoding: tcTokenURL, as: UTF8.self)
        guard try germanEidOrigin(of: validatedURL) == contract.tcTokenOrigin else {
            throw GermanEidClientError.invalidConfiguration
        }
        self.tcTokenURL = try GermanEidSensitiveBytes(
            tcTokenURL,
            maximumBytes: ProductionURLPolicy.maximumURLBytes)
        self.contract = contract
        self.sessionID = sessionID
    }

    public var description: String { "GermanEidStartRequest([REDACTED])" }
    public var debugDescription: String { description }

    public func clearSecrets() {
        tcTokenURL.clear()
    }

    fileprivate var hasAvailableSecrets: Bool {
        !tcTokenURL.isConsumed
    }
}

public struct GermanEidRunAuthCommand: CustomStringConvertible, CustomDebugStringConvertible {
    public let tcTokenURL: GermanEidSensitiveBytes
    public let sessionID: GermanEidSessionID
    /// Production composition must never make this configurable. A separate simulator fake is the
    /// only acceptable place for AusweisApp developer mode.
    public let developerMode = false
    public let statusMessages = true

    fileprivate init(request: GermanEidStartRequest) {
        tcTokenURL = request.tcTokenURL
        sessionID = request.sessionID
    }

    public var description: String { "GermanEidRunAuthCommand([REDACTED])" }
    public var debugDescription: String { description }

    public func clearSecrets() {
        tcTokenURL.clear()
    }
}

public struct GermanEidCertificate: Equatable, CustomStringConvertible, CustomDebugStringConvertible {
    public let issuerName: String
    public let issuerURL: String
    public let subjectName: String
    public let subjectURL: String
    public let termsOfUsage: String
    public let purpose: String
    public let effectiveDate: String
    public let expirationDate: String

    public init(
        issuerName: String,
        issuerURL: String,
        subjectName: String,
        subjectURL: String,
        termsOfUsage: String,
        purpose: String,
        effectiveDate: String,
        expirationDate: String
    ) throws {
        let fields = [issuerName, issuerURL, subjectName, subjectURL, purpose, effectiveDate,
                      expirationDate]
        guard fields.allSatisfy({ !$0.isEmpty && $0.utf8.count <= 4 * 1_024 }),
              !termsOfUsage.isEmpty,
              termsOfUsage.utf8.count <= 16 * 1_024,
              fields.reduce(termsOfUsage.utf8.count, { $0 + $1.utf8.count }) <= 32 * 1_024
        else { throw GermanEidClientError.invalidCertificate }
        self.issuerName = issuerName
        self.issuerURL = issuerURL
        self.subjectName = subjectName
        self.subjectURL = subjectURL
        self.termsOfUsage = termsOfUsage
        self.purpose = purpose
        self.effectiveDate = effectiveDate
        self.expirationDate = expirationDate
    }

    public var description: String { "GermanEidCertificate([REDACTED])" }
    public var debugDescription: String { description }
}

public struct GermanEidAuxiliaryData: Equatable, CustomStringConvertible, CustomDebugStringConvertible {
    public let ageVerificationDate: String?
    public let requiredAge: String?
    public let validityDate: String?
    public let communityID: String?

    public init(
        ageVerificationDate: String? = nil,
        requiredAge: String? = nil,
        validityDate: String? = nil,
        communityID: String? = nil
    ) throws {
        let values = [ageVerificationDate, requiredAge, validityDate, communityID]
        guard values.contains(where: { $0 != nil }),
              values.compactMap({ $0 }).allSatisfy({
                  !$0.isEmpty && $0.utf8.count <= 256 && !$0.unicodeScalars.contains(where: {
                      $0.value < 0x20 || $0.value == 0x7f
                  })
              }),
              values.compactMap({ $0 }).reduce(0, { $0 + $1.utf8.count }) <= 1_024
        else { throw GermanEidClientError.invalidAccessRights }
        self.ageVerificationDate = ageVerificationDate
        self.requiredAge = requiredAge
        self.validityDate = validityDate
        self.communityID = communityID
    }

    public var description: String { "GermanEidAuxiliaryData([REDACTED])" }
    public var debugDescription: String { description }
}

/// One bounded ACCESS_RIGHTS message. Provider transaction/auxiliary information is preserved for
/// consent and must remain identical across the optional-right minimisation round trip.
public struct GermanEidAccessRights: Equatable, CustomStringConvertible, CustomDebugStringConvertible {
    public let required: Set<GermanEidAccessRight>
    public let optional: Set<GermanEidAccessRight>
    public let effective: Set<GermanEidAccessRight>
    public let transactionInfo: String?
    public let auxiliaryData: GermanEidAuxiliaryData?

    public init(
        required: Set<GermanEidAccessRight>,
        optional: Set<GermanEidAccessRight>,
        effective: Set<GermanEidAccessRight>,
        transactionInfo: String? = nil,
        auxiliaryData: GermanEidAuxiliaryData? = nil
    ) throws {
        guard required.count + optional.count <= GermanEidAccessRight.allCases.count,
              required.isDisjoint(with: optional),
              effective.isSubset(of: required.union(optional)),
              transactionInfo.map({
                  !$0.isEmpty && $0.utf8.count <= 8 * 1_024
              }) ?? true
        else { throw GermanEidClientError.invalidAccessRights }
        self.required = required
        self.optional = optional
        self.effective = effective
        self.transactionInfo = transactionInfo
        self.auxiliaryData = auxiliaryData
    }

    public var description: String { "GermanEidAccessRights([REDACTED])" }
    public var debugDescription: String { description }
}

public enum GermanEidCardState: Equatable {
    case absent
    case unknown
    /// Exact simultaneous fields of a non-empty SDK card object. These facts are deliberately not
    /// collapsed into mutually exclusive states: a deactivated card still has a retry counter,
    /// and ENTER_PUK can report an inoperative PUK alongside that counter.
    case present(retryCounter: UInt8?, deactivated: Bool, inoperative: Bool)
}

/// Trusted classification supplied by the native SDK adapter. The adapter may assert
/// `integratedNfc` only for the platform-owned NFC reader; it must not infer this from the public
/// `attached`, `insertable`, or `keypad` fields because external readers can share those values.
public enum GermanEidReaderKind: Equatable {
    case integratedNfc
    case unsupportedExternal
}

/// Reader facts carried by READER and ENTER_PIN/CAN/PUK. This first production slice accepts card
/// secrets only for an explicitly attested, attached, non-virtual, non-keypad integrated reader.
public struct GermanEidReaderState: Equatable {
    public let kind: GermanEidReaderKind
    public let attached: Bool
    public let insertable: Bool
    public let keypad: Bool
    public let card: GermanEidCardState

    public init(
        kind: GermanEidReaderKind,
        attached: Bool,
        insertable: Bool,
        keypad: Bool,
        card: GermanEidCardState
    ) {
        self.kind = kind
        self.attached = attached
        self.insertable = insertable
        self.keypad = keypad
        self.card = card
    }

    fileprivate var isSupportedIntegratedNfc: Bool {
        kind == .integratedNfc && attached && !insertable && !keypad
    }
}

public enum GermanEidPauseCause: Equatable {
    case badCardPosition
}

public enum GermanEidFailureReason: String, Equatable {
    case cancelled
    case card
    case communication
    case sdk
    case unknown
}

public enum GermanEidAuthenticationOutcome: Equatable {
    case success
    case failure(GermanEidFailureReason)
}

public struct GermanEidAuthenticationResult: CustomStringConvertible, CustomDebugStringConvertible {
    public let outcome: GermanEidAuthenticationOutcome
    public let refreshOrCommunicationURL: GermanEidSensitiveBytes?
    fileprivate let contract: GermanEidProviderContract
    fileprivate let sessionID: GermanEidSessionID

    public init(
        outcome: GermanEidAuthenticationOutcome,
        url: [UInt8]?,
        contract: GermanEidProviderContract,
        sessionID: GermanEidSessionID
    ) throws {
        if outcome == .success && url == nil { throw GermanEidClientError.invalidResult }
        if let url {
            guard !url.isEmpty,
                  url.count <= ProductionURLPolicy.maximumURLBytes,
                  url.allSatisfy({ (0x21...0x7e).contains($0) })
            else { throw GermanEidClientError.invalidResult }
            let validatedURL = String(decoding: url, as: UTF8.self)
            guard contract.permitsResult(outcome: outcome, url: validatedURL) else {
                throw GermanEidClientError.invalidResult
            }
            refreshOrCommunicationURL = try GermanEidSensitiveBytes(
                url,
                maximumBytes: ProductionURLPolicy.maximumURLBytes)
        } else {
            refreshOrCommunicationURL = nil
        }
        self.outcome = outcome
        self.contract = contract
        self.sessionID = sessionID
    }

    public var description: String { "GermanEidAuthenticationResult(\(outcome), [REDACTED])" }
    public var debugDescription: String { description }

    public func clearSecrets() { refreshOrCommunicationURL?.clear() }
}

public struct GermanEidConsent: Equatable, CustomStringConvertible, CustomDebugStringConvertible {
    public let effectiveRights: Set<GermanEidAccessRight>
    public let certificate: GermanEidCertificate
    public let transactionInfo: String?
    public let auxiliaryData: GermanEidAuxiliaryData?

    public var description: String { "GermanEidConsent([REDACTED])" }
    public var debugDescription: String { description }
}

public enum GermanEidSdkCommand: CustomStringConvertible, CustomDebugStringConvertible {
    case getApiLevel
    case setApiLevel(Int)
    case runAuth(GermanEidRunAuthCommand)
    case setAccessRights(Set<GermanEidAccessRight>)
    case getCertificate
    case accept
    case cancel
    /// The iOS adapter maps this to INTERRUPT before showing custom PIN/CAN/PUK UI; Android treats
    /// it as a local no-op because AusweisApp's INTERRUPT affects only the iOS system dialog.
    case interruptSystemDialog
    case continueAfterPause
    case setSecret(GermanEidCardSecret)

    public var description: String {
        switch self {
        case .getApiLevel: return "getApiLevel"
        case .setApiLevel: return "setApiLevel"
        case .runAuth: return "runAuth([REDACTED])"
        case .setAccessRights: return "setAccessRights"
        case .getCertificate: return "getCertificate"
        case .accept: return "accept"
        case .cancel: return "cancel"
        case .interruptSystemDialog: return "interruptSystemDialog"
        case .continueAfterPause: return "continueAfterPause"
        case .setSecret(let value): return "setSecret(\(value.kind.rawValue), [REDACTED])"
        }
    }

    public var debugDescription: String { description }

    public func clearSecrets() {
        switch self {
        case .runAuth(let command): command.clearSecrets()
        case .setSecret(let secret): secret.clear()
        default: break
        }
    }
}

public enum GermanEidUiEvent: CustomStringConvertible, CustomDebugStringConvertible {
    case consent(GermanEidConsent, interactionID: GermanEidInteractionID)
    case reader(GermanEidReaderState)
    case cardRequired
    case paused(GermanEidPauseCause, interactionID: GermanEidInteractionID)
    case secretRequested(
        kind: GermanEidSecretKind,
        retryCounter: UInt8?,
        interactionID: GermanEidInteractionID)
    case completed(GermanEidAuthenticationResult)

    public var description: String {
        switch self {
        case .consent: return "consent([REDACTED])"
        case .reader: return "reader"
        case .cardRequired: return "cardRequired"
        case .paused: return "paused"
        case .secretRequested(let kind, _, _): return "secretRequested(\(kind.rawValue))"
        case .completed: return "completed([REDACTED])"
        }
    }

    public var debugDescription: String { description }

    public func clearSecrets() {
        if case .completed(let result) = self { result.clearSecrets() }
    }
}

public struct GermanEidOutput: CustomStringConvertible, CustomDebugStringConvertible {
    /// Adapters must execute commands in array order before presenting any `uiEvents` from the
    /// same output. This is security-relevant for ENTER_* failures, where iOS INTERRUPT must close
    /// the system dialog before CANCEL and holder-visible error presentation.
    public let commands: [GermanEidSdkCommand]
    public let uiEvents: [GermanEidUiEvent]

    fileprivate init(
        commands: [GermanEidSdkCommand] = [],
        uiEvents: [GermanEidUiEvent] = []
    ) {
        self.commands = commands
        self.uiEvents = uiEvents
    }

    public var description: String {
        "GermanEidOutput(commands: \(commands), uiEvents: \(uiEvents))"
    }
    public var debugDescription: String { description }

    public func clearSecrets() {
        commands.forEach { $0.clearSecrets() }
        uiEvents.forEach { $0.clearSecrets() }
    }
}

public enum GermanEidSdkEvent {
    case apiLevels(available: Set<Int>)
    case apiLevelSelected(Int)
    case authenticationStarted
    case accessRights(GermanEidAccessRights)
    case certificate(GermanEidCertificate)
    case reader(GermanEidReaderState)
    case cardRequired
    case paused(GermanEidPauseCause)
    case secretRequested(kind: GermanEidSecretKind, reader: GermanEidReaderState)
    case authenticationFinished(GermanEidAuthenticationResult)
    case authenticationResultInvalid
    case authenticationStartFailed
    case adapterFailed
    case cancellationTimedOut
}

public enum GermanEidUserAction {
    case accept(GermanEidInteractionID)
    case cancel
    case continueAfterPause(GermanEidInteractionID)
    case submitSecret(GermanEidCardSecret, interactionID: GermanEidInteractionID)
}

/// Native application seam. A production implementation composes this deterministic coordinator
/// with the official AusweisApp SDK; tests can drive it without linking that binary framework.
public protocol GermanEidClient: AnyObject {
    func start(_ request: GermanEidStartRequest) throws -> GermanEidOutput
    func receive(
        _ event: GermanEidSdkEvent,
        sessionID: GermanEidSessionID
    ) throws -> GermanEidOutput
    func act(
        _ action: GermanEidUserAction,
        sessionID: GermanEidSessionID
    ) throws -> GermanEidOutput
    func shutdown(sessionID: GermanEidSessionID) throws -> GermanEidOutput
}

/// Deterministic, one-shot, sans-SDK state machine used by the official adapter and unit tests.
/// All entry points are serialized because SDK callbacks and holder actions arrive on different
/// threads. A production adapter must create one coordinator per generation and drop callbacks
/// tagged with any older generation before calling `receive`.
public final class DeterministicGermanEidClient: GermanEidClient, @unchecked Sendable {
    private enum State {
        case idle
        case awaitingApiLevels(GermanEidStartRequest)
        case awaitingApiSelection(GermanEidStartRequest, Int)
        case awaitingAuthStart
        case awaitingInitialRights
        case awaitingMinimizedRights(GermanEidAccessRights)
        case awaitingCertificate(GermanEidAccessRights)
        case awaitingConsent(GermanEidConsent, GermanEidInteractionID)
        case running
        case awaitingSecret(GermanEidSecretKind, GermanEidInteractionID)
        case paused(GermanEidInteractionID)
        case cancelling(reason: GermanEidFailureReason, startWasPending: Bool)
        case terminal
    }

    private let supportedApiLevels: Set<Int>
    private let stateLock = NSLock()
    private var state: State = .idle
    private var activeContract: GermanEidProviderContract?
    private var activeSessionID: GermanEidSessionID?
    private var authorizationAccepted = false
    private var authorizedRights: Set<GermanEidAccessRight> = []
    private var lastReader: GermanEidReaderState?
    private var interactionCounter: UInt64 = 0
    private var lastAcceptedConsent: GermanEidInteractionID?
    private var lastContinuedPause: GermanEidInteractionID?
    private var lastSubmittedSecret: GermanEidInteractionID?

    public init(supportedApiLevels: Set<Int> = [2, 3]) throws {
        guard !supportedApiLevels.isEmpty,
              supportedApiLevels.count <= 8,
              supportedApiLevels.allSatisfy({ (2...3).contains($0) })
        else { throw GermanEidClientError.invalidConfiguration }
        self.supportedApiLevels = supportedApiLevels
    }

    deinit {
        stateLock.lock()
        clearHeldSecrets()
        state = .terminal
        stateLock.unlock()
    }

    public func start(_ request: GermanEidStartRequest) throws -> GermanEidOutput {
        stateLock.lock()
        defer { stateLock.unlock() }
        guard case .idle = state else {
            request.clearSecrets()
            return try fail(.invalidTransition)
        }
        activeContract = request.contract
        activeSessionID = request.sessionID
        state = .awaitingApiLevels(request)
        return GermanEidOutput(commands: [.getApiLevel])
    }

    public func receive(
        _ event: GermanEidSdkEvent,
        sessionID: GermanEidSessionID
    ) throws -> GermanEidOutput {
        stateLock.lock()
        defer { stateLock.unlock() }
        guard sessionID == activeSessionID else {
            clearSecrets(in: event)
            throw GermanEidFlowFailure(
                reason: .staleSession,
                recovery: GermanEidOutput())
        }
        if case .terminal = state {
            clearSecrets(in: event)
            return try fail(.alreadyTerminal)
        }
        if case .cancelling(let reason, let startWasPending) = state {
            switch event {
            case .authenticationFinished(let result):
                guard result.sessionID == activeSessionID else {
                    result.clearSecrets()
                    throw GermanEidFlowFailure(
                        reason: .staleSession,
                        recovery: GermanEidOutput())
                }
                guard result.contract == activeContract else {
                    result.clearSecrets()
                    return try terminalFailure(.invalidResult, reason: reason)
                }
                if result.outcome == .success {
                    result.clearSecrets()
                    let cancelled = try localFailureResult(reason: reason)
                    state = .terminal
                    return GermanEidOutput(uiEvents: [.completed(cancelled)])
                }
                state = .terminal
                return GermanEidOutput(uiEvents: [.completed(result)])
            case .authenticationResultInvalid:
                return try terminalFailure(.invalidResult, reason: .sdk)
            case .authenticationStarted where startWasPending:
                state = .cancelling(reason: reason, startWasPending: false)
                return GermanEidOutput()
            case .authenticationStartFailed:
                guard startWasPending else { return GermanEidOutput() }
                let result = try localFailureResult(reason: reason)
                state = .terminal
                return GermanEidOutput(uiEvents: [.completed(result)])
            case .adapterFailed, .cancellationTimedOut:
                return try terminalFailure(.adapterFailure, reason: reason)
            default:
                // CANCEL is already in flight. Benign callbacks are ignored until terminal AUTH
                // or the adapter's explicit bounded timeout/failure event.
                clearSecrets(in: event)
                return GermanEidOutput()
            }
        }

        if case .authenticationFinished(let result) = event {
            guard result.sessionID == activeSessionID else {
                result.clearSecrets()
                throw GermanEidFlowFailure(
                    reason: .staleSession,
                    recovery: GermanEidOutput())
            }
            guard workflowConfirmed, result.contract == activeContract else {
                result.clearSecrets()
                return try terminalFailure(.invalidResult, reason: .sdk)
            }
            if result.outcome == .success {
                guard authorizationAccepted, successMayFinish else {
                    result.clearSecrets()
                    return try terminalFailure(.invalidResult, reason: .sdk)
                }
            }
            state = .terminal
            return GermanEidOutput(uiEvents: [.completed(result)])
        }

        switch event {
        case .authenticationResultInvalid:
            return try terminalFailure(.invalidResult, reason: .sdk)
        case .authenticationStartFailed:
            guard case .awaitingAuthStart = state else { return try fail(.adapterFailure) }
            let result = try localFailureResult(reason: .sdk)
            state = .terminal
            return GermanEidOutput(uiEvents: [.completed(result)])
        case .adapterFailed:
            return try fail(.adapterFailure)
        case .cancellationTimedOut:
            return try fail(.invalidTransition)
        default:
            break
        }

        // READER is an asynchronous SDK notification and can arrive during API negotiation,
        // consent preparation, an active scan, or PAUSE. Treat a well-formed update as benign in
        // every active state. Only an outstanding secret prompt is invalidated by a material
        // reader change; PAUSE and all pre-consent states retain their exact interaction/state.
        if case .reader(let reader) = event {
            return try receiveReader(reader)
        }

        switch (state, event) {
        case (.awaitingApiLevels(let request), .apiLevels(let available)):
            guard !available.isEmpty,
                  available.count <= 8,
                  available.allSatisfy({ (1...16).contains($0) }),
                  let selected = supportedApiLevels.intersection(available).max()
            else { return try fail(.unsupportedApiLevel) }
            state = .awaitingApiSelection(request, selected)
            return GermanEidOutput(commands: [.setApiLevel(selected)])

        case (.awaitingApiSelection(let request, let expected), .apiLevelSelected(let selected)):
            guard selected == expected, request.hasAvailableSecrets else {
                return try fail(selected == expected ? .invalidConfiguration : .unsupportedApiLevel)
            }
            state = .awaitingAuthStart
            return GermanEidOutput(commands: [.runAuth(GermanEidRunAuthCommand(request: request))])

        case (.awaitingAuthStart, .authenticationStarted):
            state = .awaitingInitialRights
            return GermanEidOutput()

        case (.awaitingInitialRights, .accessRights(let rights)):
            guard let contract = activeContract,
                  rights.required == contract.requiredRights,
                  rights.optional == contract.optionalRights,
                  rights.effective == rights.required.union(rights.optional),
                  rights.transactionInfo == contract.expectedTransactionInfo,
                  rights.auxiliaryData == contract.expectedAuxiliaryData
            else { return try fail(.invalidAccessRights) }
            state = .awaitingMinimizedRights(rights)
            return GermanEidOutput(commands: [.setAccessRights([])])

        case (.awaitingMinimizedRights(let initial), .accessRights(let minimized)):
            guard minimized.required == initial.required,
                  minimized.optional == initial.optional,
                  minimized.effective == initial.required,
                  minimized.transactionInfo == initial.transactionInfo,
                  minimized.auxiliaryData == initial.auxiliaryData
            else { return try fail(.invalidAccessRights) }
            state = .awaitingCertificate(minimized)
            return GermanEidOutput(commands: [.getCertificate])

        case (.awaitingCertificate(let rights), .certificate(let certificate)):
            guard let contract = activeContract,
                  contract.permitsCertificate(certificate)
            else { return try fail(.invalidCertificate) }
            let consent = GermanEidConsent(
                effectiveRights: rights.effective,
                certificate: certificate,
                transactionInfo: rights.transactionInfo,
                auxiliaryData: rights.auxiliaryData)
            let interactionID = try nextInteractionID()
            state = .awaitingConsent(consent, interactionID)
            return GermanEidOutput(uiEvents: [
                .consent(consent, interactionID: interactionID)
            ])

        case (.running, .cardRequired), (.awaitingSecret, .cardRequired):
            lastReader = nil
            state = .running
            return GermanEidOutput(uiEvents: [.cardRequired])

        case (.running, .secretRequested(let kind, let reader)):
            guard secretRequestIsValid(kind: kind, reader: reader) else {
                return try failSecretRequest(.invalidCardState, reader: reader)
            }
            lastReader = reader
            let interactionID = try nextInteractionID()
            state = .awaitingSecret(kind, interactionID)
            return GermanEidOutput(
                commands: [.interruptSystemDialog],
                uiEvents: [.secretRequested(
                    kind: kind,
                    retryCounter: retryCounter(of: reader),
                    interactionID: interactionID)])

        case (.running, .paused(let cause)):
            let interactionID = try nextInteractionID()
            state = .paused(interactionID)
            return GermanEidOutput(uiEvents: [
                .paused(cause, interactionID: interactionID)
            ])

        case (.awaitingSecret, .paused(let cause)):
            let interactionID = try nextInteractionID()
            state = .paused(interactionID)
            return GermanEidOutput(uiEvents: [
                .paused(cause, interactionID: interactionID)
            ])

        default:
            return try fail(.invalidTransition)
        }
    }

    public func act(
        _ action: GermanEidUserAction,
        sessionID: GermanEidSessionID
    ) throws -> GermanEidOutput {
        stateLock.lock()
        defer { stateLock.unlock() }
        guard sessionID == activeSessionID else {
            clearSecrets(in: action)
            throw GermanEidFlowFailure(
                reason: .staleSession,
                recovery: GermanEidOutput())
        }
        if case .terminal = state {
            clearSecrets(in: action)
            return try fail(.alreadyTerminal)
        }
        if case .cancelling = state {
            if case .cancel = action { return GermanEidOutput() }
            clearSecrets(in: action)
            return try fail(.invalidTransition)
        }
        switch action {
        case .accept(let interactionID) where interactionID == lastAcceptedConsent:
            if case .running = state { return GermanEidOutput() }
            return try rejectStaleInteraction(action)
        case .continueAfterPause(let interactionID) where interactionID == lastContinuedPause:
            if case .running = state { return GermanEidOutput() }
            return try rejectStaleInteraction(action)
        case .submitSecret(let secret, let interactionID)
            where interactionID == lastSubmittedSecret:
            if case .running = state {
                secret.clear()
                return GermanEidOutput()
            }
            return try rejectStaleInteraction(action)
        default:
            break
        }
        switch (state, action) {
        case (.awaitingApiLevels, .cancel), (.awaitingApiSelection, .cancel):
            // The holder may cancel immediately after start. RUN_AUTH has not been emitted yet,
            // so there is no SDK workflow to cancel; wipe the retained TcToken URL and finish
            // locally instead of surfacing a flow error for a fast cancel tap.
            clearHeldSecrets()
            let result = try localFailureResult(reason: .cancelled)
            state = .terminal
            return GermanEidOutput(uiEvents: [.completed(result)])

        case (
            .awaitingConsent(let consent, let expectedInteractionID),
            .accept(let interactionID)
        ):
            guard interactionID == expectedInteractionID else {
                return try rejectStaleInteraction(action)
            }
            authorizationAccepted = true
            authorizedRights = consent.effectiveRights
            lastAcceptedConsent = interactionID
            state = .running
            return GermanEidOutput(commands: [.accept])

        case (
            .awaitingSecret(let expected, let expectedInteractionID),
            .submitSecret(let secret, let interactionID)
        ):
            guard interactionID == expectedInteractionID else {
                return try rejectStaleInteraction(action)
            }
            guard secret.kind == expected,
                  !secret.isConsumed,
                  let reader = lastReader,
                  secretRequestIsValid(kind: expected, reader: reader)
            else {
                secret.clear()
                return try fail(.invalidSecret)
            }
            let transferred = try secret.transferredCopy()
            lastSubmittedSecret = interactionID
            state = .running
            return GermanEidOutput(commands: [.setSecret(transferred)])

        case (
            .paused(let expectedInteractionID),
            .continueAfterPause(let interactionID)
        ):
            guard interactionID == expectedInteractionID else {
                return try rejectStaleInteraction(action)
            }
            lastContinuedPause = interactionID
            // Any pre-pause secret prompt stays invalid. The adapter waits for a fresh ENTER_*
            // callback after CONTINUE before showing or accepting card-secret input again.
            state = .running
            return GermanEidOutput(commands: [.continueAfterPause])

        case (_, .cancel):
            guard workflowMayBeLive else { return try fail(.invalidTransition) }
            state = .cancelling(
                reason: .cancelled,
                startWasPending: authenticationStartIsPending)
            return GermanEidOutput(commands: [.cancel])

        default:
            switch action {
            case .accept, .continueAfterPause, .submitSecret:
                return try rejectStaleInteraction(action)
            case .cancel:
                return try fail(.invalidTransition)
            }
        }
    }

    public func shutdown(sessionID: GermanEidSessionID) throws -> GermanEidOutput {
        stateLock.lock()
        defer { stateLock.unlock() }
        guard sessionID == activeSessionID else {
            throw GermanEidFlowFailure(
                reason: .staleSession,
                recovery: GermanEidOutput())
        }
        if case .terminal = state { return GermanEidOutput() }
        if case .cancelling = state { return GermanEidOutput() }
        let startWasPending = authenticationStartIsPending
        clearHeldSecrets()
        if workflowMayBeLive {
            state = .cancelling(reason: .sdk, startWasPending: startWasPending)
            return GermanEidOutput(commands: [.cancel])
        }
        state = .terminal
        return GermanEidOutput()
    }

    private var workflowConfirmed: Bool {
        switch state {
        case .awaitingInitialRights, .awaitingMinimizedRights, .awaitingCertificate,
             .awaitingConsent, .running, .awaitingSecret, .paused, .cancelling:
            return true
        case .idle, .awaitingApiLevels, .awaitingApiSelection, .awaitingAuthStart, .terminal:
            return false
        }
    }

    private var workflowMayBeLive: Bool {
        if case .awaitingAuthStart = state { return true }
        return workflowConfirmed
    }

    private var authenticationStartIsPending: Bool {
        if case .awaitingAuthStart = state { return true }
        return false
    }

    private var successMayFinish: Bool {
        if case .running = state { return true }
        return false
    }

    private func receiveReader(_ reader: GermanEidReaderState) throws -> GermanEidOutput {
        guard readerIsWellFormed(reader) else { return try fail(.invalidCardState) }
        let priorReader = lastReader
        let scanDialogMayBeLive: Bool
        switch state {
        case .running, .awaitingSecret, .paused:
            scanDialogMayBeLive = true
        default:
            scanDialogMayBeLive = false
        }
        if case .awaitingSecret(let kind, _) = state,
           (priorReader != reader || !secretRequestIsValid(kind: kind, reader: reader))
        {
            state = .running
        }
        lastReader = reader
        let commands: [GermanEidSdkCommand]
        switch reader.card {
        case .present(_, deactivated: true, _) where scanDialogMayBeLive:
            commands = [.interruptSystemDialog]
        default:
            commands = []
        }
        return GermanEidOutput(commands: commands, uiEvents: [.reader(reader)])
    }

    private func readerIsWellFormed(_ reader: GermanEidReaderState) -> Bool {
        if reader.kind == .integratedNfc && (reader.insertable || reader.keypad) { return false }
        if !reader.attached {
            return !reader.keypad && reader.card == .absent
        }
        if case .present(let retryCounter, _, _) = reader.card {
            return retryCounter.map({ $0 <= 3 }) ?? true
        }
        return true
    }

    private func retryCounter(of reader: GermanEidReaderState) -> UInt8? {
        if case .present(let retryCounter, _, _) = reader.card { return retryCounter }
        return nil
    }

    private func secretRequestIsValid(
        kind: GermanEidSecretKind,
        reader: GermanEidReaderState
    ) -> Bool {
        guard readerIsWellFormed(reader), reader.isSupportedIntegratedNfc,
              case .present(
                  let rawRetryCounter,
                  let deactivated,
                  let inoperative) = reader.card,
              let retryCounter = rawRetryCounter
        else { return false }
        switch kind {
        case .pin:
            return !deactivated && !inoperative && (1...3).contains(retryCounter)
        case .can:
            let canAllowed = authorizedRights.contains(.canAllowed)
            // `inoperative` means only that PUK can no longer unblock the PIN. An authenticated
            // CAN_ALLOWED terminal deliberately bypasses PIN/PUK and can still use ENTER_CAN.
            return canAllowed || (!deactivated && !inoperative && retryCounter == 1)
        case .puk:
            return !deactivated && !inoperative && retryCounter == 0
        }
    }

    private func nextInteractionID() throws -> GermanEidInteractionID {
        guard interactionCounter < UInt64.max else {
            _ = try fail(.adapterFailure)
            throw GermanEidClientError.adapterFailure
        }
        interactionCounter += 1
        return GermanEidInteractionID(interactionCounter)
    }

    private func rejectStaleInteraction(
        _ action: GermanEidUserAction
    ) throws -> GermanEidOutput {
        clearSecrets(in: action)
        throw GermanEidFlowFailure(
            reason: .staleInteraction,
            recovery: GermanEidOutput())
    }

    private func localFailureResult(
        reason: GermanEidFailureReason? = nil
    ) throws -> GermanEidAuthenticationResult {
        guard let contract = activeContract,
              let sessionID = activeSessionID
        else { throw GermanEidClientError.invalidResult }
        let effectiveReason: GermanEidFailureReason
        if let reason {
            effectiveReason = reason
        } else if case .cancelling(let current, _) = state {
            effectiveReason = current
        } else {
            effectiveReason = .sdk
        }
        return try GermanEidAuthenticationResult(
            outcome: .failure(effectiveReason),
            url: nil,
            contract: contract,
            sessionID: sessionID)
    }

    private func fail(_ error: GermanEidClientError) throws -> GermanEidOutput {
        let startWasPending = authenticationStartIsPending
        clearHeldSecrets()
        let recovery: GermanEidOutput
        if case .cancelling = state {
            recovery = GermanEidOutput()
        } else if workflowMayBeLive {
            state = .cancelling(reason: .sdk, startWasPending: startWasPending)
            recovery = GermanEidOutput(commands: [.cancel])
        } else {
            state = .terminal
            recovery = GermanEidOutput()
        }
        throw GermanEidFlowFailure(reason: error, recovery: recovery)
    }

    private func failSecretRequest(
        _ error: GermanEidClientError,
        reader: GermanEidReaderState
    ) throws -> GermanEidOutput {
        clearHeldSecrets()
        state = .cancelling(reason: .sdk, startWasPending: false)
        throw GermanEidFlowFailure(
            reason: error,
            recovery: GermanEidOutput(
                commands: [.interruptSystemDialog, .cancel],
                uiEvents: [.reader(reader)]))
    }

    private func clearHeldSecrets() {
        switch state {
        case .awaitingApiLevels(let request), .awaitingApiSelection(let request, _):
            request.clearSecrets()
        default:
            break
        }
    }

    private func terminalFailure(
        _ error: GermanEidClientError,
        reason: GermanEidFailureReason
    ) throws -> GermanEidOutput {
        clearHeldSecrets()
        let completion = try? localFailureResult(reason: reason)
        state = .terminal
        let recovery = GermanEidOutput(
            uiEvents: completion.map { [.completed($0)] } ?? [])
        throw GermanEidFlowFailure(reason: error, recovery: recovery)
    }

    private func clearSecrets(in event: GermanEidSdkEvent) {
        if case .authenticationFinished(let result) = event { result.clearSecrets() }
    }

    private func clearSecrets(in action: GermanEidUserAction) {
        if case .submitSecret(let secret, _) = action { secret.clear() }
    }
}
