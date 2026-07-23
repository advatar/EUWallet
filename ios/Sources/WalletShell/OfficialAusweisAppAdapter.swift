#if canImport(AusweisApp2SDKWrapper)
import AusweisApp2SDKWrapper
import Foundation

/// Production bridge from the official AusweisApp 2.5.4 Swift wrapper to the wallet's
/// deterministic, fail-closed German eID coordinator.
///
/// AusweisApp callbacks can arrive off the main thread. This adapter serializes them, tags every
/// callback with the active 256-bit generation, executes coordinator commands in order, and only
/// then releases holder-visible events. Process death invalidates the generation and must start a
/// new authentication; PIN, CAN, PUK, TcToken and refresh URLs are never persisted here.
@available(iOS 17, *)
public final class OfficialAusweisAppAdapter: NSObject, GermanEidClient, WorkflowCallbacks,
    @unchecked Sendable
{
    public typealias OutputHandler = @Sendable (GermanEidOutput) -> Void

    private let controller: WorkflowController
    private let coordinator: DeterministicGermanEidClient
    private let callbackQueue = DispatchQueue(label: "eu.advatar.wallet.ausweisapp")
    private let outputHandler: OutputHandler
    private var activeSessionID: GermanEidSessionID?
    private var pendingRunAuth: GermanEidRunAuthCommand?
    private var stopped = false

    public init(
        controller: WorkflowController = AA2SDKWrapper.workflowController,
        coordinator: DeterministicGermanEidClient,
        outputHandler: @escaping OutputHandler
    ) {
        self.controller = controller
        self.coordinator = coordinator
        self.outputHandler = outputHandler
        super.init()
        controller.registerCallbacks(self)
    }

    public convenience init(
        controller: WorkflowController = AA2SDKWrapper.workflowController,
        outputHandler: @escaping OutputHandler
    ) throws {
        try self.init(
            controller: controller,
            coordinator: DeterministicGermanEidClient(),
            outputHandler: outputHandler)
    }

    deinit {
        controller.unregisterCallbacks(self)
    }

    public func start(_ request: GermanEidStartRequest) throws -> GermanEidOutput {
        try callbackQueue.sync {
            guard activeSessionID == nil, !stopped else {
                throw GermanEidClientError.invalidTransition
            }
            activeSessionID = request.adapterSessionID
            let output = try coordinator.start(request)
            try execute(output.commands)
            if !output.uiEvents.isEmpty { outputHandler(output) }
            return output
        }
    }

    public func receive(
        _ event: GermanEidSdkEvent,
        sessionID: GermanEidSessionID
    ) throws -> GermanEidOutput {
        try callbackQueue.sync {
            try receiveSerialized(event, sessionID: sessionID)
        }
    }

    public func act(
        _ action: GermanEidUserAction,
        sessionID: GermanEidSessionID
    ) throws -> GermanEidOutput {
        try callbackQueue.sync {
            guard activeSessionID == sessionID, !stopped else {
                throw GermanEidClientError.staleSession
            }
            let output = try coordinator.act(action, sessionID: sessionID)
            try execute(output.commands)
            if !output.uiEvents.isEmpty { outputHandler(output) }
            return output
        }
    }

    public func shutdown(sessionID: GermanEidSessionID) throws -> GermanEidOutput {
        try callbackQueue.sync {
            guard activeSessionID == sessionID else {
                throw GermanEidClientError.staleSession
            }
            let output = try coordinator.shutdown(sessionID: sessionID)
            try execute(output.commands)
            invalidateSession()
            controller.stop()
            return output
        }
    }

    private func receiveSerialized(
        _ event: GermanEidSdkEvent,
        sessionID: GermanEidSessionID
    ) throws -> GermanEidOutput {
        guard activeSessionID == sessionID, !stopped else {
            throw GermanEidClientError.staleSession
        }
        let output = try coordinator.receive(event, sessionID: sessionID)
        try execute(output.commands)
        if !output.uiEvents.isEmpty { outputHandler(output) }
        if output.uiEvents.contains(where: {
            if case .completed = $0 { return true }
            return false
        }) {
            invalidateSession()
        }
        return output
    }

    private func invalidateSession() {
        pendingRunAuth?.clearSecrets()
        pendingRunAuth = nil
        activeSessionID = nil
        stopped = true
    }

    private func execute(_ commands: [GermanEidSdkCommand]) throws {
        for command in commands {
            switch command {
            case .getApiLevel:
                // The 2.5.4 high-level wrapper negotiates the SDK internally and implements the
                // API-level-3 pause/continue contract used by the coordinator.
                if controller.isStarted {
                    try feed(.apiLevels(available: [3]))
                } else {
                    controller.start()
                }
            case .setApiLevel(let level):
                guard level == 3 else { throw GermanEidClientError.unsupportedApiLevel }
                try feed(.apiLevelSelected(level))
            case .runAuth(let value):
                pendingRunAuth?.clearSecrets()
                pendingRunAuth = value
                try startAuthentication(value)
            case .setAccessRights(let rights):
                guard let mapped = mapAccessRights(rights) else {
                    throw GermanEidClientError.invalidAccessRights
                }
                controller.setAccessRights(mapped)
            case .getCertificate:
                controller.getCertificate()
            case .accept:
                controller.accept()
            case .cancel:
                controller.cancel()
            case .interruptSystemDialog:
                controller.interrupt()
            case .continueAfterPause:
                controller.continueWorkflow()
            case .setSecret(let secret):
                try submit(secret)
            }
        }
    }

    private func feed(_ event: GermanEidSdkEvent) throws {
        guard let sessionID = activeSessionID else {
            throw GermanEidClientError.staleSession
        }
        _ = try receiveSerialized(event, sessionID: sessionID)
    }

    private func startAuthentication(_ command: GermanEidRunAuthCommand) throws {
        let url = try command.tcTokenURL.consume { raw -> URL in
            let bytes = Array(raw)
            guard let string = String(bytes: bytes, encoding: .utf8),
                  let url = URL(string: string)
            else { throw GermanEidClientError.invalidConfiguration }
            return url
        }
        controller.startAuthentication(
            withTcTokenUrl: url,
            withDeveloperMode: false,
            withUserInfoMessages: AA2UserInfoMessages(
                sessionStarted: "Hold your ID card to the top of your iPhone.",
                sessionFailed: "The card could not be read. You can try again.",
                sessionSucceeded: "Your ID card was read.",
                sessionInProgress: "Keep your card still."),
            withStatusMsgEnabled: true,
            withCustomHeader: nil)
        pendingRunAuth = nil
    }

    private func submit(_ secret: GermanEidCardSecret) throws {
        try secret.consume { raw in
            guard let digits = String(bytes: raw, encoding: .utf8) else {
                throw GermanEidClientError.invalidSecret
            }
            switch secret.kind {
            case .pin: controller.setPin(digits)
            case .can: controller.setCan(digits)
            case .puk: controller.setPuk(digits)
            }
        }
    }

    private func mapAccessRights(_ rights: Set<GermanEidAccessRight>) -> [AccessRight]? {
        let mapped = rights.compactMap { AccessRight(rawValue: $0.rawValue) }
        return mapped.count == rights.count ? mapped.sorted { $0.rawValue < $1.rawValue } : nil
    }

    private func readerState(_ reader: Reader) -> GermanEidReaderState {
        let card: GermanEidCardState
        if let value = reader.card {
            if value.isUnknown() {
                card = .unknown
            } else {
                card = .present(
                    retryCounter: value.pinRetryCounter.flatMap(UInt8.init(exactly:)),
                    deactivated: value.deactivated ?? false,
                    inoperative: value.inoperative ?? false)
            }
        } else {
            card = .absent
        }
        // The embedded iOS wrapper only exposes CoreNFC as its reader transport.
        return GermanEidReaderState(
            kind: .integratedNfc,
            attached: reader.attached,
            insertable: reader.insertable,
            keypad: reader.keypad,
            card: card)
    }

    private static let iso8601 = ISO8601DateFormatter()

    private func auxiliary(_ value: AuxiliaryData?) throws -> GermanEidAuxiliaryData? {
        guard let value else { return nil }
        let fields: (String?, String?, String?, String?) = (
            value.ageVerificationDate.map(Self.iso8601.string),
            value.requiredAge.map(String.init),
            value.validityDate.map(Self.iso8601.string),
            value.communityId)
        if fields == (nil, nil, nil, nil) { return nil }
        return try GermanEidAuxiliaryData(
            ageVerificationDate: fields.0,
            requiredAge: fields.1,
            validityDate: fields.2,
            communityID: fields.3)
    }

    // MARK: - Official wrapper callbacks

    public func onStarted() {
        enqueue { try self.feed(.apiLevels(available: [3])) }
    }

    public func onAuthenticationStarted() {
        enqueue { try self.feed(.authenticationStarted) }
    }

    public func onAuthenticationStartFailed(error _: String) {
        enqueue { try self.feed(.authenticationStartFailed) }
    }

    public func onAccessRights(error: String?, accessRights: AccessRights?) {
        enqueue {
            guard error == nil, let value = accessRights else {
                try self.feed(.adapterFailed)
                return
            }
            let required = Set(value.requiredRights.compactMap {
                GermanEidAccessRight(rawValue: $0.rawValue)
            })
            let optional = Set(value.optionalRights.compactMap {
                GermanEidAccessRight(rawValue: $0.rawValue)
            })
            let effective = Set(value.effectiveRights.compactMap {
                GermanEidAccessRight(rawValue: $0.rawValue)
            })
            guard required.count == value.requiredRights.count,
                  optional.count == value.optionalRights.count,
                  effective.count == value.effectiveRights.count
            else { throw GermanEidClientError.invalidAccessRights }
            try self.feed(.accessRights(try GermanEidAccessRights(
                required: required,
                optional: optional,
                effective: effective,
                transactionInfo: value.transactionInfo,
                auxiliaryData: try self.auxiliary(value.auxiliaryData))))
        }
    }

    public func onCertificate(certificateDescription value: CertificateDescription) {
        enqueue {
            guard let issuerURL = value.issuerUrl?.absoluteString,
                  let subjectURL = value.subjectUrl?.absoluteString
            else { throw GermanEidClientError.invalidCertificate }
            try self.feed(.certificate(try GermanEidCertificate(
                issuerName: value.issuerName,
                issuerURL: issuerURL,
                subjectName: value.subjectName,
                subjectURL: subjectURL,
                termsOfUsage: value.termsOfUsage,
                purpose: value.purpose,
                effectiveDate: Self.iso8601.string(from: value.validity.effectiveDate),
                expirationDate: Self.iso8601.string(from: value.validity.expirationDate))))
        }
    }

    public func onReader(reader: Reader?) {
        guard let reader else { return }
        enqueue { try self.feed(.reader(self.readerState(reader))) }
    }

    public func onInsertCard(error: String?) {
        enqueue {
            try self.feed(error == nil ? .cardRequired : .adapterFailed)
        }
    }

    public func onPause(cause: Cause) {
        enqueue {
            guard cause == .BadCardPosition else {
                try self.feed(.adapterFailed)
                return
            }
            try self.feed(.paused(.badCardPosition))
        }
    }

    public func onEnterPin(error: String?, reader: Reader) {
        secretRequested(.pin, error: error, reader: reader)
    }

    public func onEnterCan(error: String?, reader: Reader) {
        secretRequested(.can, error: error, reader: reader)
    }

    public func onEnterPuk(error: String?, reader: Reader) {
        secretRequested(.puk, error: error, reader: reader)
    }

    private func secretRequested(
        _ kind: GermanEidSecretKind,
        error: String?,
        reader: Reader
    ) {
        enqueue {
            guard error == nil else {
                try self.feed(.adapterFailed)
                return
            }
            try self.feed(.secretRequested(kind: kind, reader: self.readerState(reader)))
        }
    }

    public func onAuthenticationCompleted(authResult: AuthResult) {
        enqueue {
            guard let sessionID = self.activeSessionID else {
                throw GermanEidClientError.staleSession
            }
            let reason: GermanEidFailureReason
            if authResult.result == nil {
                reason = .unknown
            } else if authResult.result?.isCancellationByUser == true {
                reason = .cancelled
            } else {
                reason = .communication
            }
            let outcome: GermanEidAuthenticationOutcome =
                authResult.hasError ? .failure(reason) : .success
            let result = try GermanEidAuthenticationResult(
                outcome: outcome,
                url: authResult.url.map { Array($0.absoluteString.utf8) },
                contract: self.coordinator.activeProviderContractForAdapter,
                sessionID: sessionID)
            try self.feed(.authenticationFinished(result))
        }
    }

    private func enqueue(_ operation: @escaping () throws -> Void) {
        callbackQueue.async {
            guard !self.stopped else { return }
            do {
                try operation()
            } catch {
                guard let sessionID = self.activeSessionID else { return }
                if let output = try? self.coordinator.receive(
                    .adapterFailed,
                    sessionID: sessionID)
                {
                    try? self.execute(output.commands)
                    if !output.uiEvents.isEmpty { self.outputHandler(output) }
                }
            }
        }
    }

    public func onBadState(error _: String) { enqueue { try self.feed(.adapterFailed) } }
    public func onInternalError(error _: String) { enqueue { try self.feed(.adapterFailed) } }
    public func onWrapperError(error _: WrapperError) { enqueue { try self.feed(.adapterFailed) } }
    public func onInfo(versionInfo _: VersionInfo) {}
    public func onReaderList(readers _: [Reader]?) {}
    public func onStatus(workflowProgress _: WorkflowProgress) {}
    public func onChangePinStarted() { enqueue { try self.feed(.adapterFailed) } }
    public func onChangePinCompleted(changePinResult _: ChangePinResult) {
        enqueue { try self.feed(.adapterFailed) }
    }
    public func onEnterNewPin(error _: String?, reader _: Reader) {
        enqueue { try self.feed(.adapterFailed) }
    }
}
#endif
