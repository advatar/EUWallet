import XCTest
@testable import WalletShell

private let germanEidTestSessionID = try! GermanEidSessionID(
    [UInt8](repeating: 0x5a, count: 32))

private extension DeterministicGermanEidClient {
    func receive(_ event: GermanEidSdkEvent) throws -> GermanEidOutput {
        try receive(event, sessionID: germanEidTestSessionID)
    }

    func act(_ action: GermanEidUserAction) throws -> GermanEidOutput {
        try act(action, sessionID: germanEidTestSessionID)
    }
}

final class GermanEidClientTests: XCTestCase {
    private let tcToken = "https://eid.example/tctoken?session=top-secret"
    private let requiredRights: Set<GermanEidAccessRight> = [.familyName, .givenNames]
    private let optionalRights: Set<GermanEidAccessRight> = [.address]

    private func providerContract(
        required: Set<GermanEidAccessRight>? = nil,
        optional: Set<GermanEidAccessRight>? = nil,
        certificateSubjectName: String = "PID Provider",
        certificateSubjectURLOrigin: String = "https://provider.example",
        expectedTransactionInfo: String? = "PID enrolment",
        expectedAuxiliaryData: GermanEidAuxiliaryData? = nil
    ) throws -> GermanEidProviderContract {
        try GermanEidProviderContract(
            tcTokenOrigin: "https://eid.example",
            refreshOrigin: "https://provider.example",
            communicationOrigins: ["https://errors.example"],
            certificateSubjectName: certificateSubjectName,
            certificateSubjectURLOrigin: certificateSubjectURLOrigin,
            requiredRights: required ?? requiredRights,
            optionalRights: optional ?? optionalRights,
            expectedTransactionInfo: expectedTransactionInfo,
            expectedAuxiliaryData: expectedAuxiliaryData)
    }

    private func request(
        contract: GermanEidProviderContract? = nil
    ) throws -> GermanEidStartRequest {
        try GermanEidStartRequest(
            tcTokenURL: Array(tcToken.utf8),
            contract: contract ?? providerContract(),
            sessionID: germanEidTestSessionID)
    }

    private func reader(
        kind: GermanEidReaderKind = .integratedNfc,
        card: GermanEidCardState = .present(
            retryCounter: 3,
            deactivated: false,
            inoperative: false),
        attached: Bool = true,
        insertable: Bool = false,
        keypad: Bool = false
    ) -> GermanEidReaderState {
        GermanEidReaderState(
            kind: kind,
            attached: attached,
            insertable: insertable,
            keypad: keypad,
            card: card)
    }

    private func certificate(
        subjectName: String = "PID Provider",
        subjectURL: String = "https://provider.example"
    ) throws -> GermanEidCertificate {
        try GermanEidCertificate(
            issuerName: "German test DVCA",
            issuerURL: "https://issuer.example",
            subjectName: subjectName,
            subjectURL: subjectURL,
            termsOfUsage: "The provider requests the minimum attributes for PID issuance.",
            purpose: "PID issuance",
            effectiveDate: "2026-01-01",
            expirationDate: "2026-12-31")
    }

    private func result(
        _ outcome: GermanEidAuthenticationOutcome,
        url: String? = nil,
        contract: GermanEidProviderContract? = nil,
        sessionID: GermanEidSessionID = germanEidTestSessionID
    ) throws -> GermanEidAuthenticationResult {
        try GermanEidAuthenticationResult(
            outcome: outcome,
            url: url.map { Array($0.utf8) },
            contract: contract ?? providerContract(),
            sessionID: sessionID)
    }

    private func advanceToConsent(
        _ client: DeterministicGermanEidClient
    ) throws -> (consent: GermanEidConsent, interactionID: GermanEidInteractionID) {
        _ = try client.start(request())
        let select = try client.receive(.apiLevels(available: [1, 2, 3, 4]))
        guard case .setApiLevel(3) = select.commands.first else {
            XCTFail("expected highest supported API level")
            throw GermanEidClientError.invalidTransition
        }
        let run = try client.receive(.apiLevelSelected(3))
        guard case .runAuth(let command) = run.commands.first else {
            XCTFail("expected RUN_AUTH")
            throw GermanEidClientError.invalidTransition
        }
        XCTAssertFalse(command.developerMode)
        XCTAssertTrue(command.statusMessages)
        _ = try client.receive(.authenticationStarted)
        let minimize = try client.receive(.accessRights(try GermanEidAccessRights(
            required: requiredRights,
            optional: optionalRights,
            effective: requiredRights.union(optionalRights),
            transactionInfo: "PID enrolment")))
        guard case .setAccessRights(let selected) = minimize.commands.first else {
            XCTFail("expected SET_ACCESS_RIGHTS")
            throw GermanEidClientError.invalidTransition
        }
        XCTAssertTrue(selected.isEmpty)
        let getCertificate = try client.receive(.accessRights(try GermanEidAccessRights(
            required: requiredRights,
            optional: optionalRights,
            effective: requiredRights,
            transactionInfo: "PID enrolment")))
        guard case .getCertificate = getCertificate.commands.first else {
            XCTFail("expected GET_CERTIFICATE")
            throw GermanEidClientError.invalidTransition
        }
        let show = try client.receive(.certificate(certificate()))
        guard case .consent(let consent, let interactionID) = show.uiEvents.first else {
            XCTFail("expected consent")
            throw GermanEidClientError.invalidTransition
        }
        return (consent, interactionID)
    }

    @discardableResult
    private func advanceAndAccept(
        _ client: DeterministicGermanEidClient
    ) throws -> GermanEidConsent {
        let prompt = try advanceToConsent(client)
        _ = try client.act(.accept(prompt.interactionID))
        return prompt.consent
    }

    func testNegotiatesHighestSupportedApiAndEmitsOneReleaseSafeRunAuth() throws {
        let client = try DeterministicGermanEidClient()
        guard case .getApiLevel = try client.start(request()).commands.first else {
            return XCTFail("expected GET_API_LEVEL")
        }
        guard case .setApiLevel(3) = try client.receive(
            .apiLevels(available: [1, 2, 3])).commands.first
        else { return XCTFail("expected SET_API_LEVEL 3") }
        let run = try client.receive(.apiLevelSelected(3))
        guard case .runAuth(let command) = run.commands.first else {
            return XCTFail("expected RUN_AUTH")
        }
        XCTAssertFalse(command.developerMode)
        XCTAssertFalse(String(describing: command).contains("top-secret"))
        assertFlowFailure(.invalidTransition, expectsCancel: true) {
            try client.receive(.apiLevelSelected(3))
        }
    }

    func testRunAuthSecretsAreRedactedAndOneShotCleared() throws {
        let client = try DeterministicGermanEidClient()
        _ = try client.start(request())
        _ = try client.receive(.apiLevels(available: [3]))
        let run = try client.receive(.apiLevelSelected(3))
        guard case .runAuth(let command) = run.commands.first else {
            return XCTFail("expected RUN_AUTH")
        }
        XCTAssertEqual(
            try command.tcTokenURL.consume { String(decoding: $0, as: UTF8.self) },
            tcToken)
        XCTAssertTrue(command.tcTokenURL.isConsumed)
        XCTAssertThrowsError(try command.tcTokenURL.consume { _ in () }) {
            XCTAssertEqual($0 as? GermanEidClientError, .secretAlreadyConsumed)
        }
    }

    func testAbandonedOutputAndPreConsumedRunAuthInputFailClosed() throws {
        let abandoned = try DeterministicGermanEidClient()
        _ = try abandoned.start(request())
        _ = try abandoned.receive(.apiLevels(available: [3]))
        let output = try abandoned.receive(.apiLevelSelected(3))
        guard case .runAuth(let run) = output.commands.first else {
            return XCTFail("expected RUN_AUTH")
        }
        output.clearSecrets()
        XCTAssertTrue(run.tcTokenURL.isConsumed)

        let preConsumedRequest = try request()
        preConsumedRequest.clearSecrets()
        let preConsumed = try DeterministicGermanEidClient()
        _ = try preConsumed.start(preConsumedRequest)
        _ = try preConsumed.receive(.apiLevels(available: [3]))
        assertFlowFailure(.invalidConfiguration, expectsCancel: false) {
            try preConsumed.receive(.apiLevelSelected(3))
        }
    }

    func testProviderContractBindsRightsAndOrigins() throws {
        XCTAssertThrowsError(try providerContract(required: [.writeAddress]))
        XCTAssertThrowsError(try providerContract(required: [.pinManagement]))
        XCTAssertThrowsError(try GermanEidStartRequest(
            tcTokenURL: Array("https://other.example/tctoken".utf8),
            contract: providerContract(),
            sessionID: germanEidTestSessionID))
        XCTAssertThrowsError(try result(
            .success,
            url: "https://attacker.example/refresh"))

        let client = try DeterministicGermanEidClient()
        _ = try client.start(request())
        _ = try client.receive(.apiLevels(available: [3]))
        _ = try client.receive(.apiLevelSelected(3))
        _ = try client.receive(.authenticationStarted)
        assertFlowFailure(.invalidAccessRights, expectsCancel: true) {
            try client.receive(.accessRights(try GermanEidAccessRights(
                required: [.familyName],
                optional: optionalRights,
                effective: [.familyName, .address])))
        }

        let transaction = try DeterministicGermanEidClient()
        _ = try transaction.start(request())
        _ = try transaction.receive(.apiLevels(available: [3]))
        _ = try transaction.receive(.apiLevelSelected(3))
        _ = try transaction.receive(.authenticationStarted)
        assertFlowFailure(.invalidAccessRights, expectsCancel: true) {
            try transaction.receive(.accessRights(try GermanEidAccessRights(
                required: requiredRights,
                optional: optionalRights,
                effective: requiredRights.union(optionalRights),
                transactionInfo: "changed transaction")))
        }

        let certificateClient = try DeterministicGermanEidClient()
        _ = try certificateClient.start(request())
        _ = try certificateClient.receive(.apiLevels(available: [3]))
        _ = try certificateClient.receive(.apiLevelSelected(3))
        _ = try certificateClient.receive(.authenticationStarted)
        _ = try certificateClient.receive(.accessRights(try GermanEidAccessRights(
            required: requiredRights,
            optional: optionalRights,
            effective: requiredRights.union(optionalRights),
            transactionInfo: "PID enrolment")))
        _ = try certificateClient.receive(.accessRights(try GermanEidAccessRights(
            required: requiredRights,
            optional: optionalRights,
            effective: requiredRights,
            transactionInfo: "PID enrolment")))
        assertFlowFailure(.invalidCertificate, expectsCancel: true) {
            try certificateClient.receive(.certificate(try certificate(
                subjectName: "Unexpected Provider")))
        }

        let expectedAuxiliary = try GermanEidAuxiliaryData(requiredAge: "18")
        let auxiliaryContract = try providerContract(
            required: [.ageVerification],
            optional: [],
            expectedTransactionInfo: nil,
            expectedAuxiliaryData: expectedAuxiliary)
        let auxiliaryClient = try DeterministicGermanEidClient()
        _ = try auxiliaryClient.start(request(contract: auxiliaryContract))
        _ = try auxiliaryClient.receive(.apiLevels(available: [3]))
        _ = try auxiliaryClient.receive(.apiLevelSelected(3))
        _ = try auxiliaryClient.receive(.authenticationStarted)
        assertFlowFailure(.invalidAccessRights, expectsCancel: true) {
            try auxiliaryClient.receive(.accessRights(try GermanEidAccessRights(
                required: [.ageVerification],
                optional: [],
                effective: [.ageVerification],
                auxiliaryData: try GermanEidAuxiliaryData(requiredAge: "21"))))
        }
    }

    func testRightsAreMinimizedBeforeCertificateConsent() throws {
        let client = try DeterministicGermanEidClient()
        let prompt = try advanceToConsent(client)
        XCTAssertEqual(prompt.consent.effectiveRights, requiredRights)
        XCTAssertEqual(prompt.consent.certificate.purpose, "PID issuance")
        XCTAssertEqual(prompt.consent.transactionInfo, "PID enrolment")
        XCTAssertNil(prompt.consent.auxiliaryData)
        guard case .accept = try client.act(.accept(prompt.interactionID)).commands.first else {
            return XCTFail("expected ACCEPT")
        }
    }

    func testCannotAcceptBeforeCertificateOrChangeRightsAfterMinimization() throws {
        let staleSource = try DeterministicGermanEidClient()
        let staleInteractionID = try advanceToConsent(staleSource).interactionID

        let client = try DeterministicGermanEidClient()
        _ = try client.start(request())
        _ = try client.receive(.apiLevels(available: [3]))
        _ = try client.receive(.apiLevelSelected(3))
        _ = try client.receive(.authenticationStarted)
        assertFlowFailure(.staleInteraction, expectsCancel: false) {
            try client.act(.accept(staleInteractionID))
        }

        let second = try DeterministicGermanEidClient()
        _ = try second.start(request())
        _ = try second.receive(.apiLevels(available: [3]))
        _ = try second.receive(.apiLevelSelected(3))
        _ = try second.receive(.authenticationStarted)
        _ = try second.receive(.accessRights(try GermanEidAccessRights(
            required: requiredRights,
            optional: optionalRights,
            effective: requiredRights.union(optionalRights),
            transactionInfo: "PID enrolment")))
        assertFlowFailure(.invalidAccessRights, expectsCancel: true) {
            try second.receive(.accessRights(try GermanEidAccessRights(
                required: requiredRights,
                optional: optionalRights,
                effective: [.familyName],
                transactionInfo: "PID enrolment")))
        }
    }

    func testPinCanAndPukAreRetryBoundRedactedAndConsumedOnce() throws {
        let vectors: [(GermanEidSecretKind, String, UInt8)] = [
            (.pin, "123456", 3),
            (.can, "654321", 1),
            (.puk, "1234567890", 0),
        ]
        for (kind, digits, retryCounter) in vectors {
            let client = try DeterministicGermanEidClient()
            _ = try advanceAndAccept(client)
            let prompt = try client.receive(.secretRequested(
                kind: kind,
                reader: reader(card: .present(
                    retryCounter: retryCounter,
                    deactivated: false,
                    inoperative: false))))
            guard case .interruptSystemDialog = prompt.commands.first,
                  case .secretRequested(
                    let promptedKind,
                    retryCounter,
                    let interactionID) = prompt.uiEvents.first
            else { return XCTFail("expected interrupted secret prompt") }
            XCTAssertEqual(promptedKind, kind)

            var source = Array(digits.utf8)
            let secret = try GermanEidCardSecret(kind: kind, digits: source)
            source.indices.forEach { source[$0] = 0 }
            XCTAssertTrue(source.allSatisfy({ $0 == 0 }))
            let output = try client.act(.submitSecret(secret, interactionID: interactionID))
            XCTAssertFalse(String(describing: output).contains(digits))
            guard case .setSecret(let emitted) = output.commands.first else {
                return XCTFail("expected SET secret")
            }
            XCTAssertEqual(
                try emitted.consume { String(decoding: $0, as: UTF8.self) },
                digits)
            XCTAssertTrue(emitted.isConsumed)
            XCTAssertThrowsError(try emitted.consume { _ in () })
        }
    }

    func testCanAllowedSupportsADeactivatedCardWithoutCollapsingCardFacts() throws {
        let canRights = requiredRights.union([.canAllowed])
        let contract = try providerContract(required: canRights)
        let client = try DeterministicGermanEidClient()
        _ = try client.start(request(contract: contract))
        _ = try client.receive(.apiLevels(available: [3]))
        _ = try client.receive(.apiLevelSelected(3))
        _ = try client.receive(.authenticationStarted)
        _ = try client.receive(.accessRights(try GermanEidAccessRights(
            required: canRights,
            optional: optionalRights,
            effective: canRights.union(optionalRights),
            transactionInfo: "PID enrolment")))
        _ = try client.receive(.accessRights(try GermanEidAccessRights(
            required: canRights,
            optional: optionalRights,
            effective: canRights,
            transactionInfo: "PID enrolment")))
        let consent = try client.receive(.certificate(certificate()))
        guard case .consent(_, let consentID) = consent.uiEvents.first else {
            return XCTFail("expected CAN-allowed consent")
        }
        _ = try client.act(.accept(consentID))

        let card: GermanEidCardState = .present(
            retryCounter: 0,
            deactivated: true,
            inoperative: true)
        let prompt = try client.receive(.secretRequested(kind: .can, reader: reader(card: card)))
        guard case .interruptSystemDialog = prompt.commands.first,
              case .secretRequested(.can, 0, _) = prompt.uiEvents.first
        else { return XCTFail("expected CAN prompt for deactivated CAN-allowed card") }
    }

    func testKeypadInvalidCardAndConsumedSecretsFailClosed() throws {
        let external = try DeterministicGermanEidClient()
        _ = try advanceAndAccept(external)
        assertFlowFailure(.invalidCardState, expectsCancel: true) {
            try external.receive(.secretRequested(
                kind: .pin,
                reader: reader(kind: .unsupportedExternal)))
        }

        let keypad = try DeterministicGermanEidClient()
        _ = try advanceAndAccept(keypad)
        assertFlowFailure(.invalidCardState, expectsCancel: true) {
            try keypad.receive(.secretRequested(
                kind: .pin,
                reader: reader(keypad: true)))
        }

        let retry = try DeterministicGermanEidClient()
        _ = try advanceAndAccept(retry)
        assertFlowFailure(.invalidCardState, expectsCancel: true) {
            try retry.receive(.secretRequested(
                kind: .puk,
                reader: reader(card: .present(
                    retryCounter: 1,
                    deactivated: false,
                    inoperative: false))))
        }

        let consumed = try DeterministicGermanEidClient()
        _ = try advanceAndAccept(consumed)
        let prompt = try consumed.receive(.secretRequested(kind: .pin, reader: reader()))
        guard case .secretRequested(_, _, let interactionID) = prompt.uiEvents.first else {
            return XCTFail("expected secret interaction")
        }
        let secret = try GermanEidCardSecret(kind: .pin, digits: Array("123456".utf8))
        _ = try secret.consume { _ in () }
        assertFlowFailure(.invalidSecret, expectsCancel: true) {
            try consumed.act(.submitSecret(secret, interactionID: interactionID))
        }
    }

    func testInsertCardReaderPauseAndContinueAreTyped() throws {
        let client = try DeterministicGermanEidClient()
        _ = try advanceAndAccept(client)
        guard case .cardRequired = try client.receive(.cardRequired).uiEvents.first else {
            return XCTFail("expected INSERT_CARD presentation")
        }
        let inoperativeCard: GermanEidCardState = .present(
            retryCounter: 0,
            deactivated: false,
            inoperative: true)
        let inoperative = try client.receive(.reader(reader(card: inoperativeCard)))
        guard inoperative.commands.isEmpty,
              case .reader(let emitted) = inoperative.uiEvents.first
        else {
            return XCTFail("expected inoperative card")
        }
        XCTAssertEqual(emitted.card, inoperativeCard)

        let pause = try client.receive(.paused(.badCardPosition))
        guard case .paused(.badCardPosition, let pauseID) = pause.uiEvents.first else {
            return XCTFail("expected PAUSE")
        }
        let deactivatedCard: GermanEidCardState = .present(
            retryCounter: 3,
            deactivated: true,
            inoperative: false)
        let pausedReader = try client.receive(.reader(reader(card: deactivatedCard)))
        guard case .interruptSystemDialog = pausedReader.commands.first,
              case .reader(let pausedReaderState) = pausedReader.uiEvents.first,
              pausedReaderState.card == deactivatedCard
        else { return XCTFail("expected benign paused READER update") }
        guard case .continueAfterPause = try client.act(
            .continueAfterPause(pauseID)).commands.first
        else { return XCTFail("expected CONTINUE") }
    }

    func testInvalidEnterSecretInterruptsBeforeCancelAndPresentsReaderFact() throws {
        let client = try DeterministicGermanEidClient()
        _ = try advanceAndAccept(client)
        let failure = assertFlowFailure(.invalidCardState, expectsCancel: true) {
            try client.receive(.secretRequested(
                kind: .puk,
                reader: reader(card: .present(
                    retryCounter: 0,
                    deactivated: false,
                    inoperative: true))))
        }
        XCTAssertEqual(failure.recovery.commands.count, 2)
        guard case .interruptSystemDialog = failure.recovery.commands.first,
              case .cancel = failure.recovery.commands.last,
              case .reader(let emitted) = failure.recovery.uiEvents.first
        else { return XCTFail("expected ordered INTERRUPT, CANCEL and reader presentation") }
        XCTAssertEqual(
            emitted.card,
            .present(retryCounter: 0, deactivated: false, inoperative: true))
    }

    func testAsynchronousReaderUpdatesPreservePreConsentStateWithoutEarlyInterrupt() throws {
        let client = try DeterministicGermanEidClient()
        _ = try client.start(request())

        let preflightCard: GermanEidCardState = .present(
            retryCounter: 3,
            deactivated: true,
            inoperative: false)
        let preflight = try client.receive(.reader(reader(card: preflightCard)))
        XCTAssertTrue(preflight.commands.isEmpty)
        guard case .reader(let preflightReader) = preflight.uiEvents.first,
              preflightReader.card == preflightCard
        else { return XCTFail("expected preflight READER update") }

        guard case .setApiLevel(3) = try client.receive(
            .apiLevels(available: [3])).commands.first
        else { return XCTFail("READER changed API negotiation state") }
        guard case .runAuth = try client.receive(.apiLevelSelected(3)).commands.first else {
            return XCTFail("expected RUN_AUTH after asynchronous READER")
        }
        _ = try client.receive(.authenticationStarted)

        let beforeRights = try client.receive(.reader(reader()))
        XCTAssertTrue(beforeRights.commands.isEmpty)
        guard case .setAccessRights = try client.receive(.accessRights(
            try GermanEidAccessRights(
                required: requiredRights,
                optional: optionalRights,
                effective: requiredRights.union(optionalRights),
                transactionInfo: "PID enrolment"))).commands.first
        else { return XCTFail("READER changed pre-consent workflow state") }
    }

    func testResultRequiresConsentExactContractAndBoundedHttpsUrl() throws {
        XCTAssertThrowsError(try result(.success))
        XCTAssertThrowsError(try GermanEidAuthenticationResult(
            outcome: .success,
            url: Array("http://provider.example/result".utf8),
            contract: providerContract(),
            sessionID: germanEidTestSessionID))

        let premature = try DeterministicGermanEidClient()
        _ = try advanceAndAccept(premature)
        _ = try premature.receive(.secretRequested(kind: .pin, reader: reader()))
        let prematureResult = try result(
            .success,
            url: "https://provider.example/refresh")
        let invalid = assertFlowFailure(.invalidResult, expectsCancel: false) {
            try premature.receive(.authenticationFinished(prematureResult))
        }
        guard case .completed(let invalidCompletion) = invalid.recovery.uiEvents.first else {
            return XCTFail("expected terminal local failure")
        }
        XCTAssertEqual(invalidCompletion.outcome, .failure(.sdk))
        assertFlowFailure(.alreadyTerminal, expectsCancel: false) {
            try premature.receive(.authenticationResultInvalid)
        }

        let client = try DeterministicGermanEidClient()
        _ = try advanceAndAccept(client)
        let completed = try client.receive(.authenticationFinished(try result(
            .success,
            url: "https://provider.example/refresh?session=result-secret")))
        XCTAssertFalse(String(describing: completed).contains("result-secret"))
        guard case .completed(let emitted) = completed.uiEvents.first else {
            return XCTFail("expected completion")
        }
        XCTAssertEqual(emitted.outcome, .success)
        XCTAssertEqual(
            try emitted.refreshOrCommunicationURL?.consume {
                String(decoding: $0, as: UTF8.self)
            },
            "https://provider.example/refresh?session=result-secret")
        assertFlowFailure(.alreadyTerminal, expectsCancel: false) { try client.act(.cancel) }
    }

    func testCancellationPreservesFailureAndWinsOverLaterSuccess() throws {
        let beforeAccept = try DeterministicGermanEidClient()
        _ = try advanceToConsent(beforeAccept)
        guard case .cancel = try beforeAccept.act(.cancel).commands.first else {
            return XCTFail("expected CANCEL")
        }
        let failure = try result(
            .failure(.communication),
            url: "https://errors.example/help")
        let failed = try beforeAccept.receive(.authenticationFinished(failure))
        guard case .completed(let emittedFailure) = failed.uiEvents.first else {
            return XCTFail("expected failure completion")
        }
        XCTAssertEqual(emittedFailure.outcome, .failure(.communication))

        let accepted = try DeterministicGermanEidClient()
        _ = try advanceAndAccept(accepted)
        _ = try accepted.act(.cancel)
        XCTAssertTrue(try accepted.act(.cancel).commands.isEmpty)
        let raced = try accepted.receive(.authenticationFinished(try result(
            .success,
            url: "https://provider.example/refresh?raced=1")))
        guard case .completed(let cancelled) = raced.uiEvents.first else {
            return XCTFail("expected cancelled completion")
        }
        XCTAssertEqual(cancelled.outcome, .failure(.cancelled))
    }

    func testCancellationTimeoutInvalidTerminalAuthAndPreAuthCancelTerminate() throws {
        let timedOut = try DeterministicGermanEidClient()
        _ = try advanceToConsent(timedOut)
        _ = try timedOut.act(.cancel)
        let timeout = assertFlowFailure(.adapterFailure, expectsCancel: false) {
            try timedOut.receive(.cancellationTimedOut)
        }
        guard case .completed(let timeoutResult) = timeout.recovery.uiEvents.first else {
            return XCTFail("expected timeout completion")
        }
        XCTAssertEqual(timeoutResult.outcome, .failure(.cancelled))

        let malformedFinal = try DeterministicGermanEidClient()
        _ = try advanceAndAccept(malformedFinal)
        let malformed = assertFlowFailure(.invalidResult, expectsCancel: false) {
            try malformedFinal.receive(.authenticationResultInvalid)
        }
        XCTAssertEqual(malformed.recovery.commands.count, 0)
        guard case .completed(let malformedResult) = malformed.recovery.uiEvents.first else {
            return XCTFail("expected malformed terminal AUTH completion")
        }
        XCTAssertEqual(malformedResult.outcome, .failure(.sdk))
        assertFlowFailure(.alreadyTerminal, expectsCancel: false) {
            try malformedFinal.act(.cancel)
        }

        let beforeRunAuth = try DeterministicGermanEidClient()
        _ = try beforeRunAuth.start(request())
        let cancelledLocally = try beforeRunAuth.act(.cancel)
        XCTAssertTrue(cancelledLocally.commands.isEmpty)
        guard case .completed(let beforeRunAuthResult) = cancelledLocally.uiEvents.first else {
            return XCTFail("expected local cancellation before RUN_AUTH")
        }
        XCTAssertEqual(beforeRunAuthResult.outcome, .failure(.cancelled))
        assertFlowFailure(.alreadyTerminal, expectsCancel: false) {
            try beforeRunAuth.receive(.apiLevels(available: [3]))
        }

        let runAuthInFlight = try DeterministicGermanEidClient()
        _ = try runAuthInFlight.start(request())
        _ = try runAuthInFlight.receive(.apiLevels(available: [3]))
        _ = try runAuthInFlight.receive(.apiLevelSelected(3))
        guard case .cancel = try runAuthInFlight.act(.cancel).commands.first else {
            return XCTFail("expected uncertain RUN_AUTH teardown")
        }
        let stopped = try runAuthInFlight.receive(.authenticationStartFailed)
        guard case .completed(let stoppedResult) = stopped.uiEvents.first else {
            return XCTFail("expected pre-AUTH cancellation completion")
        }
        XCTAssertEqual(stoppedResult.outcome, .failure(.cancelled))

        let startWonRace = try DeterministicGermanEidClient()
        _ = try startWonRace.start(request())
        _ = try startWonRace.receive(.apiLevels(available: [3]))
        _ = try startWonRace.receive(.apiLevelSelected(3))
        _ = try startWonRace.act(.cancel)
        XCTAssertTrue(try startWonRace.receive(.authenticationStarted).commands.isEmpty)
        XCTAssertTrue(try startWonRace.receive(.authenticationStartFailed).uiEvents.isEmpty)
        let racedFinal = try startWonRace.receive(.authenticationFinished(
            try result(.failure(.cancelled))))
        guard case .completed(let racedFinalResult) = racedFinal.uiEvents.first else {
            return XCTFail("AUTH start race orphaned the live workflow")
        }
        XCTAssertEqual(racedFinalResult.outcome, .failure(.cancelled))

        let confirmedWorkflow = try DeterministicGermanEidClient()
        _ = try advanceAndAccept(confirmedWorkflow)
        _ = try confirmedWorkflow.act(.cancel)
        XCTAssertTrue(try confirmedWorkflow.receive(
            .authenticationStartFailed).uiEvents.isEmpty)
        let authoritativeFinal = try confirmedWorkflow.receive(.authenticationFinished(
            try result(.failure(.communication), url: "https://errors.example/help")))
        guard case .completed(let authoritativeResult) = authoritativeFinal.uiEvents.first else {
            return XCTFail("delayed start failure orphaned a confirmed workflow")
        }
        XCTAssertEqual(authoritativeResult.outcome, .failure(.communication))
    }

    func testSessionAndInteractionGenerationsRejectStaleWork() throws {
        let staleSession = try GermanEidSessionID([UInt8](repeating: 0x33, count: 32))
        let sessionClient = try DeterministicGermanEidClient()
        _ = try sessionClient.start(request())
        assertFlowFailure(.staleSession, expectsCancel: false) {
            try sessionClient.receive(.apiLevels(available: [3]), sessionID: staleSession)
        }
        guard case .setApiLevel(3) = try sessionClient.receive(
            .apiLevels(available: [3])).commands.first
        else { return XCTFail("stale callback mutated the session") }

        let client = try DeterministicGermanEidClient()
        let consent = try advanceToConsent(client)
        _ = try client.act(.accept(consent.interactionID))
        XCTAssertTrue(try client.act(.accept(consent.interactionID)).commands.isEmpty)

        let firstPrompt = try client.receive(.secretRequested(kind: .pin, reader: reader()))
        guard case .secretRequested(_, _, let firstID) = firstPrompt.uiEvents.first else {
            return XCTFail("expected first PIN prompt")
        }
        let firstSecret = try GermanEidCardSecret(
            kind: .pin, digits: Array("123456".utf8))
        _ = try client.act(.submitSecret(firstSecret, interactionID: firstID))
        XCTAssertTrue(firstSecret.isConsumed)

        let secondPrompt = try client.receive(.secretRequested(
            kind: .pin,
            reader: reader(card: .present(
                retryCounter: 2,
                deactivated: false,
                inoperative: false))))
        guard case .secretRequested(_, _, let secondID) = secondPrompt.uiEvents.first else {
            return XCTFail("expected second PIN prompt")
        }
        let staleSecret = try GermanEidCardSecret(
            kind: .pin, digits: Array("111111".utf8))
        assertFlowFailure(.staleInteraction, expectsCancel: false) {
            try client.act(.submitSecret(staleSecret, interactionID: firstID))
        }
        XCTAssertTrue(staleSecret.isConsumed)

        let current = try GermanEidCardSecret(
            kind: .pin, digits: Array("222222".utf8))
        _ = try client.act(.submitSecret(current, interactionID: secondID))
        let duplicate = try GermanEidCardSecret(
            kind: .pin, digits: Array("333333".utf8))
        XCTAssertTrue(try client.act(
            .submitSecret(duplicate, interactionID: secondID)).commands.isEmpty)
        XCTAssertTrue(duplicate.isConsumed)
    }

    func testStaleOuterAndInnerSessionsAreClearedWithoutMutatingCurrentFlow() throws {
        let staleSession = try GermanEidSessionID([UInt8](repeating: 0x33, count: 32))

        let actionClient = try DeterministicGermanEidClient()
        _ = try advanceAndAccept(actionClient)
        let prompt = try actionClient.receive(.secretRequested(kind: .pin, reader: reader()))
        guard case .secretRequested(_, _, let interactionID) = prompt.uiEvents.first else {
            return XCTFail("expected PIN prompt")
        }
        let staleActionSecret = try GermanEidCardSecret(
            kind: .pin,
            digits: Array("123456".utf8))
        assertFlowFailure(.staleSession, expectsCancel: false) {
            try actionClient.act(
                .submitSecret(staleActionSecret, interactionID: interactionID),
                sessionID: staleSession)
        }
        XCTAssertTrue(staleActionSecret.isConsumed)
        let currentSecret = try GermanEidCardSecret(
            kind: .pin,
            digits: Array("654321".utf8))
        let currentAction = try actionClient.act(
            .submitSecret(currentSecret, interactionID: interactionID))
        guard case .setSecret(let emittedSecret) = currentAction.commands.first else {
            return XCTFail("stale outer action mutated the current prompt")
        }
        emittedSecret.clear()

        let resultClient = try DeterministicGermanEidClient()
        _ = try advanceAndAccept(resultClient)
        let staleInnerResult = try result(
            .success,
            url: "https://provider.example/refresh?stale=1",
            sessionID: staleSession)
        let staleURL = staleInnerResult.refreshOrCommunicationURL
        assertFlowFailure(.staleSession, expectsCancel: false) {
            try resultClient.receive(.authenticationFinished(staleInnerResult))
        }
        XCTAssertEqual(staleURL?.isConsumed, true)

        let currentResult = try result(
            .success,
            url: "https://provider.example/refresh?current=1")
        let completed = try resultClient.receive(.authenticationFinished(currentResult))
        guard case .completed(let emittedResult) = completed.uiEvents.first else {
            return XCTFail("stale inner result mutated the current flow")
        }
        XCTAssertEqual(emittedResult.outcome, .success)
        emittedResult.clearSecrets()
    }

    func testReaderUpdatesPreserveOnlyAnUnchangedSecretPrompt() throws {
        let stableReader = reader(card: .present(
            retryCounter: 3,
            deactivated: false,
            inoperative: false))
        let preserved = try DeterministicGermanEidClient()
        _ = try advanceAndAccept(preserved)
        let preservedPrompt = try preserved.receive(.secretRequested(
            kind: .pin,
            reader: stableReader))
        guard case .secretRequested(_, _, let preservedID) = preservedPrompt.uiEvents.first else {
            return XCTFail("expected preserved PIN prompt")
        }
        _ = try preserved.receive(.reader(stableReader))
        let preservedSecret = try GermanEidCardSecret(
            kind: .pin,
            digits: Array("123456".utf8))
        let preservedSubmission = try preserved.act(
            .submitSecret(preservedSecret, interactionID: preservedID))
        guard case .setSecret(let emittedPreserved) = preservedSubmission.commands.first else {
            return XCTFail("unchanged reader invalidated the PIN prompt")
        }
        emittedPreserved.clear()

        let changed = try DeterministicGermanEidClient()
        _ = try advanceAndAccept(changed)
        let changedPrompt = try changed.receive(.secretRequested(
            kind: .pin,
            reader: stableReader))
        guard case .secretRequested(_, _, let changedID) = changedPrompt.uiEvents.first else {
            return XCTFail("expected PIN prompt before material reader update")
        }
        _ = try changed.receive(.reader(reader(card: .present(
            retryCounter: 2,
            deactivated: false,
            inoperative: false))))
        let changedSecret = try GermanEidCardSecret(
            kind: .pin,
            digits: Array("234567".utf8))
        assertFlowFailure(.staleInteraction, expectsCancel: false) {
            try changed.act(.submitSecret(changedSecret, interactionID: changedID))
        }
        XCTAssertTrue(changedSecret.isConsumed)

        let detached = try DeterministicGermanEidClient()
        _ = try advanceAndAccept(detached)
        let detachedPrompt = try detached.receive(.secretRequested(
            kind: .pin,
            reader: stableReader))
        guard case .secretRequested(_, _, let detachedID) = detachedPrompt.uiEvents.first else {
            return XCTFail("expected PIN prompt before integrated-reader detach")
        }
        let detachedUpdate = try detached.receive(.reader(reader(
            card: .absent,
            attached: false)))
        XCTAssertTrue(detachedUpdate.commands.isEmpty)
        guard case .reader(let detachedReader) = detachedUpdate.uiEvents.first,
              detachedReader.kind == .integratedNfc,
              !detachedReader.attached
        else { return XCTFail("expected benign detached integrated-reader update") }
        let detachedSecret = try GermanEidCardSecret(
            kind: .pin,
            digits: Array("765432".utf8))
        assertFlowFailure(.staleInteraction, expectsCancel: false) {
            try detached.act(.submitSecret(detachedSecret, interactionID: detachedID))
        }
        XCTAssertTrue(detachedSecret.isConsumed)

        let removed = try DeterministicGermanEidClient()
        _ = try advanceAndAccept(removed)
        let removedPrompt = try removed.receive(.secretRequested(
            kind: .pin,
            reader: stableReader))
        guard case .secretRequested(_, _, let removedID) = removedPrompt.uiEvents.first else {
            return XCTFail("expected PIN prompt before card removal")
        }
        _ = try removed.receive(.cardRequired)
        let removedSecret = try GermanEidCardSecret(
            kind: .pin,
            digits: Array("345678".utf8))
        assertFlowFailure(.staleInteraction, expectsCancel: false) {
            try removed.act(.submitSecret(removedSecret, interactionID: removedID))
        }
        XCTAssertTrue(removedSecret.isConsumed)
    }

    func testPauseUsesOneShotInteractionsAndRequiresFreshSecretRequest() throws {
        let client = try DeterministicGermanEidClient()
        _ = try advanceAndAccept(client)
        let prePausePrompt = try client.receive(.secretRequested(kind: .pin, reader: reader()))
        guard case .secretRequested(_, _, let prePauseSecretID) =
            prePausePrompt.uiEvents.first
        else { return XCTFail("expected pre-pause PIN prompt") }

        let firstPause = try client.receive(.paused(.badCardPosition))
        guard case .paused(.badCardPosition, let firstPauseID) = firstPause.uiEvents.first else {
            return XCTFail("expected first pause")
        }
        guard case .continueAfterPause = try client.act(
            .continueAfterPause(firstPauseID)).commands.first
        else { return XCTFail("expected first CONTINUE") }
        XCTAssertTrue(try client.act(
            .continueAfterPause(firstPauseID)).commands.isEmpty)

        let secondPause = try client.receive(.paused(.badCardPosition))
        guard case .paused(.badCardPosition, let secondPauseID) = secondPause.uiEvents.first else {
            return XCTFail("expected second pause")
        }
        XCTAssertNotEqual(firstPauseID, secondPauseID)
        assertFlowFailure(.staleInteraction, expectsCancel: false) {
            try client.act(.continueAfterPause(firstPauseID))
        }
        guard case .continueAfterPause = try client.act(
            .continueAfterPause(secondPauseID)).commands.first
        else { return XCTFail("stale CONTINUE mutated the current pause") }

        let staleSecret = try GermanEidCardSecret(
            kind: .pin,
            digits: Array("456789".utf8))
        assertFlowFailure(.staleInteraction, expectsCancel: false) {
            try client.act(.submitSecret(staleSecret, interactionID: prePauseSecretID))
        }
        XCTAssertTrue(staleSecret.isConsumed)

        let freshPrompt = try client.receive(.secretRequested(kind: .pin, reader: reader()))
        guard case .secretRequested(_, _, let freshSecretID) = freshPrompt.uiEvents.first else {
            return XCTFail("expected a fresh post-CONTINUE PIN prompt")
        }
        XCTAssertNotEqual(prePauseSecretID, freshSecretID)
        let freshSecret = try GermanEidCardSecret(
            kind: .pin,
            digits: Array("567890".utf8))
        let submission = try client.act(
            .submitSecret(freshSecret, interactionID: freshSecretID))
        guard case .setSecret(let emittedSecret) = submission.commands.first else {
            return XCTFail("expected fresh post-CONTINUE SET")
        }
        emittedSecret.clear()
    }

    func testShutdownAndReentrantSecretInspectionAreBounded() throws {
        let preflightRequest = try request()
        let preflight = try DeterministicGermanEidClient()
        _ = try preflight.start(preflightRequest)
        XCTAssertTrue(try preflight.shutdown(
            sessionID: germanEidTestSessionID).commands.isEmpty)

        let live = try DeterministicGermanEidClient()
        _ = try live.start(request())
        _ = try live.receive(.apiLevels(available: [3]))
        _ = try live.receive(.apiLevelSelected(3))
        guard case .cancel = try live.shutdown(
            sessionID: germanEidTestSessionID).commands.first
        else { return XCTFail("expected shutdown CANCEL") }

        let bytes = try GermanEidSensitiveBytes(Array("secret".utf8))
        _ = try bytes.consume { raw in
            XCTAssertTrue(bytes.isConsumed)
            XCTAssertEqual(raw.count, 6)
        }
        XCTAssertTrue(bytes.isConsumed)

        enum AdapterProbeError: Error { case failed }
        let throwingBytes = try GermanEidSensitiveBytes(Array("secret".utf8))
        XCTAssertThrowsError(try throwingBytes.consume { _ -> Void in
            XCTAssertTrue(throwingBytes.isConsumed)
            throw AdapterProbeError.failed
        }) { error in
            XCTAssertTrue(error is AdapterProbeError)
        }
        XCTAssertTrue(throwingBytes.isConsumed)
        XCTAssertThrowsError(try throwingBytes.consume { _ in () }) {
            XCTAssertEqual($0 as? GermanEidClientError, .secretAlreadyConsumed)
        }
    }

    func testLocalFaultIssuesOneCancelAndWaitsForTerminalAuth() throws {
        let client = try DeterministicGermanEidClient()
        _ = try advanceToConsent(client)
        let failure = assertFlowFailure(.invalidTransition, expectsCancel: true) {
            try client.receive(.apiLevelSelected(3))
        }
        XCTAssertEqual(failure.recovery.commands.count, 1)
        XCTAssertTrue(try client.receive(.reader(reader())).commands.isEmpty)
        XCTAssertTrue(try client.act(.cancel).commands.isEmpty)
        let completed = try client.receive(.authenticationFinished(try result(
            .failure(.card),
            url: nil)))
        guard case .completed(let final) = completed.uiEvents.first else {
            return XCTFail("expected authoritative final failure")
        }
        XCTAssertEqual(final.outcome, .failure(.card))
    }

    func testAuthenticationStartFailureAndLiveAdapterFaultAreDistinct() throws {
        let startFailure = try DeterministicGermanEidClient()
        _ = try startFailure.start(request())
        _ = try startFailure.receive(.apiLevels(available: [3]))
        _ = try startFailure.receive(.apiLevelSelected(3))
        let completed = try startFailure.receive(.authenticationStartFailed)
        guard case .completed(let result) = completed.uiEvents.first else {
            return XCTFail("expected start failure")
        }
        XCTAssertEqual(result.outcome, .failure(.sdk))

        let liveFault = try DeterministicGermanEidClient()
        _ = try advanceToConsent(liveFault)
        assertFlowFailure(.adapterFailure, expectsCancel: true) {
            try liveFault.receive(.adapterFailed)
        }
    }

    func testUnsupportedApiAndSecondStartFailClosedAndClearOwnedSecrets() throws {
        let client = try DeterministicGermanEidClient()
        _ = try client.start(request())
        let rejected = try request()
        assertFlowFailure(.invalidTransition, expectsCancel: false) {
            try client.start(rejected)
        }

        let second = try DeterministicGermanEidClient()
        _ = try second.start(request())
        assertFlowFailure(.unsupportedApiLevel, expectsCancel: false) {
            try second.receive(.apiLevels(available: [1, 4]))
        }
    }

    @discardableResult
    private func assertFlowFailure<Result>(
        _ expected: GermanEidClientError,
        expectsCancel: Bool,
        _ body: () throws -> Result
    ) -> GermanEidFlowFailure {
        var captured: GermanEidFlowFailure?
        XCTAssertThrowsError(try body()) { error in
            guard let failure = error as? GermanEidFlowFailure else {
                return XCTFail("expected GermanEidFlowFailure, got \(error)")
            }
            captured = failure
            XCTAssertEqual(failure.reason, expected)
            let cancelCount = failure.recovery.commands.filter { command in
                if case .cancel = command { return true }
                return false
            }.count
            XCTAssertEqual(cancelCount, expectsCancel ? 1 : 0)
        }
        return captured!
    }
}
