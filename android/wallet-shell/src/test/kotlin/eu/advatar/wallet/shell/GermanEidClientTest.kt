package eu.advatar.wallet.shell

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Test

class GermanEidClientTest {
    private val tcToken = "https://eid.example/tctoken?session=top-secret"
    private val sessionId = session(0x5a)
    private val requiredRights = setOf(
        GermanEidAccessRight.FAMILY_NAME,
        GermanEidAccessRight.GIVEN_NAMES,
    )
    private val optionalRights = setOf(GermanEidAccessRight.ADDRESS)

    private data class ConsentPrompt(
        val consent: GermanEidConsent,
        val interactionId: GermanEidInteractionId,
    )

    private fun session(fill: Int): GermanEidSessionId =
        GermanEidSessionId(ByteArray(32) { fill.toByte() })

    private fun providerContract(
        required: Set<GermanEidAccessRight> = requiredRights,
        optional: Set<GermanEidAccessRight> = optionalRights,
        communicationOrigins: Set<String> = setOf("https://errors.example"),
        expectedSubjectName: String = "PID Provider",
        expectedSubjectOrigin: String = "https://provider.example",
        expectedTransactionInfo: String? = "PID enrolment",
        expectedAuxiliaryData: GermanEidAuxiliaryData? = GermanEidAuxiliaryData(
            requiredAge = "18",
        ),
    ) = GermanEidProviderContract(
        tcTokenOrigin = "https://eid.example",
        refreshOrigin = "https://provider.example",
        communicationOrigins = communicationOrigins,
        requiredRights = required,
        optionalRights = optional,
        expectedSubjectName = expectedSubjectName,
        expectedSubjectOrigin = expectedSubjectOrigin,
        expectedTransactionInfo = expectedTransactionInfo,
        expectedAuxiliaryData = expectedAuxiliaryData,
    )

    private fun request(
        contract: GermanEidProviderContract = providerContract(),
        session: GermanEidSessionId = sessionId,
    ): GermanEidStartRequest = GermanEidStartRequest(
        tcToken.toByteArray(),
        contract,
        session,
    )

    private fun presentCard(
        retryCounter: Int? = 3,
        deactivated: Boolean = false,
        inoperative: Boolean = false,
    ) = GermanEidCardState.Present(retryCounter, deactivated, inoperative)

    private fun reader(
        card: GermanEidCardState = presentCard(),
        kind: GermanEidReaderKind = GermanEidReaderKind.TRUSTED_PLATFORM_INTEGRATED_NFC,
        attached: Boolean = true,
        insertable: Boolean = false,
        keypad: Boolean = false,
    ) = GermanEidReaderState(kind, attached, insertable, keypad, card)

    private fun certificate(
        subjectName: String = "PID Provider",
        subjectUrl: String = "https://provider.example",
    ): GermanEidCertificate = GermanEidCertificate(
        issuerName = "German test DVCA",
        issuerUrl = "https://issuer.example",
        subjectName = subjectName,
        subjectUrl = subjectUrl,
        termsOfUsage = "The provider requests the minimum attributes for PID issuance.",
        purpose = "PID issuance",
        effectiveDate = "2026-01-01",
        expirationDate = "2026-12-31",
    )

    private fun result(
        outcome: GermanEidAuthenticationOutcome,
        url: String? = null,
        contract: GermanEidProviderContract = providerContract(),
        session: GermanEidSessionId = sessionId,
    ) = GermanEidAuthenticationResult(
        outcome,
        url?.toByteArray(),
        contract,
        session,
    )

    private fun DeterministicGermanEidClient.receive(
        event: GermanEidSdkEvent,
    ): GermanEidOutput = receive(event, sessionId)

    private fun DeterministicGermanEidClient.act(
        action: GermanEidUserAction,
    ): GermanEidOutput = act(action, sessionId)

    private fun advanceToInitialRights(
        client: DeterministicGermanEidClient,
        contract: GermanEidProviderContract = providerContract(),
        session: GermanEidSessionId = sessionId,
    ) {
        client.start(request(contract, session))
        val select = client.receive(
            GermanEidSdkEvent.ApiLevels(setOf(1, 2, 3, 4)),
            session,
        )
        assertEquals(GermanEidSdkCommand.SetApiLevel(3), select.commands.single())
        val runOutput = client.receive(GermanEidSdkEvent.ApiLevelSelected(3), session)
        val run = (runOutput.commands.single() as GermanEidSdkCommand.RunAuth).value
        assertEquals(session, run.sessionId)
        assertFalse(run.developerMode)
        assertTrue(run.statusMessages)
        runOutput.close()
        client.receive(GermanEidSdkEvent.AuthenticationStarted, session)
    }

    private fun advanceToCertificate(
        client: DeterministicGermanEidClient,
        contract: GermanEidProviderContract = providerContract(),
        session: GermanEidSessionId = sessionId,
    ) {
        advanceToInitialRights(client, contract, session)
        val auxiliary = GermanEidAuxiliaryData(requiredAge = "18")
        val minimize = client.receive(
            GermanEidSdkEvent.AccessRights(
                GermanEidAccessRights(
                    contract.requiredRights,
                    contract.optionalRights,
                    contract.requiredRights + contract.optionalRights,
                    transactionInfo = "PID enrolment",
                    auxiliaryData = auxiliary,
                ),
            ),
            session,
        )
        assertTrue(
            (minimize.commands.single() as GermanEidSdkCommand.SetAccessRights).rights.isEmpty(),
        )
        val getCertificate = client.receive(
            GermanEidSdkEvent.AccessRights(
                GermanEidAccessRights(
                    contract.requiredRights,
                    contract.optionalRights,
                    contract.requiredRights,
                    transactionInfo = "PID enrolment",
                    auxiliaryData = auxiliary,
                ),
            ),
            session,
        )
        assertEquals(GermanEidSdkCommand.GetCertificate, getCertificate.commands.single())
    }

    private fun advanceToConsent(
        client: DeterministicGermanEidClient,
        contract: GermanEidProviderContract = providerContract(),
        session: GermanEidSessionId = sessionId,
    ): ConsentPrompt {
        advanceToCertificate(client, contract, session)
        val event = client.receive(GermanEidSdkEvent.Certificate(certificate()), session)
            .uiEvents.single() as GermanEidUiEvent.Consent
        return ConsentPrompt(event.value, event.interactionId)
    }

    private fun advanceToRunning(
        client: DeterministicGermanEidClient,
        contract: GermanEidProviderContract = providerContract(),
        session: GermanEidSessionId = sessionId,
    ): ConsentPrompt {
        val prompt = advanceToConsent(client, contract, session)
        assertEquals(
            GermanEidSdkCommand.Accept,
            client.act(GermanEidUserAction.Accept(prompt.interactionId), session)
                .commands.single(),
        )
        return prompt
    }

    @Test
    fun negotiatesHighestSupportedApiAndEmitsOneReleaseSafeRunAuth() {
        val client = DeterministicGermanEidClient()
        assertEquals(GermanEidSdkCommand.GetApiLevel, client.start(request()).commands.single())
        assertEquals(
            GermanEidSdkCommand.SetApiLevel(3),
            client.receive(GermanEidSdkEvent.ApiLevels(setOf(1, 2, 3))).commands.single(),
        )
        val output = client.receive(GermanEidSdkEvent.ApiLevelSelected(3))
        val run = (output.commands.single() as GermanEidSdkCommand.RunAuth).value
        assertEquals(sessionId, run.sessionId)
        assertFalse(run.developerMode)
        assertTrue(run.statusMessages)
        assertFalse(output.toString().contains("top-secret"))
        output.close()

        assertFlowReason(GermanEidClientError.INVALID_TRANSITION, expectsCancel = true) {
            client.receive(GermanEidSdkEvent.ApiLevelSelected(3))
        }
    }

    @Test
    fun runAuthUrlIsRedactedOwnedAndOneShotWithoutCustomHeaders() {
        val client = DeterministicGermanEidClient()
        client.start(request())
        client.receive(GermanEidSdkEvent.ApiLevels(setOf(3)))
        val run = (
            client.receive(GermanEidSdkEvent.ApiLevelSelected(3)).commands.single()
                as GermanEidSdkCommand.RunAuth
            ).value

        assertEquals(tcToken, run.tcTokenUrl.consume { it.toString(Charsets.UTF_8) })
        assertTrue(run.tcTokenUrl.isConsumed)
        assertReason(GermanEidClientError.SECRET_ALREADY_CONSUMED) {
            run.tcTokenUrl.consume { Unit }
        }
        assertFalse(run.toString().contains("top-secret"))
    }

    @Test
    fun sensitiveBytesAreCopiedReentrantAndOneShot() {
        val source = "secret-value".toByteArray()
        val secret = GermanEidSensitiveBytes(source)
        source.fill(0)

        assertEquals(
            "secret-value",
            secret.consume { exposed ->
                assertTrue(secret.isConsumed)
                assertReason(GermanEidClientError.SECRET_ALREADY_CONSUMED) {
                    secret.consume { Unit }
                }
                exposed.toString(Charsets.UTF_8)
            },
        )
        assertTrue(secret.isConsumed)
        assertReason(GermanEidClientError.SECRET_ALREADY_CONSUMED) {
            secret.consume { Unit }
        }
    }

    @Test
    fun abandonedAndPreConsumedRunAuthInputsFailClosed() {
        val abandoned = DeterministicGermanEidClient()
        abandoned.start(request())
        abandoned.receive(GermanEidSdkEvent.ApiLevels(setOf(3)))
        val output = abandoned.receive(GermanEidSdkEvent.ApiLevelSelected(3))
        val run = (output.commands.single() as GermanEidSdkCommand.RunAuth).value
        output.close()
        assertTrue(run.tcTokenUrl.isConsumed)

        val preConsumedRequest = request()
        val preConsumed = DeterministicGermanEidClient()
        preConsumed.start(preConsumedRequest)
        preConsumed.receive(GermanEidSdkEvent.ApiLevels(setOf(3)))
        preConsumedRequest.tcTokenUrl.consume { Unit }
        assertFlowReason(GermanEidClientError.INVALID_CONFIGURATION, expectsCancel = false) {
            preConsumed.receive(GermanEidSdkEvent.ApiLevelSelected(3))
        }
    }

    @Test
    fun holderCancelBeforeRunAuthClearsSecretsAndCompletesLocally() {
        val beforeLevelsRequest = request()
        val beforeLevels = DeterministicGermanEidClient()
        beforeLevels.start(beforeLevelsRequest)
        val first = beforeLevels.act(GermanEidUserAction.Cancel)
        assertTrue(first.commands.isEmpty())
        assertCompletedFailure(first, GermanEidFailureReason.CANCELLED)
        assertTrue(beforeLevelsRequest.tcTokenUrl.isConsumed)
        assertFlowReason(GermanEidClientError.ALREADY_TERMINAL, expectsCancel = false) {
            beforeLevels.act(GermanEidUserAction.Cancel)
        }

        val beforeSelectionRequest = request()
        val beforeSelection = DeterministicGermanEidClient()
        beforeSelection.start(beforeSelectionRequest)
        beforeSelection.receive(GermanEidSdkEvent.ApiLevels(setOf(3)))
        val second = beforeSelection.act(GermanEidUserAction.Cancel)
        assertTrue(second.commands.isEmpty())
        assertCompletedFailure(second, GermanEidFailureReason.CANCELLED)
        assertTrue(beforeSelectionRequest.tcTokenUrl.isConsumed)
    }

    @Test
    fun providerContractBindsRightsOriginsAndExportsImmutableSets() {
        assertReason(GermanEidClientError.INVALID_CONFIGURATION) {
            providerContract(required = setOf(GermanEidAccessRight.WRITE_ADDRESS))
        }
        assertReason(GermanEidClientError.INVALID_CONFIGURATION) {
            providerContract(required = setOf(GermanEidAccessRight.PIN_MANAGEMENT))
        }
        assertReason(GermanEidClientError.INVALID_CONFIGURATION) {
            GermanEidStartRequest(
                "https://other.example/tctoken".toByteArray(),
                providerContract(),
                sessionId,
            )
        }
        assertReason(GermanEidClientError.INVALID_RESULT) {
            result(
                GermanEidAuthenticationOutcome.Success,
                "https://attacker.example/refresh",
            )
        }
        assertReason(GermanEidClientError.INVALID_CONFIGURATION) {
            providerContract(expectedSubjectName = "")
        }
        assertReason(GermanEidClientError.INVALID_CONFIGURATION) {
            providerContract(expectedSubjectOrigin = "http://provider.example")
        }

        val mutableRequired = linkedSetOf(GermanEidAccessRight.FAMILY_NAME)
        val contract = providerContract(required = mutableRequired, optional = emptySet())
        mutableRequired.add(GermanEidAccessRight.GIVEN_NAMES)
        assertEquals(setOf(GermanEidAccessRight.FAMILY_NAME), contract.requiredRights)
        assertImmutable(contract.requiredRights)

        val mutableEffective = linkedSetOf(GermanEidAccessRight.FAMILY_NAME)
        val rights = GermanEidAccessRights(
            setOf(GermanEidAccessRight.FAMILY_NAME),
            emptySet(),
            mutableEffective,
        )
        mutableEffective.clear()
        assertEquals(setOf(GermanEidAccessRight.FAMILY_NAME), rights.effective)
        assertImmutable(rights.required)
        assertImmutable(rights.effective)

        val client = DeterministicGermanEidClient()
        val consent = advanceToConsent(client).consent
        assertImmutable(consent.effectiveRights)
    }

    @Test
    fun providerContractBindsCertificateSubjectBeforeConsent() {
        listOf(
            certificate(subjectName = "Imposter PID Provider"),
            certificate(subjectUrl = "https://attacker.example"),
            certificate(subjectUrl = "http://provider.example"),
        ).forEach { mismatchedCertificate ->
            val client = DeterministicGermanEidClient()
            advanceToCertificate(client)
            assertFlowReason(GermanEidClientError.INVALID_CERTIFICATE, expectsCancel = true) {
                client.receive(GermanEidSdkEvent.Certificate(mismatchedCertificate))
            }
        }
    }

    @Test
    fun providerContractBindsTransactionAndAuxiliarySemanticsBeforeMinimization() {
        val expectedAuxiliary = GermanEidAuxiliaryData(requiredAge = "18")
        val mismatches = listOf(
            Triple(
                providerContract(),
                "Different transaction",
                expectedAuxiliary,
            ),
            Triple(
                providerContract(),
                "PID enrolment",
                GermanEidAuxiliaryData(requiredAge = "21"),
            ),
            Triple(
                providerContract(
                    expectedTransactionInfo = null,
                    expectedAuxiliaryData = null,
                ),
                "PID enrolment",
                expectedAuxiliary,
            ),
        )
        mismatches.forEach { (contract, transactionInfo, auxiliaryData) ->
            val client = DeterministicGermanEidClient()
            advanceToInitialRights(client, contract)
            assertFlowReason(
                GermanEidClientError.INVALID_ACCESS_RIGHTS,
                expectsCancel = true,
            ) {
                client.receive(
                    GermanEidSdkEvent.AccessRights(
                        GermanEidAccessRights(
                            requiredRights,
                            optionalRights,
                            requiredRights + optionalRights,
                            transactionInfo = transactionInfo,
                            auxiliaryData = auxiliaryData,
                        ),
                    ),
                )
            }
        }
    }

    @Test
    fun exactRightsAreMinimizedAndCertificateGatesConsent() {
        val client = DeterministicGermanEidClient()
        val prompt = advanceToConsent(client)
        assertEquals(requiredRights, prompt.consent.effectiveRights)
        assertEquals("PID issuance", prompt.consent.certificate.purpose)
        assertEquals("PID enrolment", prompt.consent.transactionInfo)
        assertEquals("18", prompt.consent.auxiliaryData?.requiredAge)
        assertEquals(
            GermanEidSdkCommand.Accept,
            client.act(GermanEidUserAction.Accept(prompt.interactionId)).commands.single(),
        )
        assertTrue(client.act(GermanEidUserAction.Accept(prompt.interactionId)).commands.isEmpty())

        val early = DeterministicGermanEidClient()
        early.start(request())
        early.receive(GermanEidSdkEvent.ApiLevels(setOf(3)))
        val run = early.receive(GermanEidSdkEvent.ApiLevelSelected(3))
        run.close()
        early.receive(GermanEidSdkEvent.AuthenticationStarted)
        assertFlowReason(GermanEidClientError.STALE_INTERACTION, expectsCancel = false) {
            early.act(GermanEidUserAction.Accept(GermanEidInteractionId(1)))
        }
    }

    @Test
    fun changedOrUnexpectedRightsFailClosed() {
        val client = DeterministicGermanEidClient()
        client.start(request())
        client.receive(GermanEidSdkEvent.ApiLevels(setOf(3)))
        client.receive(GermanEidSdkEvent.ApiLevelSelected(3)).close()
        client.receive(GermanEidSdkEvent.AuthenticationStarted)
        client.receive(
            GermanEidSdkEvent.AccessRights(
                GermanEidAccessRights(
                    requiredRights,
                    optionalRights,
                    requiredRights + optionalRights,
                    transactionInfo = "PID enrolment",
                    auxiliaryData = GermanEidAuxiliaryData(requiredAge = "18"),
                ),
            ),
        )
        assertFlowReason(GermanEidClientError.INVALID_ACCESS_RIGHTS, expectsCancel = true) {
            client.receive(
                GermanEidSdkEvent.AccessRights(
                    GermanEidAccessRights(
                        requiredRights,
                        optionalRights,
                        setOf(GermanEidAccessRight.FAMILY_NAME),
                        transactionInfo = "PID enrolment",
                        auxiliaryData = GermanEidAuxiliaryData(requiredAge = "18"),
                    ),
                ),
            )
        }

        val mismatch = DeterministicGermanEidClient()
        mismatch.start(request())
        mismatch.receive(GermanEidSdkEvent.ApiLevels(setOf(3)))
        mismatch.receive(GermanEidSdkEvent.ApiLevelSelected(3)).close()
        mismatch.receive(GermanEidSdkEvent.AuthenticationStarted)
        assertFlowReason(GermanEidClientError.INVALID_ACCESS_RIGHTS, expectsCancel = true) {
            mismatch.receive(
                GermanEidSdkEvent.AccessRights(
                    GermanEidAccessRights(
                        setOf(GermanEidAccessRight.FAMILY_NAME),
                        optionalRights,
                        setOf(
                            GermanEidAccessRight.FAMILY_NAME,
                            GermanEidAccessRight.ADDRESS,
                        ),
                        transactionInfo = "PID enrolment",
                        auxiliaryData = GermanEidAuxiliaryData(requiredAge = "18"),
                    ),
                ),
            )
        }
    }

    @Test
    fun asynchronousReaderUpdatesPreserveEveryPreConsentStateWithoutInterrupting() {
        val client = DeterministicGermanEidClient()
        client.start(request())

        assertBenignReaderUpdate(
            client.receive(
                GermanEidSdkEvent.Reader(reader(presentCard(inoperative = true))),
            ),
        )
        client.receive(GermanEidSdkEvent.ApiLevels(setOf(3)))
        assertBenignReaderUpdate(
            client.receive(
                GermanEidSdkEvent.Reader(reader(presentCard(deactivated = true))),
            ),
        )
        client.receive(GermanEidSdkEvent.ApiLevelSelected(3)).close()
        assertBenignReaderUpdate(
            client.receive(
                GermanEidSdkEvent.Reader(reader(presentCard(inoperative = true))),
            ),
        )
        client.receive(GermanEidSdkEvent.AuthenticationStarted)
        assertBenignReaderUpdate(client.receive(GermanEidSdkEvent.Reader(reader())))

        val auxiliary = GermanEidAuxiliaryData(requiredAge = "18")
        client.receive(
            GermanEidSdkEvent.AccessRights(
                GermanEidAccessRights(
                    requiredRights,
                    optionalRights,
                    requiredRights + optionalRights,
                    transactionInfo = "PID enrolment",
                    auxiliaryData = auxiliary,
                ),
            ),
        )
        assertBenignReaderUpdate(client.receive(GermanEidSdkEvent.Reader(reader())))
        client.receive(
            GermanEidSdkEvent.AccessRights(
                GermanEidAccessRights(
                    requiredRights,
                    optionalRights,
                    requiredRights,
                    transactionInfo = "PID enrolment",
                    auxiliaryData = auxiliary,
                ),
            ),
        )
        assertBenignReaderUpdate(client.receive(GermanEidSdkEvent.Reader(reader())))
        val consent = client.receive(GermanEidSdkEvent.Certificate(certificate()))
            .uiEvents.single() as GermanEidUiEvent.Consent
        assertBenignReaderUpdate(
            client.receive(
                GermanEidSdkEvent.Reader(reader(presentCard(inoperative = true))),
            ),
        )
        assertEquals(
            GermanEidSdkCommand.Accept,
            client.act(GermanEidUserAction.Accept(consent.interactionId)).commands.single(),
        )
    }

    @Test
    fun invalidAsynchronousReaderFailsAccordingToSdkWorkflowLiveness() {
        val beforeSdkRequest = request()
        val beforeSdk = DeterministicGermanEidClient()
        beforeSdk.start(beforeSdkRequest)
        assertFlowReason(GermanEidClientError.INVALID_CARD_STATE, expectsCancel = false) {
            beforeSdk.receive(
                GermanEidSdkEvent.Reader(
                    reader(card = presentCard(retryCounter = 4)),
                ),
            )
        }
        assertTrue(beforeSdkRequest.tcTokenUrl.isConsumed)

        val live = DeterministicGermanEidClient()
        live.start(request())
        live.receive(GermanEidSdkEvent.ApiLevels(setOf(3)))
        live.receive(GermanEidSdkEvent.ApiLevelSelected(3)).close()
        assertFlowReason(GermanEidClientError.INVALID_CARD_STATE, expectsCancel = true) {
            live.receive(
                GermanEidSdkEvent.Reader(
                    reader(card = presentCard(retryCounter = 4)),
                ),
            )
        }
    }

    @Test
    fun pinCanAndPukAreRetryBoundRedactedAndTransferredOnce() {
        listOf(
            Triple(GermanEidSecretKind.PIN, "123456", 3),
            Triple(GermanEidSecretKind.CAN, "654321", 1),
            Triple(GermanEidSecretKind.PUK, "1234567890", 0),
        ).forEach { (kind, digits, retryCounter) ->
            val client = DeterministicGermanEidClient()
            advanceToRunning(client)
            val prompt = client.receive(
                GermanEidSdkEvent.SecretRequested(
                    kind,
                    reader(presentCard(retryCounter)),
                ),
            )
            assertEquals(GermanEidSdkCommand.InterruptSystemDialog, prompt.commands.single())
            val requested = prompt.uiEvents.single() as GermanEidUiEvent.SecretRequested
            assertEquals(kind, requested.kind)
            assertEquals(retryCounter, requested.retryCounter)

            val source = digits.toByteArray()
            val secret = GermanEidCardSecret(kind, source)
            source.fill(0)
            val output = client.act(
                GermanEidUserAction.SubmitSecret(secret, requested.interactionId),
            )
            assertTrue(secret.isConsumed)
            assertFalse(output.toString().contains(digits))
            val emitted = (output.commands.single() as GermanEidSdkCommand.SetSecret).secret
            assertEquals(digits, emitted.consume { it.toString(Charsets.UTF_8) })
            assertTrue(emitted.isConsumed)
            assertReason(GermanEidClientError.SECRET_ALREADY_CONSUMED) {
                emitted.consume { Unit }
            }
        }
    }

    @Test
    fun acceptedCanRightAllowsDeactivatedCardRecovery() {
        val canContract = providerContract(
            required = requiredRights + GermanEidAccessRight.CAN_ALLOWED,
        )
        val client = DeterministicGermanEidClient()
        advanceToRunning(client, canContract)
        val deactivated = reader(
            presentCard(
                retryCounter = 0,
                deactivated = true,
                inoperative = true,
            ),
        )
        val prompt = client.receive(
            GermanEidSdkEvent.SecretRequested(GermanEidSecretKind.CAN, deactivated),
        )
        assertEquals(GermanEidSdkCommand.InterruptSystemDialog, prompt.commands.single())
        val requested = prompt.uiEvents.single() as GermanEidUiEvent.SecretRequested
        assertEquals(GermanEidSecretKind.CAN, requested.kind)
        assertEquals(0, requested.retryCounter)
        val output = client.act(
            GermanEidUserAction.SubmitSecret(
                GermanEidCardSecret(GermanEidSecretKind.CAN, "654321".toByteArray()),
                requested.interactionId,
            ),
        )
        assertTrue(output.commands.single() is GermanEidSdkCommand.SetSecret)

        val withoutCanAllowed = DeterministicGermanEidClient()
        advanceToRunning(withoutCanAllowed)
        assertFlowReason(GermanEidClientError.INVALID_CARD_STATE, expectsCancel = true) {
            withoutCanAllowed.receive(
                GermanEidSdkEvent.SecretRequested(
                    GermanEidSecretKind.CAN,
                    deactivated,
                ),
            )
        }
    }

    @Test
    fun keypadInvalidRetryAndConsumedSecretsFailClosed() {
        val keypad = DeterministicGermanEidClient()
        advanceToRunning(keypad)
        assertFlowReason(GermanEidClientError.INVALID_CARD_STATE, expectsCancel = true) {
            keypad.receive(
                GermanEidSdkEvent.SecretRequested(
                    GermanEidSecretKind.PIN,
                    reader(keypad = true),
                ),
            )
        }

        val retry = DeterministicGermanEidClient()
        advanceToRunning(retry)
        assertFlowReason(GermanEidClientError.INVALID_CARD_STATE, expectsCancel = true) {
            retry.receive(
                GermanEidSdkEvent.SecretRequested(
                    GermanEidSecretKind.PUK,
                    reader(presentCard(1)),
                ),
            )
        }

        val consumed = DeterministicGermanEidClient()
        advanceToRunning(consumed)
        val prompt = consumed.receive(
            GermanEidSdkEvent.SecretRequested(GermanEidSecretKind.PIN, reader()),
        ).uiEvents.single() as GermanEidUiEvent.SecretRequested
        val secret = GermanEidCardSecret(GermanEidSecretKind.PIN, "123456".toByteArray())
        secret.consume { Unit }
        assertFlowReason(GermanEidClientError.INVALID_SECRET, expectsCancel = true) {
            consumed.act(GermanEidUserAction.SubmitSecret(secret, prompt.interactionId))
        }
    }

    @Test
    fun externalContactlessLookalikeCannotSatisfyAnySecretRequest() {
        val externalLookalike = reader(
            kind = GermanEidReaderKind.UNSUPPORTED_OR_EXTERNAL,
            attached = true,
            insertable = false,
            keypad = false,
        )
        val client = DeterministicGermanEidClient()
        advanceToRunning(client)
        val update = client.receive(GermanEidSdkEvent.Reader(externalLookalike))
        assertEquals(externalLookalike, (update.uiEvents.single() as GermanEidUiEvent.Reader).value)
        val failure = assertFlowReason(
            GermanEidClientError.INVALID_CARD_STATE,
            expectsCancel = true,
        ) {
            client.receive(
                GermanEidSdkEvent.SecretRequested(
                    GermanEidSecretKind.PIN,
                    externalLookalike,
                ),
            )
        }
        assertEquals(
            listOf(
                GermanEidSdkCommand.InterruptSystemDialog,
                GermanEidSdkCommand.Cancel,
            ),
            failure.recovery.commands,
        )
        assertEquals(
            externalLookalike,
            (failure.recovery.uiEvents.single() as GermanEidUiEvent.Reader).value,
        )
    }

    @Test
    fun invalidEnterPukInterruptsBeforeCancelAndPublishesReaderFact() {
        listOf(
            presentCard(retryCounter = 0, deactivated = true),
            presentCard(retryCounter = 0, inoperative = true),
        ).forEach { cardState ->
            val client = DeterministicGermanEidClient()
            advanceToRunning(client)
            val invalidReader = reader(cardState)
            val failure = assertFlowReason(
                GermanEidClientError.INVALID_CARD_STATE,
                expectsCancel = true,
            ) {
                client.receive(
                    GermanEidSdkEvent.SecretRequested(
                        GermanEidSecretKind.PUK,
                        invalidReader,
                    ),
                )
            }
            assertEquals(
                listOf(
                    GermanEidSdkCommand.InterruptSystemDialog,
                    GermanEidSdkCommand.Cancel,
                ),
                failure.recovery.commands,
            )
            assertEquals(
                invalidReader,
                (failure.recovery.uiEvents.single() as GermanEidUiEvent.Reader).value,
            )
        }
    }

    @Test
    fun duplicateAndStaleInteractionsAreIdempotentOrRejectedWithoutStateLoss() {
        val client = DeterministicGermanEidClient()
        val consent = advanceToRunning(client)
        assertTrue(client.act(GermanEidUserAction.Accept(consent.interactionId)).commands.isEmpty())

        val requested = client.receive(
            GermanEidSdkEvent.SecretRequested(GermanEidSecretKind.PIN, reader()),
        ).uiEvents.single() as GermanEidUiEvent.SecretRequested
        val stale = GermanEidCardSecret(GermanEidSecretKind.PIN, "111111".toByteArray())
        assertFlowReason(GermanEidClientError.STALE_INTERACTION, expectsCancel = false) {
            client.act(
                GermanEidUserAction.SubmitSecret(
                    stale,
                    GermanEidInteractionId(requested.interactionId.value + 1),
                ),
            )
        }
        assertTrue(stale.isConsumed)

        val submitted = GermanEidCardSecret(GermanEidSecretKind.PIN, "123456".toByteArray())
        client.act(GermanEidUserAction.SubmitSecret(submitted, requested.interactionId)).close()
        assertTrue(submitted.isConsumed)
        val duplicate = GermanEidCardSecret(GermanEidSecretKind.PIN, "654321".toByteArray())
        assertTrue(
            client.act(GermanEidUserAction.SubmitSecret(duplicate, requested.interactionId))
                .commands.isEmpty(),
        )
        assertTrue(duplicate.isConsumed)

        val paused = client.receive(
            GermanEidSdkEvent.Paused(GermanEidPauseCause.BAD_CARD_POSITION),
        ).uiEvents.single() as GermanEidUiEvent.Paused
        assertFlowReason(GermanEidClientError.STALE_INTERACTION, expectsCancel = false) {
            client.act(GermanEidUserAction.Accept(consent.interactionId))
        }
        assertEquals(
            GermanEidSdkCommand.ContinueAfterPause,
            client.act(GermanEidUserAction.ContinueAfterPause(paused.interactionId))
                .commands.single(),
        )
        assertTrue(
            client.act(GermanEidUserAction.ContinueAfterPause(paused.interactionId))
                .commands.isEmpty(),
        )
    }

    @Test
    fun unchangedReaderPreservesPromptWhileFullReaderStateChangesInvalidateIt() {
        val preserved = DeterministicGermanEidClient()
        advanceToRunning(preserved)
        val unchangedReader = reader(presentCard(3))
        val prompt = preserved.receive(
            GermanEidSdkEvent.SecretRequested(GermanEidSecretKind.PIN, unchangedReader),
        ).uiEvents.single() as GermanEidUiEvent.SecretRequested
        preserved.receive(GermanEidSdkEvent.Reader(unchangedReader))
        val accepted = GermanEidCardSecret(GermanEidSecretKind.PIN, "123456".toByteArray())
        assertTrue(
            preserved.act(GermanEidUserAction.SubmitSecret(accepted, prompt.interactionId))
                .commands.single() is GermanEidSdkCommand.SetSecret,
        )

        val changed = DeterministicGermanEidClient()
        advanceToRunning(changed)
        val oldPrompt = changed.receive(
            GermanEidSdkEvent.SecretRequested(GermanEidSecretKind.PIN, unchangedReader),
        ).uiEvents.single() as GermanEidUiEvent.SecretRequested
        changed.receive(GermanEidSdkEvent.Reader(reader(presentCard(2))))
        val invalidated = GermanEidCardSecret(GermanEidSecretKind.PIN, "123456".toByteArray())
        assertFlowReason(GermanEidClientError.STALE_INTERACTION, expectsCancel = false) {
            changed.act(
                GermanEidUserAction.SubmitSecret(invalidated, oldPrompt.interactionId),
            )
        }
        assertTrue(invalidated.isConsumed)
        val freshPrompt = changed.receive(
            GermanEidSdkEvent.SecretRequested(
                GermanEidSecretKind.PIN,
                reader(presentCard(2)),
            ),
        ).uiEvents.single() as GermanEidUiEvent.SecretRequested
        assertNotEquals(oldPrompt.interactionId, freshPrompt.interactionId)

        val reclassified = DeterministicGermanEidClient()
        advanceToRunning(reclassified)
        val attestedPrompt = reclassified.receive(
            GermanEidSdkEvent.SecretRequested(GermanEidSecretKind.PIN, unchangedReader),
        ).uiEvents.single() as GermanEidUiEvent.SecretRequested
        reclassified.receive(
            GermanEidSdkEvent.Reader(
                unchangedReader.copy(kind = GermanEidReaderKind.UNSUPPORTED_OR_EXTERNAL),
            ),
        )
        val noLongerAttested = GermanEidCardSecret(
            GermanEidSecretKind.PIN,
            "123456".toByteArray(),
        )
        assertFlowReason(GermanEidClientError.STALE_INTERACTION, expectsCancel = false) {
            reclassified.act(
                GermanEidUserAction.SubmitSecret(
                    noLongerAttested,
                    attestedPrompt.interactionId,
                ),
            )
        }
        assertTrue(noLongerAttested.isConsumed)
    }

    @Test
    fun detachedIntegratedReaderIsBenignAndInvalidatesOutstandingPrompt() {
        val client = DeterministicGermanEidClient()
        advanceToRunning(client)
        val prompt = client.receive(
            GermanEidSdkEvent.SecretRequested(GermanEidSecretKind.PIN, reader()),
        ).uiEvents.single() as GermanEidUiEvent.SecretRequested
        val detachedIntegrated = reader(
            card = GermanEidCardState.Absent,
            kind = GermanEidReaderKind.TRUSTED_PLATFORM_INTEGRATED_NFC,
            attached = false,
        )
        val update = client.receive(GermanEidSdkEvent.Reader(detachedIntegrated))
        assertTrue(update.commands.isEmpty())
        assertEquals(
            detachedIntegrated,
            (update.uiEvents.single() as GermanEidUiEvent.Reader).value,
        )

        val staleSecret = GermanEidCardSecret(
            GermanEidSecretKind.PIN,
            "123456".toByteArray(),
        )
        assertFlowReason(GermanEidClientError.STALE_INTERACTION, expectsCancel = false) {
            client.act(
                GermanEidUserAction.SubmitSecret(staleSecret, prompt.interactionId),
            )
        }
        assertTrue(staleSecret.isConsumed)
    }

    @Test
    fun cardRequiredAndPauseInvalidateSecretPromptUntilFreshSdkRequest() {
        val card = DeterministicGermanEidClient()
        advanceToRunning(card)
        val cardPrompt = card.receive(
            GermanEidSdkEvent.SecretRequested(GermanEidSecretKind.PIN, reader()),
        ).uiEvents.single() as GermanEidUiEvent.SecretRequested
        assertEquals(
            GermanEidUiEvent.CardRequired,
            card.receive(GermanEidSdkEvent.CardRequired).uiEvents.single(),
        )
        val afterRemoval = GermanEidCardSecret(GermanEidSecretKind.PIN, "123456".toByteArray())
        assertFlowReason(GermanEidClientError.STALE_INTERACTION, expectsCancel = false) {
            card.act(GermanEidUserAction.SubmitSecret(afterRemoval, cardPrompt.interactionId))
        }
        assertTrue(afterRemoval.isConsumed)

        val pausedClient = DeterministicGermanEidClient()
        advanceToRunning(pausedClient)
        val oldPrompt = pausedClient.receive(
            GermanEidSdkEvent.SecretRequested(GermanEidSecretKind.PIN, reader()),
        ).uiEvents.single() as GermanEidUiEvent.SecretRequested
        val paused = pausedClient.receive(
            GermanEidSdkEvent.Paused(GermanEidPauseCause.BAD_CARD_POSITION),
        ).uiEvents.single() as GermanEidUiEvent.Paused
        val pausedReader = pausedClient.receive(
            GermanEidSdkEvent.Reader(reader(presentCard(inoperative = true))),
        )
        assertTrue(pausedReader.commands.isEmpty())
        val deactivatedReader = pausedClient.receive(
            GermanEidSdkEvent.Reader(reader(presentCard(deactivated = true))),
        )
        assertEquals(
            GermanEidSdkCommand.InterruptSystemDialog,
            deactivatedReader.commands.single(),
        )
        val oldSecret = GermanEidCardSecret(GermanEidSecretKind.PIN, "123456".toByteArray())
        assertFlowReason(GermanEidClientError.STALE_INTERACTION, expectsCancel = false) {
            pausedClient.act(
                GermanEidUserAction.SubmitSecret(oldSecret, oldPrompt.interactionId),
            )
        }
        assertEquals(
            GermanEidSdkCommand.ContinueAfterPause,
            pausedClient.act(GermanEidUserAction.ContinueAfterPause(paused.interactionId))
                .commands.single(),
        )
        val fresh = pausedClient.receive(
            GermanEidSdkEvent.SecretRequested(GermanEidSecretKind.PIN, reader()),
        ).uiEvents.single() as GermanEidUiEvent.SecretRequested
        assertNotEquals(oldPrompt.interactionId, fresh.interactionId)
    }

    @Test
    fun staleOuterAndInnerSessionsAreRejectedWithoutMutatingCurrentFlow() {
        val staleSession = session(0x33)
        val client = DeterministicGermanEidClient()
        val consent = advanceToConsent(client)
        assertFlowReason(GermanEidClientError.STALE_SESSION, expectsCancel = false) {
            client.receive(GermanEidSdkEvent.Reader(reader()), staleSession)
        }
        client.act(GermanEidUserAction.Accept(consent.interactionId))

        val prompt = client.receive(
            GermanEidSdkEvent.SecretRequested(GermanEidSecretKind.PIN, reader()),
        ).uiEvents.single() as GermanEidUiEvent.SecretRequested
        val staleActionSecret = GermanEidCardSecret(
            GermanEidSecretKind.PIN,
            "123456".toByteArray(),
        )
        assertFlowReason(GermanEidClientError.STALE_SESSION, expectsCancel = false) {
            client.act(
                GermanEidUserAction.SubmitSecret(staleActionSecret, prompt.interactionId),
                staleSession,
            )
        }
        assertTrue(staleActionSecret.isConsumed)
        client.act(
            GermanEidUserAction.SubmitSecret(
                GermanEidCardSecret(GermanEidSecretKind.PIN, "123456".toByteArray()),
                prompt.interactionId,
            ),
        ).close()

        val staleResult = result(
            GermanEidAuthenticationOutcome.Success,
            "https://provider.example/refresh?stale=1",
            session = staleSession,
        )
        assertFlowReason(GermanEidClientError.STALE_SESSION, expectsCancel = false) {
            client.receive(GermanEidSdkEvent.AuthenticationFinished(staleResult))
        }
        assertTrue(staleResult.refreshOrCommunicationUrl?.isConsumed == true)

        val completed = client.receive(
            GermanEidSdkEvent.AuthenticationFinished(
                result(
                    GermanEidAuthenticationOutcome.Success,
                    "https://provider.example/refresh",
                ),
            ),
        )
        assertEquals(
            GermanEidAuthenticationOutcome.Success,
            (completed.uiEvents.single() as GermanEidUiEvent.Completed).result.outcome,
        )
    }

    @Test
    fun resultRequiresExactContractConsentAndTerminalAuthParsing() {
        assertReason(GermanEidClientError.INVALID_RESULT) {
            result(GermanEidAuthenticationOutcome.Success)
        }
        assertReason(GermanEidClientError.INVALID_RESULT) {
            result(GermanEidAuthenticationOutcome.Success, "http://provider.example/result")
        }

        val premature = DeterministicGermanEidClient()
        advanceToRunning(premature)
        val prompt = premature.receive(
            GermanEidSdkEvent.SecretRequested(GermanEidSecretKind.PIN, reader()),
        ).uiEvents.single() as GermanEidUiEvent.SecretRequested
        val prematureResult = result(
            GermanEidAuthenticationOutcome.Success,
            "https://provider.example/refresh",
        )
        val prematureFailure = assertFlowReason(
            GermanEidClientError.INVALID_RESULT,
            expectsCancel = false,
        ) {
            premature.receive(GermanEidSdkEvent.AuthenticationFinished(prematureResult))
        }
        assertCompletedFailure(prematureFailure.recovery, GermanEidFailureReason.SDK)
        assertTrue(prematureResult.refreshOrCommunicationUrl?.isConsumed == true)
        assertTrue(prompt.interactionId.toString().contains("REDACTED"))

        val malformed = DeterministicGermanEidClient()
        advanceToRunning(malformed)
        val parseFailure = assertFlowReason(
            GermanEidClientError.INVALID_RESULT,
            expectsCancel = false,
        ) {
            malformed.receive(GermanEidSdkEvent.AuthenticationResultInvalid)
        }
        assertCompletedFailure(parseFailure.recovery, GermanEidFailureReason.SDK)
        assertFlowReason(GermanEidClientError.ALREADY_TERMINAL, expectsCancel = false) {
            malformed.act(GermanEidUserAction.Cancel)
        }
    }

    @Test
    fun successfulResultIsBoundedRedactedAndTerminal() {
        val client = DeterministicGermanEidClient()
        advanceToRunning(client)
        val output = client.receive(
            GermanEidSdkEvent.AuthenticationFinished(
                result(
                    GermanEidAuthenticationOutcome.Success,
                    "https://provider.example/refresh?session=result-secret",
                ),
            ),
        )
        assertFalse(output.toString().contains("result-secret"))
        val emitted = (output.uiEvents.single() as GermanEidUiEvent.Completed).result
        assertEquals(GermanEidAuthenticationOutcome.Success, emitted.outcome)
        assertEquals(
            "https://provider.example/refresh?session=result-secret",
            emitted.refreshOrCommunicationUrl?.consume { it.toString(Charsets.UTF_8) },
        )
        assertFlowReason(GermanEidClientError.ALREADY_TERMINAL, expectsCancel = false) {
            client.act(GermanEidUserAction.Cancel)
        }
    }

    @Test
    fun cancellationPreservesFailureButWinsSuccessRaceAndTimeout() {
        val beforeAccept = DeterministicGermanEidClient()
        advanceToConsent(beforeAccept)
        assertEquals(
            GermanEidSdkCommand.Cancel,
            beforeAccept.act(GermanEidUserAction.Cancel).commands.single(),
        )
        val failed = beforeAccept.receive(
            GermanEidSdkEvent.AuthenticationFinished(
                result(
                    GermanEidAuthenticationOutcome.Failure(
                        GermanEidFailureReason.COMMUNICATION,
                    ),
                    "https://errors.example/help",
                ),
            ),
        )
        assertCompletedFailure(failed, GermanEidFailureReason.COMMUNICATION)

        val accepted = DeterministicGermanEidClient()
        advanceToRunning(accepted)
        accepted.act(GermanEidUserAction.Cancel)
        assertTrue(accepted.act(GermanEidUserAction.Cancel).commands.isEmpty())
        val racedResult = result(
            GermanEidAuthenticationOutcome.Success,
            "https://provider.example/refresh?raced=1",
        )
        val raced = accepted.receive(GermanEidSdkEvent.AuthenticationFinished(racedResult))
        assertCompletedFailure(raced, GermanEidFailureReason.CANCELLED)
        assertTrue(racedResult.refreshOrCommunicationUrl?.isConsumed == true)

        val timedOut = DeterministicGermanEidClient()
        advanceToRunning(timedOut)
        timedOut.act(GermanEidUserAction.Cancel)
        val timeoutFailure = assertFlowReason(
            GermanEidClientError.ADAPTER_FAILURE,
            expectsCancel = false,
        ) {
            timedOut.receive(GermanEidSdkEvent.CancellationTimedOut)
        }
        assertCompletedFailure(timeoutFailure.recovery, GermanEidFailureReason.CANCELLED)
        assertFlowReason(GermanEidClientError.ALREADY_TERMINAL, expectsCancel = false) {
            timedOut.act(GermanEidUserAction.Cancel)
        }
    }

    @Test
    fun cancellationPhaseDistinguishesAuthoritativeAndDelayedStartFailure() {
        val startPending = DeterministicGermanEidClient()
        startPending.start(request())
        startPending.receive(GermanEidSdkEvent.ApiLevels(setOf(3)))
        startPending.receive(GermanEidSdkEvent.ApiLevelSelected(3)).close()
        assertEquals(
            GermanEidSdkCommand.Cancel,
            startPending.act(GermanEidUserAction.Cancel).commands.single(),
        )
        val authoritative = startPending.receive(GermanEidSdkEvent.AuthenticationStartFailed)
        assertCompletedFailure(authoritative, GermanEidFailureReason.CANCELLED)

        val confirmedAfterCancel = DeterministicGermanEidClient()
        confirmedAfterCancel.start(request())
        confirmedAfterCancel.receive(GermanEidSdkEvent.ApiLevels(setOf(3)))
        confirmedAfterCancel.receive(GermanEidSdkEvent.ApiLevelSelected(3)).close()
        confirmedAfterCancel.act(GermanEidUserAction.Cancel)
        assertTrue(
            confirmedAfterCancel.receive(GermanEidSdkEvent.AuthenticationStarted)
                .uiEvents.isEmpty(),
        )
        assertTrue(
            confirmedAfterCancel.receive(GermanEidSdkEvent.AuthenticationStartFailed)
                .uiEvents.isEmpty(),
        )
        val postStartFinal = confirmedAfterCancel.receive(
            GermanEidSdkEvent.AuthenticationFinished(
                result(GermanEidAuthenticationOutcome.Failure(GermanEidFailureReason.CARD)),
            ),
        )
        assertCompletedFailure(postStartFinal, GermanEidFailureReason.CARD)

        val confirmed = DeterministicGermanEidClient()
        advanceToRunning(confirmed)
        confirmed.act(GermanEidUserAction.Cancel)
        val ignoredReader = confirmed.receive(
            GermanEidSdkEvent.Reader(reader(presentCard(deactivated = true))),
        )
        assertTrue(ignoredReader.commands.isEmpty())
        assertTrue(ignoredReader.uiEvents.isEmpty())
        val delayedStartFailure = confirmed.receive(GermanEidSdkEvent.AuthenticationStartFailed)
        assertTrue(delayedStartFailure.commands.isEmpty())
        assertTrue(delayedStartFailure.uiEvents.isEmpty())

        val finalFailure = confirmed.receive(
            GermanEidSdkEvent.AuthenticationFinished(
                result(GermanEidAuthenticationOutcome.Failure(GermanEidFailureReason.CARD)),
            ),
        )
        assertCompletedFailure(finalFailure, GermanEidFailureReason.CARD)
    }

    @Test
    fun localFaultIssuesOneCancelAndWaitsForFinalAuth() {
        val client = DeterministicGermanEidClient()
        advanceToConsent(client)
        val failure = assertFlowReason(GermanEidClientError.INVALID_TRANSITION, expectsCancel = true) {
            client.receive(GermanEidSdkEvent.ApiLevelSelected(3))
        }
        assertEquals(1, failure.recovery.commands.size)
        assertTrue(client.receive(GermanEidSdkEvent.Reader(reader())).commands.isEmpty())
        assertTrue(client.act(GermanEidUserAction.Cancel).commands.isEmpty())
        val completed = client.receive(
            GermanEidSdkEvent.AuthenticationFinished(
                result(GermanEidAuthenticationOutcome.Failure(GermanEidFailureReason.CARD)),
            ),
        )
        assertCompletedFailure(completed, GermanEidFailureReason.CARD)
    }

    @Test
    fun authenticationStartFailureAndLiveAdapterFaultAreDistinct() {
        val startFailure = DeterministicGermanEidClient()
        startFailure.start(request())
        startFailure.receive(GermanEidSdkEvent.ApiLevels(setOf(3)))
        startFailure.receive(GermanEidSdkEvent.ApiLevelSelected(3)).close()
        val completed = startFailure.receive(GermanEidSdkEvent.AuthenticationStartFailed)
        assertCompletedFailure(completed, GermanEidFailureReason.SDK)

        val liveFault = DeterministicGermanEidClient()
        advanceToConsent(liveFault)
        assertFlowReason(GermanEidClientError.ADAPTER_FAILURE, expectsCancel = true) {
            liveFault.receive(GermanEidSdkEvent.AdapterFailed)
        }
    }

    @Test
    fun shutdownIsGenerationBoundAndCancelsOnlyWhenSdkMayBeLive() {
        val staleSession = session(0x22)
        val beforeRunRequest = request()
        val beforeRun = DeterministicGermanEidClient()
        beforeRun.start(beforeRunRequest)
        assertFlowReason(GermanEidClientError.STALE_SESSION, expectsCancel = false) {
            beforeRun.shutdown(staleSession)
        }
        val localShutdown = beforeRun.shutdown(sessionId)
        assertTrue(localShutdown.commands.isEmpty())
        assertTrue(beforeRunRequest.tcTokenUrl.isConsumed)

        val live = DeterministicGermanEidClient()
        live.start(request())
        live.receive(GermanEidSdkEvent.ApiLevels(setOf(3)))
        val run = live.receive(GermanEidSdkEvent.ApiLevelSelected(3))
        run.close()
        assertEquals(
            GermanEidSdkCommand.Cancel,
            live.shutdown(sessionId).commands.single(),
        )
        assertTrue(live.shutdown(sessionId).commands.isEmpty())
        val timeoutFailure = assertFlowReason(
            GermanEidClientError.ADAPTER_FAILURE,
            expectsCancel = false,
        ) {
            live.receive(GermanEidSdkEvent.CancellationTimedOut)
        }
        assertCompletedFailure(timeoutFailure.recovery, GermanEidFailureReason.SDK)
    }

    @Test
    fun unsupportedApiSecondStartAndSessionConstructionFailClosed() {
        assertReason(GermanEidClientError.INVALID_CONFIGURATION) {
            GermanEidSessionId(ByteArray(32))
        }
        val randomA = GermanEidSessionId.random()
        val randomB = GermanEidSessionId.random()
        assertNotEquals(randomA, randomB)
        assertTrue(randomA.toString().contains("REDACTED"))

        val client = DeterministicGermanEidClient()
        client.start(request())
        assertFlowReason(GermanEidClientError.INVALID_TRANSITION, expectsCancel = false) {
            client.start(request())
        }

        val second = DeterministicGermanEidClient()
        second.start(request())
        assertFlowReason(GermanEidClientError.UNSUPPORTED_API_LEVEL, expectsCancel = false) {
            second.receive(GermanEidSdkEvent.ApiLevels(setOf(1, 4)))
        }
    }

    private fun assertImmutable(rights: Set<GermanEidAccessRight>) {
        @Suppress("UNCHECKED_CAST")
        val mutable = rights as MutableSet<GermanEidAccessRight>
        assertThrows(UnsupportedOperationException::class.java) {
            mutable.add(GermanEidAccessRight.NATIONALITY)
        }
    }

    private fun assertBenignReaderUpdate(output: GermanEidOutput) {
        assertTrue(output.commands.isEmpty())
        assertTrue(output.uiEvents.single() is GermanEidUiEvent.Reader)
    }

    private fun assertCompletedFailure(
        output: GermanEidOutput,
        reason: GermanEidFailureReason,
    ) {
        assertEquals(
            GermanEidAuthenticationOutcome.Failure(reason),
            (output.uiEvents.single() as GermanEidUiEvent.Completed).result.outcome,
        )
    }

    private fun assertReason(expected: GermanEidClientError, body: () -> Unit) {
        val error = assertThrows(GermanEidClientException::class.java, body)
        assertEquals(expected, error.reason)
    }

    private fun assertFlowReason(
        expected: GermanEidClientError,
        expectsCancel: Boolean,
        body: () -> Unit,
    ): GermanEidFlowException {
        val error = assertThrows(GermanEidFlowException::class.java, body)
        assertEquals(expected, error.reason)
        val cancelCount = error.recovery.commands.count { it == GermanEidSdkCommand.Cancel }
        assertEquals(if (expectsCancel) 1 else 0, cancelCount)
        return error
    }
}
