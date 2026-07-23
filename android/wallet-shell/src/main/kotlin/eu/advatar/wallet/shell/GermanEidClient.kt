package eu.advatar.wallet.shell

import java.net.URI
import java.security.SecureRandom
import java.util.Collections

private fun <Value> immutableSet(values: Set<Value>): Set<Value> =
    Collections.unmodifiableSet(LinkedHashSet(values))

/** Native-only AusweisApp boundary. These types are deliberately absent from Rust/UniFFI JSON. */
enum class GermanEidClientError {
    INVALID_CONFIGURATION,
    INVALID_TRANSITION,
    UNSUPPORTED_API_LEVEL,
    INVALID_ACCESS_RIGHTS,
    INVALID_CERTIFICATE,
    INVALID_CARD_STATE,
    INVALID_SECRET,
    SECRET_ALREADY_CONSUMED,
    INVALID_RESULT,
    ADAPTER_FAILURE,
    STALE_SESSION,
    STALE_INTERACTION,
    ALREADY_TERMINAL,
}

class GermanEidClientException(
    val reason: GermanEidClientError,
) : IllegalStateException("German eID client rejected input: ${reason.name}")

class GermanEidFlowException(
    val reason: GermanEidClientError,
    val recovery: GermanEidOutput,
) : IllegalStateException("German eID flow rejected input: ${reason.name}")

/** Opaque 256-bit CSPRNG adapter generation; correlation data is always redacted. */
class GermanEidSessionId internal constructor(bytes: ByteArray) {
    private val bytes: ByteArray

    init {
        if (bytes.size != 32 || bytes.all { it == 0.toByte() }) {
            throw GermanEidClientException(GermanEidClientError.INVALID_CONFIGURATION)
        }
        this.bytes = bytes.copyOf()
    }

    override fun equals(other: Any?): Boolean =
        other is GermanEidSessionId && bytes.contentEquals(other.bytes)

    override fun hashCode(): Int = bytes.contentHashCode()

    override fun toString(): String = "GermanEidSessionId([REDACTED])"

    companion object {
        fun random(): GermanEidSessionId {
            val bytes = ByteArray(32)
            SecureRandom().nextBytes(bytes)
            return GermanEidSessionId(bytes)
        }
    }
}

/** Coordinator-issued holder-interaction generation; callers echo it exactly once. */
class GermanEidInteractionId internal constructor(internal val value: Long) {
    override fun equals(other: Any?): Boolean =
        other is GermanEidInteractionId && value == other.value

    override fun hashCode(): Int = value.hashCode()

    override fun toString(): String = "GermanEidInteractionId([REDACTED])"
}

/** Closed access-right vocabulary from the AusweisApp SDK 2.5.4 protocol. */
enum class GermanEidAccessRight(val wireValue: String) {
    ADDRESS("Address"),
    BIRTH_NAME("BirthName"),
    FAMILY_NAME("FamilyName"),
    GIVEN_NAMES("GivenNames"),
    PLACE_OF_BIRTH("PlaceOfBirth"),
    DATE_OF_BIRTH("DateOfBirth"),
    DOCTORAL_DEGREE("DoctoralDegree"),
    ARTISTIC_NAME("ArtisticName"),
    PSEUDONYM("Pseudonym"),
    VALID_UNTIL("ValidUntil"),
    NATIONALITY("Nationality"),
    ISSUING_COUNTRY("IssuingCountry"),
    DOCUMENT_TYPE("DocumentType"),
    RESIDENCE_PERMIT_I("ResidencePermitI"),
    RESIDENCE_PERMIT_II("ResidencePermitII"),
    COMMUNITY_ID("CommunityID"),
    ADDRESS_VERIFICATION("AddressVerification"),
    AGE_VERIFICATION("AgeVerification"),
    WRITE_ADDRESS("WriteAddress"),
    WRITE_COMMUNITY_ID("WriteCommunityID"),
    WRITE_RESIDENCE_PERMIT_I("WriteResidencePermitI"),
    WRITE_RESIDENCE_PERMIT_II("WriteResidencePermitII"),
    CAN_ALLOWED("CanAllowed"),
    PIN_MANAGEMENT("PinManagement"),
    ;

    companion object {
        fun fromWire(value: String): GermanEidAccessRight? = entries.firstOrNull {
            it.wireValue == value
        }
    }
}

private fun germanEidCanonicalOrigin(value: String, requireOriginOnly: Boolean): String {
    val uri = try {
        ProductionUrlPolicy().validateForIngress(value)
    } catch (_: WalletHttpClientException) {
        throw GermanEidClientException(GermanEidClientError.INVALID_CONFIGURATION)
    }
    if (
        requireOriginOnly &&
        (uri.rawQuery != null || !(uri.rawPath.isNullOrEmpty() || uri.rawPath == "/"))
    ) {
        throw GermanEidClientException(GermanEidClientError.INVALID_CONFIGURATION)
    }
    return URI(uri.scheme, null, uri.host, uri.port, null, null, null).toASCIIString()
}

/**
 * Authenticated PID-provider contract. Administrative write and PIN-management rights are out of
 * scope. RUN_AUTH custom headers are prohibited because AusweisApp forwards them to a
 * RefreshAddress selected inside the TcToken before the wallet can validate that origin.
 */
class GermanEidProviderContract(
    tcTokenOrigin: String,
    refreshOrigin: String,
    communicationOrigins: Set<String> = emptySet(),
    requiredRights: Set<GermanEidAccessRight>,
    optionalRights: Set<GermanEidAccessRight> = emptySet(),
    expectedSubjectName: String,
    expectedSubjectOrigin: String,
    internal val expectedTransactionInfo: String? = null,
    internal val expectedAuxiliaryData: GermanEidAuxiliaryData? = null,
) {
    internal val tcTokenOrigin = germanEidCanonicalOrigin(tcTokenOrigin, true)
    internal val refreshOrigin = germanEidCanonicalOrigin(refreshOrigin, true)
    internal val communicationOrigins = immutableSet(
        communicationOrigins.map { germanEidCanonicalOrigin(it, true) }.toSet(),
    )
    val requiredRights = immutableSet(requiredRights)
    val optionalRights = immutableSet(optionalRights)
    internal val expectedSubjectName = expectedSubjectName
    internal val expectedSubjectOrigin = germanEidCanonicalOrigin(expectedSubjectOrigin, true)

    init {
        val administrativeRights = setOf(
            GermanEidAccessRight.WRITE_ADDRESS,
            GermanEidAccessRight.WRITE_COMMUNITY_ID,
            GermanEidAccessRight.WRITE_RESIDENCE_PERMIT_I,
            GermanEidAccessRight.WRITE_RESIDENCE_PERMIT_II,
            GermanEidAccessRight.PIN_MANAGEMENT,
        )
        if (
            this.requiredRights.isEmpty() ||
            this.requiredRights.intersect(this.optionalRights).isNotEmpty() ||
            (this.requiredRights + this.optionalRights).intersect(administrativeRights).isNotEmpty() ||
            communicationOrigins.size > MAXIMUM_COMMUNICATION_ORIGINS ||
            expectedSubjectName.isEmpty() ||
            expectedSubjectName.toByteArray(Charsets.UTF_8).size > MAXIMUM_SUBJECT_NAME_BYTES ||
            expectedSubjectName.any { it.code < 0x20 || it.code == 0x7f } ||
            expectedTransactionInfo?.let {
                it.isEmpty() || it.toByteArray(Charsets.UTF_8).size > MAXIMUM_TRANSACTION_BYTES
            } == true
        ) {
            throw GermanEidClientException(GermanEidClientError.INVALID_CONFIGURATION)
        }
    }

    internal fun permitsResult(outcome: GermanEidAuthenticationOutcome, url: String): Boolean {
        val origin = try {
            germanEidCanonicalOrigin(url, false)
        } catch (_: GermanEidClientException) {
            return false
        }
        return when (outcome) {
            GermanEidAuthenticationOutcome.Success -> origin == refreshOrigin
            is GermanEidAuthenticationOutcome.Failure ->
                origin == refreshOrigin || origin in communicationOrigins
        }
    }

    /** The provider may later strengthen this binding with a terminal-certificate identifier. */
    internal fun permitsCertificate(certificate: GermanEidCertificate): Boolean {
        if (certificate.subjectName != expectedSubjectName) return false
        val subjectOrigin = try {
            germanEidCanonicalOrigin(certificate.subjectUrl, false)
        } catch (_: GermanEidClientException) {
            return false
        }
        return subjectOrigin == expectedSubjectOrigin
    }

    override fun equals(other: Any?): Boolean = other is GermanEidProviderContract &&
        tcTokenOrigin == other.tcTokenOrigin &&
        refreshOrigin == other.refreshOrigin &&
        communicationOrigins == other.communicationOrigins &&
        requiredRights == other.requiredRights &&
        optionalRights == other.optionalRights &&
        expectedSubjectName == other.expectedSubjectName &&
        expectedSubjectOrigin == other.expectedSubjectOrigin &&
        expectedTransactionInfo == other.expectedTransactionInfo &&
        expectedAuxiliaryData == other.expectedAuxiliaryData

    override fun hashCode(): Int = listOf(
        tcTokenOrigin,
        refreshOrigin,
        communicationOrigins,
        requiredRights,
        optionalRights,
        expectedSubjectName,
        expectedSubjectOrigin,
        expectedTransactionInfo,
        expectedAuxiliaryData,
    ).hashCode()

    override fun toString(): String = "GermanEidProviderContract([REDACTED])"

    private companion object {
        const val MAXIMUM_COMMUNICATION_ORIGINS = 8
        const val MAXIMUM_SUBJECT_NAME_BYTES = 4 * 1024
        const val MAXIMUM_TRANSACTION_BYTES = 8 * 1024
    }
}

enum class GermanEidSecretKind(val digitCount: Int) {
    PIN(6),
    CAN(6),
    PUK(10),
}

/**
 * One-shot owned native secret. [consume] clears this object's bytes in a finally block. The caller
 * remains responsible for clearing any source buffer and a trusted SDK adapter must not retain it.
 */
class GermanEidSensitiveBytes(
    bytes: ByteArray,
    maximumBytes: Int = 32 * 1024,
) : AutoCloseable {
    private val storage: ByteArray
    private var consumed = false

    init {
        if (bytes.isEmpty() || maximumBytes <= 0 || bytes.size > maximumBytes) {
            throw GermanEidClientException(GermanEidClientError.INVALID_CONFIGURATION)
        }
        storage = bytes.copyOf()
    }

    @Synchronized
    fun <Result> consume(block: (ByteArray) -> Result): Result {
        if (consumed) {
            throw GermanEidClientException(GermanEidClientError.SECRET_ALREADY_CONSUMED)
        }
        consumed = true
        return try {
            block(storage)
        } finally {
            storage.fill(0)
        }
    }

    @get:Synchronized
    val isConsumed: Boolean
        get() = consumed

    @Synchronized
    override fun close() {
        consumed = true
        storage.fill(0)
    }

    override fun toString(): String = "GermanEidSensitiveBytes([REDACTED])"
}

class GermanEidCardSecret(
    val kind: GermanEidSecretKind,
    digits: ByteArray,
) : AutoCloseable {
    private val bytes: GermanEidSensitiveBytes

    init {
        if (digits.size != kind.digitCount || digits.any { it.toInt() !in 0x30..0x39 }) {
            throw GermanEidClientException(GermanEidClientError.INVALID_SECRET)
        }
        bytes = GermanEidSensitiveBytes(digits, kind.digitCount)
    }

    val isConsumed: Boolean
        get() = bytes.isConsumed

    fun <Result> consume(block: (ByteArray) -> Result): Result = bytes.consume(block)

    internal fun transferredCopy(): GermanEidCardSecret = consume { source ->
        GermanEidCardSecret(kind, source)
    }

    override fun close() = bytes.close()

    override fun toString(): String = "GermanEidCardSecret(${kind.name}, [REDACTED])"
}

class GermanEidStartRequest(
    tcTokenUrl: ByteArray,
    internal val contract: GermanEidProviderContract,
    internal val sessionId: GermanEidSessionId,
) : AutoCloseable {
    internal val tcTokenUrl: GermanEidSensitiveBytes

    init {
        if (
            tcTokenUrl.isEmpty() ||
            tcTokenUrl.size > MAXIMUM_URL_BYTES ||
            tcTokenUrl.any { it.toInt() !in 0x21..0x7e }
        ) {
            throw GermanEidClientException(GermanEidClientError.INVALID_CONFIGURATION)
        }
        val validatedUrl = tcTokenUrl.toString(Charsets.US_ASCII)
        if (germanEidCanonicalOrigin(validatedUrl, false) != contract.tcTokenOrigin) {
            throw GermanEidClientException(GermanEidClientError.INVALID_CONFIGURATION)
        }
        this.tcTokenUrl = GermanEidSensitiveBytes(tcTokenUrl, MAXIMUM_URL_BYTES)
    }

    override fun toString(): String = "GermanEidStartRequest([REDACTED])"

    override fun close() {
        tcTokenUrl.close()
    }

    internal val hasAvailableSecrets: Boolean
        get() = !tcTokenUrl.isConsumed

    private companion object {
        const val MAXIMUM_URL_BYTES = 4096
    }
}

class GermanEidRunAuthCommand internal constructor(
    request: GermanEidStartRequest,
) : AutoCloseable {
    val tcTokenUrl = request.tcTokenUrl
    val sessionId = request.sessionId
    val developerMode = false
    val statusMessages = true

    override fun toString(): String = "GermanEidRunAuthCommand([REDACTED])"

    override fun close() {
        tcTokenUrl.close()
    }
}

class GermanEidCertificate(
    val issuerName: String,
    val issuerUrl: String,
    val subjectName: String,
    val subjectUrl: String,
    val termsOfUsage: String,
    val purpose: String,
    val effectiveDate: String,
    val expirationDate: String,
) {
    init {
        val fields = listOf(
            issuerName,
            issuerUrl,
            subjectName,
            subjectUrl,
            purpose,
            effectiveDate,
            expirationDate,
        )
        if (
            fields.any { it.isEmpty() || it.toByteArray(Charsets.UTF_8).size > MAXIMUM_FIELD_BYTES } ||
            termsOfUsage.isEmpty() ||
            termsOfUsage.toByteArray(Charsets.UTF_8).size > MAXIMUM_TERMS_BYTES ||
            fields.sumOf { it.toByteArray(Charsets.UTF_8).size } +
            termsOfUsage.toByteArray(Charsets.UTF_8).size > MAXIMUM_TOTAL_BYTES
        ) {
            throw GermanEidClientException(GermanEidClientError.INVALID_CERTIFICATE)
        }
    }

    override fun toString(): String = "GermanEidCertificate([REDACTED])"

    private companion object {
        const val MAXIMUM_FIELD_BYTES = 4 * 1024
        const val MAXIMUM_TERMS_BYTES = 16 * 1024
        const val MAXIMUM_TOTAL_BYTES = 32 * 1024
    }
}

data class GermanEidAuxiliaryData(
    val ageVerificationDate: String? = null,
    val requiredAge: String? = null,
    val validityDate: String? = null,
    val communityId: String? = null,
) {
    init {
        val values = listOf(ageVerificationDate, requiredAge, validityDate, communityId)
        if (
            values.none { it != null } ||
            values.filterNotNull().any {
                it.isEmpty() ||
                    it.toByteArray(Charsets.UTF_8).size > MAXIMUM_VALUE_BYTES ||
                    it.any { character -> character.code < 0x20 || character.code == 0x7f }
            } ||
            values.filterNotNull().sumOf { it.toByteArray(Charsets.UTF_8).size } >
            MAXIMUM_TOTAL_BYTES
        ) {
            throw GermanEidClientException(GermanEidClientError.INVALID_ACCESS_RIGHTS)
        }
    }

    override fun toString(): String = "GermanEidAuxiliaryData([REDACTED])"

    private companion object {
        const val MAXIMUM_VALUE_BYTES = 256
        const val MAXIMUM_TOTAL_BYTES = 1024
    }
}

class GermanEidAccessRights(
    required: Set<GermanEidAccessRight>,
    optional: Set<GermanEidAccessRight>,
    effective: Set<GermanEidAccessRight>,
    val transactionInfo: String? = null,
    val auxiliaryData: GermanEidAuxiliaryData? = null,
) {
    val required = immutableSet(required)
    val optional = immutableSet(optional)
    val effective = immutableSet(effective)

    init {
        if (
            required.size + optional.size > GermanEidAccessRight.entries.size ||
            required.intersect(optional).isNotEmpty() ||
            effective.any { it !in required && it !in optional } ||
            transactionInfo?.let {
                it.isEmpty() || it.toByteArray(Charsets.UTF_8).size > MAXIMUM_TRANSACTION_BYTES
            } == true
        ) {
            throw GermanEidClientException(GermanEidClientError.INVALID_ACCESS_RIGHTS)
        }
    }

    override fun toString(): String = "GermanEidAccessRights([REDACTED])"

    private companion object {
        const val MAXIMUM_TRANSACTION_BYTES = 8 * 1024
    }
}

sealed interface GermanEidCardState {
    data object Absent : GermanEidCardState
    data object Unknown : GermanEidCardState
    data class Present(
        val retryCounter: Int?,
        val deactivated: Boolean,
        val inoperative: Boolean,
    ) : GermanEidCardState
}

/**
 * Trusted adapter-originated reader classification. The future official adapter may assert
 * [TRUSTED_PLATFORM_INTEGRATED_NFC] only for the platform-owned NFC reader. It must never infer
 * that trust from the READER `attached`, `insertable`, or `keypad` booleans.
 */
enum class GermanEidReaderKind {
    TRUSTED_PLATFORM_INTEGRATED_NFC,
    UNSUPPORTED_OR_EXTERNAL,
}

/** Exact READER facts and adapter attestation needed to keep external readers out of this slice. */
data class GermanEidReaderState(
    val kind: GermanEidReaderKind,
    val attached: Boolean,
    val insertable: Boolean,
    val keypad: Boolean,
    val card: GermanEidCardState,
) {
    internal val isTrustedIntegratedNfc: Boolean
        get() = kind == GermanEidReaderKind.TRUSTED_PLATFORM_INTEGRATED_NFC && attached
}

enum class GermanEidPauseCause {
    BAD_CARD_POSITION,
}

enum class GermanEidFailureReason {
    CANCELLED,
    CARD,
    COMMUNICATION,
    SDK,
    UNKNOWN,
}

sealed interface GermanEidAuthenticationOutcome {
    data object Success : GermanEidAuthenticationOutcome
    data class Failure(val reason: GermanEidFailureReason) : GermanEidAuthenticationOutcome
}

class GermanEidAuthenticationResult(
    val outcome: GermanEidAuthenticationOutcome,
    url: ByteArray?,
    internal val contract: GermanEidProviderContract,
    internal val sessionId: GermanEidSessionId,
) : AutoCloseable {
    val refreshOrCommunicationUrl: GermanEidSensitiveBytes?

    init {
        if (outcome == GermanEidAuthenticationOutcome.Success && url == null) {
            throw GermanEidClientException(GermanEidClientError.INVALID_RESULT)
        }
        refreshOrCommunicationUrl = if (url == null) {
            null
        } else {
            if (
                url.isEmpty() ||
                url.size > MAXIMUM_URL_BYTES ||
                url.any { it.toInt() !in 0x21..0x7e }
            ) {
                throw GermanEidClientException(GermanEidClientError.INVALID_RESULT)
            }
            val validatedUrl = url.toString(Charsets.US_ASCII)
            if (!contract.permitsResult(outcome, validatedUrl)) {
                throw GermanEidClientException(GermanEidClientError.INVALID_RESULT)
            }
            GermanEidSensitiveBytes(url, MAXIMUM_URL_BYTES)
        }
    }

    override fun toString(): String = "GermanEidAuthenticationResult($outcome, [REDACTED])"

    override fun close() {
        refreshOrCommunicationUrl?.close()
    }

    private companion object {
        const val MAXIMUM_URL_BYTES = 4096
    }
}

class GermanEidConsent(
    effectiveRights: Set<GermanEidAccessRight>,
    val certificate: GermanEidCertificate,
    val transactionInfo: String?,
    val auxiliaryData: GermanEidAuxiliaryData?,
) {
    val effectiveRights = immutableSet(effectiveRights)

    override fun toString(): String = "GermanEidConsent([REDACTED])"
}

sealed interface GermanEidSdkCommand : AutoCloseable {
    data object GetApiLevel : GermanEidSdkCommand
    data class SetApiLevel(val level: Int) : GermanEidSdkCommand

    class RunAuth(val value: GermanEidRunAuthCommand) : GermanEidSdkCommand {
        override fun toString(): String = "RunAuth([REDACTED])"
    }

    data class SetAccessRights(val rights: Set<GermanEidAccessRight>) : GermanEidSdkCommand
    data object GetCertificate : GermanEidSdkCommand
    data object Accept : GermanEidSdkCommand
    data object Cancel : GermanEidSdkCommand
    /**
     * iOS maps this to INTERRUPT; Android handles it locally without transmitting a command. The
     * adapter must still preserve its position relative to subsequent commands.
     */
    data object InterruptSystemDialog : GermanEidSdkCommand
    data object ContinueAfterPause : GermanEidSdkCommand

    class SetSecret(val secret: GermanEidCardSecret) : GermanEidSdkCommand {
        override fun toString(): String = "SetSecret(${secret.kind}, [REDACTED])"
        override fun close() = secret.close()
    }

    override fun close() {
        if (this is RunAuth) value.close()
    }
}

sealed interface GermanEidUiEvent : AutoCloseable {
    class Consent(
        val value: GermanEidConsent,
        val interactionId: GermanEidInteractionId,
    ) : GermanEidUiEvent {
        override fun toString(): String = "Consent([REDACTED])"
    }

    data class Reader(val value: GermanEidReaderState) : GermanEidUiEvent
    data object CardRequired : GermanEidUiEvent
    data class Paused(
        val cause: GermanEidPauseCause,
        val interactionId: GermanEidInteractionId,
    ) : GermanEidUiEvent
    data class SecretRequested(
        val kind: GermanEidSecretKind,
        val retryCounter: Int?,
        val interactionId: GermanEidInteractionId,
    ) : GermanEidUiEvent

    class Completed(val result: GermanEidAuthenticationResult) : GermanEidUiEvent {
        override fun toString(): String = "Completed([REDACTED])"
        override fun close() = result.close()
    }

    override fun close() = Unit
}

/** Adapters execute [commands] in list order before delivering any [uiEvents]. */
class GermanEidOutput internal constructor(
    val commands: List<GermanEidSdkCommand> = emptyList(),
    val uiEvents: List<GermanEidUiEvent> = emptyList(),
) : AutoCloseable {
    override fun toString(): String = "GermanEidOutput(commands=$commands, uiEvents=$uiEvents)"

    override fun close() {
        commands.forEach { it.close() }
        uiEvents.forEach { it.close() }
    }
}

sealed interface GermanEidSdkEvent {
    data class ApiLevels(val available: Set<Int>) : GermanEidSdkEvent
    data class ApiLevelSelected(val level: Int) : GermanEidSdkEvent
    data object AuthenticationStarted : GermanEidSdkEvent
    data class AccessRights(val value: GermanEidAccessRights) : GermanEidSdkEvent

    data class Certificate(val value: GermanEidCertificate) : GermanEidSdkEvent
    data class Reader(val value: GermanEidReaderState) : GermanEidSdkEvent
    data object CardRequired : GermanEidSdkEvent
    data class Paused(val cause: GermanEidPauseCause) : GermanEidSdkEvent
    data class SecretRequested(
        val kind: GermanEidSecretKind,
        val reader: GermanEidReaderState,
    ) : GermanEidSdkEvent

    data class AuthenticationFinished(val result: GermanEidAuthenticationResult) : GermanEidSdkEvent
    data object AuthenticationResultInvalid : GermanEidSdkEvent
    data object AuthenticationStartFailed : GermanEidSdkEvent
    data object AdapterFailed : GermanEidSdkEvent
    data object CancellationTimedOut : GermanEidSdkEvent
}

sealed interface GermanEidUserAction {
    data class Accept(val interactionId: GermanEidInteractionId) : GermanEidUserAction
    data object Cancel : GermanEidUserAction
    data class ContinueAfterPause(val interactionId: GermanEidInteractionId) : GermanEidUserAction
    data class SubmitSecret(
        val secret: GermanEidCardSecret,
        val interactionId: GermanEidInteractionId,
    ) : GermanEidUserAction
}

/** Native seam implemented by the deterministic coordinator and a future official SDK adapter. */
interface GermanEidClient {
    fun start(request: GermanEidStartRequest): GermanEidOutput

    fun receive(event: GermanEidSdkEvent, sessionId: GermanEidSessionId): GermanEidOutput

    fun act(action: GermanEidUserAction, sessionId: GermanEidSessionId): GermanEidOutput

    fun shutdown(sessionId: GermanEidSessionId): GermanEidOutput
}

/**
 * Serialized, one-shot workflow shared by the official adapter and deterministic tests. The
 * adapter must allocate one instance per generation and discard stale Binder callbacks before
 * invoking [receive].
 */
class DeterministicGermanEidClient(
    supportedApiLevels: Set<Int> = setOf(2, 3),
) : GermanEidClient {
    private sealed interface State {
        data object Idle : State
        class AwaitingApiLevels(val request: GermanEidStartRequest) : State
        class AwaitingApiSelection(val request: GermanEidStartRequest, val level: Int) : State
        data object AwaitingAuthStart : State
        data object AwaitingInitialRights : State
        class AwaitingMinimizedRights(val initial: GermanEidAccessRights) : State
        class AwaitingCertificate(val rights: GermanEidAccessRights) : State
        class AwaitingConsent(
            val consent: GermanEidConsent,
            val interactionId: GermanEidInteractionId,
        ) : State
        data object Running : State
        class AwaitingSecret(
            val kind: GermanEidSecretKind,
            val interactionId: GermanEidInteractionId,
        ) : State
        class Paused(
            val interactionId: GermanEidInteractionId,
        ) : State
        class Cancelling(
            val reason: GermanEidFailureReason,
            val startWasPending: Boolean,
        ) : State
        data object Terminal : State
    }

    private val supportedApiLevels = supportedApiLevels.toSet()
    private var state: State = State.Idle
    private var activeContract: GermanEidProviderContract? = null
    private var activeSessionId: GermanEidSessionId? = null
    private var authorizationAccepted = false
    private var authorizedRights: Set<GermanEidAccessRight> = emptySet()
    private var lastReader: GermanEidReaderState? = null
    private var interactionCounter = 0L
    private var lastAcceptedConsent: GermanEidInteractionId? = null
    private var lastContinuedPause: GermanEidInteractionId? = null
    private var lastSubmittedSecret: GermanEidInteractionId? = null

    @get:Synchronized
    internal val activeProviderContractForAdapter: GermanEidProviderContract
        get() = activeContract ?: fail(GermanEidClientError.INVALID_TRANSITION)

    init {
        if (
            supportedApiLevels.isEmpty() ||
            supportedApiLevels.size > 8 ||
            supportedApiLevels.any { it !in 2..3 }
        ) {
            throw GermanEidClientException(GermanEidClientError.INVALID_CONFIGURATION)
        }
    }

    @Synchronized
    override fun start(request: GermanEidStartRequest): GermanEidOutput {
        if (state != State.Idle) {
            request.close()
            fail(GermanEidClientError.INVALID_TRANSITION)
        }
        activeContract = request.contract
        activeSessionId = request.sessionId
        state = State.AwaitingApiLevels(request)
        return GermanEidOutput(commands = listOf(GermanEidSdkCommand.GetApiLevel))
    }

    @Synchronized
    override fun receive(
        event: GermanEidSdkEvent,
        sessionId: GermanEidSessionId,
    ): GermanEidOutput {
        if (sessionId != activeSessionId) {
            clearSecrets(event)
            throw GermanEidFlowException(GermanEidClientError.STALE_SESSION, GermanEidOutput())
        }
        if (state == State.Terminal) {
            clearSecrets(event)
            fail(GermanEidClientError.ALREADY_TERMINAL)
        }
        val cancelling = state as? State.Cancelling
        if (cancelling != null) {
            if (event is GermanEidSdkEvent.AuthenticationFinished) {
                if (event.result.sessionId != activeSessionId) {
                    event.result.close()
                    throw GermanEidFlowException(
                        GermanEidClientError.STALE_SESSION,
                        GermanEidOutput(),
                    )
                }
                if (event.result.contract != activeContract) {
                    event.result.close()
                    terminalFailure(GermanEidClientError.INVALID_RESULT, cancelling.reason)
                }
                if (event.result.outcome == GermanEidAuthenticationOutcome.Success) {
                    event.result.close()
                    val result = localFailureResult(cancelling.reason)
                    state = State.Terminal
                    return GermanEidOutput(uiEvents = listOf(GermanEidUiEvent.Completed(result)))
                }
                state = State.Terminal
                return GermanEidOutput(
                    uiEvents = listOf(GermanEidUiEvent.Completed(event.result)),
                )
            }
            return when (event) {
                GermanEidSdkEvent.AuthenticationResultInvalid ->
                    terminalFailure(GermanEidClientError.INVALID_RESULT, GermanEidFailureReason.SDK)
                GermanEidSdkEvent.AuthenticationStartFailed -> {
                    if (cancelling.startWasPending) {
                        val result = localFailureResult(cancelling.reason)
                        state = State.Terminal
                        GermanEidOutput(
                            uiEvents = listOf(GermanEidUiEvent.Completed(result)),
                        )
                    } else {
                        GermanEidOutput()
                    }
                }
                GermanEidSdkEvent.AuthenticationStarted -> {
                    if (cancelling.startWasPending) {
                        state = State.Cancelling(
                            cancelling.reason,
                            startWasPending = false,
                        )
                    }
                    GermanEidOutput()
                }
                GermanEidSdkEvent.AdapterFailed,
                GermanEidSdkEvent.CancellationTimedOut,
                -> terminalFailure(GermanEidClientError.ADAPTER_FAILURE, cancelling.reason)
                else -> {
                    clearSecrets(event)
                    GermanEidOutput()
                }
            }
        }
        if (event is GermanEidSdkEvent.Reader) {
            return when (val current = state) {
                is State.AwaitingSecret -> receiveWhileAwaitingSecret(current, event)
                else -> receiveReader(
                    event.value,
                    scanDialogMayBeLive = state == State.Running || state is State.Paused,
                )
            }
        }

        if (event is GermanEidSdkEvent.AuthenticationFinished) {
            if (event.result.sessionId != activeSessionId) {
                event.result.close()
                throw GermanEidFlowException(
                    GermanEidClientError.STALE_SESSION,
                    GermanEidOutput(),
                )
            }
            if (!workflowConfirmed() || event.result.contract != activeContract) {
                event.result.close()
                terminalFailure(GermanEidClientError.INVALID_RESULT, GermanEidFailureReason.SDK)
            }
            if (
                event.result.outcome == GermanEidAuthenticationOutcome.Success &&
                (!authorizationAccepted || !successMayFinish())
            ) {
                event.result.close()
                terminalFailure(GermanEidClientError.INVALID_RESULT, GermanEidFailureReason.SDK)
            }
            state = State.Terminal
            return GermanEidOutput(uiEvents = listOf(GermanEidUiEvent.Completed(event.result)))
        }

        when (event) {
            GermanEidSdkEvent.AuthenticationResultInvalid ->
                terminalFailure(GermanEidClientError.INVALID_RESULT, GermanEidFailureReason.SDK)
            GermanEidSdkEvent.AuthenticationStartFailed -> {
                if (state != State.AwaitingAuthStart) fail(GermanEidClientError.ADAPTER_FAILURE)
                val result = localFailureResult(GermanEidFailureReason.SDK)
                state = State.Terminal
                return GermanEidOutput(uiEvents = listOf(GermanEidUiEvent.Completed(result)))
            }
            GermanEidSdkEvent.AdapterFailed -> fail(GermanEidClientError.ADAPTER_FAILURE)
            GermanEidSdkEvent.CancellationTimedOut -> fail(GermanEidClientError.INVALID_TRANSITION)
            else -> Unit
        }

        return when (val current = state) {
            is State.AwaitingApiLevels -> {
                val available = (event as? GermanEidSdkEvent.ApiLevels)?.available?.toSet()
                    ?: fail(GermanEidClientError.INVALID_TRANSITION)
                val selected = if (
                    available.isNotEmpty() &&
                    available.size <= 8 &&
                    available.all { it in 1..16 }
                ) {
                    supportedApiLevels.intersect(available).maxOrNull()
                } else {
                    null
                } ?: fail(GermanEidClientError.UNSUPPORTED_API_LEVEL)
                state = State.AwaitingApiSelection(current.request, selected)
                GermanEidOutput(commands = listOf(GermanEidSdkCommand.SetApiLevel(selected)))
            }

            is State.AwaitingApiSelection -> {
                val selected = (event as? GermanEidSdkEvent.ApiLevelSelected)?.level
                    ?: fail(GermanEidClientError.INVALID_TRANSITION)
                if (selected != current.level) fail(GermanEidClientError.UNSUPPORTED_API_LEVEL)
                if (!current.request.hasAvailableSecrets) {
                    fail(GermanEidClientError.INVALID_CONFIGURATION)
                }
                state = State.AwaitingAuthStart
                GermanEidOutput(
                    commands = listOf(
                        GermanEidSdkCommand.RunAuth(GermanEidRunAuthCommand(current.request)),
                    ),
                )
            }

            State.AwaitingAuthStart -> {
                if (event != GermanEidSdkEvent.AuthenticationStarted) {
                    fail(GermanEidClientError.INVALID_TRANSITION)
                }
                state = State.AwaitingInitialRights
                GermanEidOutput()
            }

            State.AwaitingInitialRights -> {
                val rights = (event as? GermanEidSdkEvent.AccessRights)?.value
                    ?: fail(GermanEidClientError.INVALID_TRANSITION)
                val contract = activeContract
                    ?: fail(GermanEidClientError.INVALID_CONFIGURATION)
                if (
                    rights.required != contract.requiredRights ||
                    rights.optional != contract.optionalRights ||
                    rights.effective != rights.required + rights.optional ||
                    rights.transactionInfo != contract.expectedTransactionInfo ||
                    rights.auxiliaryData != contract.expectedAuxiliaryData
                ) {
                    fail(GermanEidClientError.INVALID_ACCESS_RIGHTS)
                }
                state = State.AwaitingMinimizedRights(rights)
                GermanEidOutput(
                    commands = listOf(GermanEidSdkCommand.SetAccessRights(emptySet())),
                )
            }

            is State.AwaitingMinimizedRights -> {
                val rights = (event as? GermanEidSdkEvent.AccessRights)?.value
                    ?: fail(GermanEidClientError.INVALID_TRANSITION)
                if (
                    rights.required != current.initial.required ||
                    rights.optional != current.initial.optional ||
                    rights.effective != current.initial.required ||
                    rights.transactionInfo != current.initial.transactionInfo ||
                    rights.auxiliaryData != current.initial.auxiliaryData
                ) {
                    fail(GermanEidClientError.INVALID_ACCESS_RIGHTS)
                }
                state = State.AwaitingCertificate(rights)
                GermanEidOutput(commands = listOf(GermanEidSdkCommand.GetCertificate))
            }

            is State.AwaitingCertificate -> {
                val certificate = (event as? GermanEidSdkEvent.Certificate)?.value
                    ?: fail(GermanEidClientError.INVALID_TRANSITION)
                val contract = activeContract
                    ?: fail(GermanEidClientError.INVALID_CONFIGURATION)
                if (!contract.permitsCertificate(certificate)) {
                    fail(GermanEidClientError.INVALID_CERTIFICATE)
                }
                val consent = GermanEidConsent(
                    current.rights.effective,
                    certificate,
                    current.rights.transactionInfo,
                    current.rights.auxiliaryData,
                )
                val interactionId = nextInteractionId()
                state = State.AwaitingConsent(consent, interactionId)
                GermanEidOutput(
                    uiEvents = listOf(GermanEidUiEvent.Consent(consent, interactionId)),
                )
            }

            State.Running -> receiveDuringRunning(event)
            is State.AwaitingSecret -> receiveWhileAwaitingSecret(current, event)

            State.Idle,
            is State.AwaitingConsent,
            is State.Paused,
            is State.Cancelling,
            State.Terminal,
            -> fail(GermanEidClientError.INVALID_TRANSITION)
        }
    }

    @Synchronized
    override fun act(
        action: GermanEidUserAction,
        sessionId: GermanEidSessionId,
    ): GermanEidOutput {
        if (sessionId != activeSessionId) {
            clearSecrets(action)
            throw GermanEidFlowException(GermanEidClientError.STALE_SESSION, GermanEidOutput())
        }
        if (state == State.Terminal) {
            clearSecrets(action)
            fail(GermanEidClientError.ALREADY_TERMINAL)
        }
        if (state is State.Cancelling) {
            if (action == GermanEidUserAction.Cancel) return GermanEidOutput()
            clearSecrets(action)
            fail(GermanEidClientError.INVALID_TRANSITION)
        }
        when (action) {
            is GermanEidUserAction.Accept -> if (action.interactionId == lastAcceptedConsent) {
                if (state == State.Running) return GermanEidOutput()
                rejectStaleInteraction(action)
            }
            is GermanEidUserAction.ContinueAfterPause ->
                if (action.interactionId == lastContinuedPause) {
                    if (state == State.Running) return GermanEidOutput()
                    rejectStaleInteraction(action)
                }
            is GermanEidUserAction.SubmitSecret -> if (action.interactionId == lastSubmittedSecret) {
                if (state == State.Running) {
                    action.secret.close()
                    return GermanEidOutput()
                }
                rejectStaleInteraction(action)
            }
            GermanEidUserAction.Cancel -> Unit
        }
        return when (action) {
            is GermanEidUserAction.Accept -> {
                val awaiting = state as? State.AwaitingConsent
                    ?: rejectStaleInteraction(action)
                if (action.interactionId != awaiting.interactionId) {
                    rejectStaleInteraction(action)
                }
                authorizationAccepted = true
                authorizedRights = awaiting.consent.effectiveRights
                lastAcceptedConsent = action.interactionId
                state = State.Running
                GermanEidOutput(commands = listOf(GermanEidSdkCommand.Accept))
            }

            GermanEidUserAction.Cancel -> {
                if (state is State.AwaitingApiLevels || state is State.AwaitingApiSelection) {
                    clearHeldSecrets()
                    val result = localFailureResult(GermanEidFailureReason.CANCELLED)
                    state = State.Terminal
                    return GermanEidOutput(
                        uiEvents = listOf(GermanEidUiEvent.Completed(result)),
                    )
                }
                if (!workflowMayBeLive()) fail(GermanEidClientError.INVALID_TRANSITION)
                state = State.Cancelling(
                    GermanEidFailureReason.CANCELLED,
                    startWasPending = state == State.AwaitingAuthStart,
                )
                GermanEidOutput(commands = listOf(GermanEidSdkCommand.Cancel))
            }

            is GermanEidUserAction.ContinueAfterPause -> {
                val paused = state as? State.Paused ?: rejectStaleInteraction(action)
                if (action.interactionId != paused.interactionId) {
                    rejectStaleInteraction(action)
                }
                lastContinuedPause = action.interactionId
                // A pre-pause prompt remains invalid. Wait for a fresh ENTER_* after CONTINUE.
                state = State.Running
                GermanEidOutput(
                    commands = listOf(GermanEidSdkCommand.ContinueAfterPause),
                )
            }

            is GermanEidUserAction.SubmitSecret -> {
                val awaiting = state as? State.AwaitingSecret
                    ?: rejectStaleInteraction(action)
                if (action.interactionId != awaiting.interactionId) {
                    rejectStaleInteraction(action)
                }
                val reader = lastReader
                if (
                    action.secret.kind != awaiting.kind ||
                    action.secret.isConsumed ||
                    reader == null ||
                    !secretRequestIsValid(awaiting.kind, reader)
                ) {
                    action.secret.close()
                    fail(GermanEidClientError.INVALID_SECRET)
                }
                val transferred = action.secret.transferredCopy()
                lastSubmittedSecret = action.interactionId
                state = State.Running
                GermanEidOutput(commands = listOf(GermanEidSdkCommand.SetSecret(transferred)))
            }
        }
    }

    @Synchronized
    override fun shutdown(sessionId: GermanEidSessionId): GermanEidOutput {
        if (sessionId != activeSessionId) {
            throw GermanEidFlowException(GermanEidClientError.STALE_SESSION, GermanEidOutput())
        }
        if (state == State.Terminal || state is State.Cancelling) return GermanEidOutput()
        clearHeldSecrets()
        return if (workflowMayBeLive()) {
            state = State.Cancelling(
                GermanEidFailureReason.SDK,
                startWasPending = state == State.AwaitingAuthStart,
            )
            GermanEidOutput(commands = listOf(GermanEidSdkCommand.Cancel))
        } else {
            state = State.Terminal
            GermanEidOutput()
        }
    }

    private fun receiveDuringRunning(event: GermanEidSdkEvent): GermanEidOutput = when (event) {
        is GermanEidSdkEvent.Reader -> receiveReader(event.value, scanDialogMayBeLive = true)
        GermanEidSdkEvent.CardRequired -> {
            lastReader = null
            GermanEidOutput(uiEvents = listOf(GermanEidUiEvent.CardRequired))
        }
        is GermanEidSdkEvent.SecretRequested -> {
            if (!secretRequestIsValid(event.kind, event.reader)) {
                failSecretRequest(event.reader)
            }
            lastReader = event.reader
            val interactionId = nextInteractionId()
            state = State.AwaitingSecret(event.kind, interactionId)
            GermanEidOutput(
                commands = listOf(GermanEidSdkCommand.InterruptSystemDialog),
                uiEvents = listOf(
                    GermanEidUiEvent.SecretRequested(
                        event.kind,
                        retryCounter(event.reader),
                        interactionId,
                    ),
                ),
            )
        }
        is GermanEidSdkEvent.Paused -> {
            val interactionId = nextInteractionId()
            state = State.Paused(interactionId)
            GermanEidOutput(
                uiEvents = listOf(GermanEidUiEvent.Paused(event.cause, interactionId)),
            )
        }
        else -> fail(GermanEidClientError.INVALID_TRANSITION)
    }

    private fun receiveWhileAwaitingSecret(
        current: State.AwaitingSecret,
        event: GermanEidSdkEvent,
    ): GermanEidOutput = when (event) {
        is GermanEidSdkEvent.Reader -> {
            val priorReader = lastReader
            val output = receiveReader(event.value, scanDialogMayBeLive = true)
            if (
                priorReader != event.value ||
                !secretRequestIsValid(current.kind, event.value)
            ) {
                state = State.Running
            }
            output
        }
        GermanEidSdkEvent.CardRequired -> {
            lastReader = null
            state = State.Running
            GermanEidOutput(uiEvents = listOf(GermanEidUiEvent.CardRequired))
        }
        is GermanEidSdkEvent.Paused -> {
            val interactionId = nextInteractionId()
            state = State.Paused(interactionId)
            GermanEidOutput(
                uiEvents = listOf(GermanEidUiEvent.Paused(event.cause, interactionId)),
            )
        }
        else -> fail(GermanEidClientError.INVALID_TRANSITION)
    }

    private fun receiveReader(
        reader: GermanEidReaderState,
        scanDialogMayBeLive: Boolean,
    ): GermanEidOutput {
        if (!readerIsWellFormed(reader)) fail(GermanEidClientError.INVALID_CARD_STATE)
        lastReader = reader
        val commands = if (
            scanDialogMayBeLive &&
            (reader.card as? GermanEidCardState.Present)?.deactivated == true
        ) {
            listOf(GermanEidSdkCommand.InterruptSystemDialog)
        } else {
            emptyList()
        }
        return GermanEidOutput(
            commands = commands,
            uiEvents = listOf(GermanEidUiEvent.Reader(reader)),
        )
    }

    private fun workflowConfirmed(): Boolean = when (state) {
        State.AwaitingInitialRights,
        is State.AwaitingMinimizedRights,
        is State.AwaitingCertificate,
        is State.AwaitingConsent,
        State.Running,
        is State.AwaitingSecret,
        is State.Paused,
        is State.Cancelling,
        -> true
        State.Idle,
        is State.AwaitingApiLevels,
        is State.AwaitingApiSelection,
        State.AwaitingAuthStart,
        State.Terminal,
        -> false
    }

    private fun successMayFinish(): Boolean = state == State.Running

    private fun workflowMayBeLive(): Boolean =
        state == State.AwaitingAuthStart || workflowConfirmed()

    private fun readerIsWellFormed(reader: GermanEidReaderState): Boolean {
        if (
            reader.kind == GermanEidReaderKind.TRUSTED_PLATFORM_INTEGRATED_NFC &&
            (reader.insertable || reader.keypad)
        ) {
            return false
        }
        if (!reader.attached) {
            return !reader.keypad && reader.card == GermanEidCardState.Absent
        }
        val retryCounter = (reader.card as? GermanEidCardState.Present)?.retryCounter
        return retryCounter == null || retryCounter in 0..3
    }

    private fun retryCounter(reader: GermanEidReaderState): Int? =
        (reader.card as? GermanEidCardState.Present)?.retryCounter

    private fun secretRequestIsValid(
        kind: GermanEidSecretKind,
        reader: GermanEidReaderState,
    ): Boolean {
        if (!readerIsWellFormed(reader) || !reader.isTrustedIntegratedNfc) return false
        val card = reader.card as? GermanEidCardState.Present ?: return false
        return when (kind) {
            GermanEidSecretKind.PIN ->
                !card.deactivated &&
                    !card.inoperative &&
                    card.retryCounter?.let { it in 1..3 } == true
            GermanEidSecretKind.CAN -> {
                val canAllowed = GermanEidAccessRight.CAN_ALLOWED in authorizedRights
                canAllowed ||
                    (!card.deactivated && !card.inoperative && card.retryCounter == 1)
            }
            GermanEidSecretKind.PUK ->
                !card.deactivated && !card.inoperative && card.retryCounter == 0
        }
    }

    private fun nextInteractionId(): GermanEidInteractionId {
        if (interactionCounter == Long.MAX_VALUE) fail(GermanEidClientError.ADAPTER_FAILURE)
        interactionCounter += 1
        return GermanEidInteractionId(interactionCounter)
    }

    private fun rejectStaleInteraction(action: GermanEidUserAction): Nothing {
        clearSecrets(action)
        throw GermanEidFlowException(GermanEidClientError.STALE_INTERACTION, GermanEidOutput())
    }

    private fun localFailureResult(
        reason: GermanEidFailureReason? = null,
    ): GermanEidAuthenticationResult {
        val contract = activeContract
            ?: throw GermanEidClientException(GermanEidClientError.INVALID_RESULT)
        val sessionId = activeSessionId
            ?: throw GermanEidClientException(GermanEidClientError.INVALID_RESULT)
        val effectiveReason = reason ?: (state as? State.Cancelling)?.reason
            ?: GermanEidFailureReason.SDK
        return GermanEidAuthenticationResult(
            GermanEidAuthenticationOutcome.Failure(effectiveReason),
            null,
            contract,
            sessionId,
        )
    }

    private fun fail(error: GermanEidClientError): Nothing {
        clearHeldSecrets()
        val recovery = when {
            state is State.Cancelling -> GermanEidOutput()
            workflowMayBeLive() -> {
                state = State.Cancelling(
                    GermanEidFailureReason.SDK,
                    startWasPending = state == State.AwaitingAuthStart,
                )
                GermanEidOutput(commands = listOf(GermanEidSdkCommand.Cancel))
            }
            else -> {
                state = State.Terminal
                GermanEidOutput()
            }
        }
        throw GermanEidFlowException(error, recovery)
    }

    private fun failSecretRequest(reader: GermanEidReaderState): Nothing {
        clearHeldSecrets()
        lastReader = reader
        val commands = mutableListOf<GermanEidSdkCommand>(
            GermanEidSdkCommand.InterruptSystemDialog,
        )
        if (workflowMayBeLive()) {
            state = State.Cancelling(
                GermanEidFailureReason.SDK,
                startWasPending = state == State.AwaitingAuthStart,
            )
            commands.add(GermanEidSdkCommand.Cancel)
        } else {
            state = State.Terminal
        }
        throw GermanEidFlowException(
            GermanEidClientError.INVALID_CARD_STATE,
            GermanEidOutput(
                commands = commands,
                uiEvents = listOf(GermanEidUiEvent.Reader(reader)),
            ),
        )
    }

    private fun clearHeldSecrets() {
        when (val current = state) {
            is State.AwaitingApiLevels -> current.request.close()
            is State.AwaitingApiSelection -> current.request.close()
            else -> Unit
        }
    }

    private fun terminalFailure(
        error: GermanEidClientError,
        reason: GermanEidFailureReason,
    ): Nothing {
        clearHeldSecrets()
        val completion = runCatching { localFailureResult(reason) }.getOrNull()
        state = State.Terminal
        val recovery = GermanEidOutput(
            uiEvents = completion?.let { listOf(GermanEidUiEvent.Completed(it)) } ?: emptyList(),
        )
        throw GermanEidFlowException(error, recovery)
    }

    private fun clearSecrets(event: GermanEidSdkEvent) {
        if (event is GermanEidSdkEvent.AuthenticationFinished) event.result.close()
    }

    private fun clearSecrets(action: GermanEidUserAction) {
        if (action is GermanEidUserAction.SubmitSecret) action.secret.close()
    }
}
