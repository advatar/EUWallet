package eu.advatar.wallet.shell

import java.io.ByteArrayOutputStream

/**
 * Authenticated, non-secret binding for one durable wallet-state namespace.
 *
 * The caller should include stable installation context such as the wallet profile and device-key
 * reference. The bytes are authenticated but are not treated as secret.
 */
class DurableStateContext(
    val schemaVersion: Int = CURRENT_SCHEMA_VERSION,
    binding: ByteArray,
) {
    private val authenticatedBinding = binding.copyOf()
    val binding: ByteArray
        get() = authenticatedBinding.copyOf()

    init {
        if (schemaVersion != CURRENT_SCHEMA_VERSION) {
            throw DurableStateStoreException.UnsupportedSchemaVersion(schemaVersion)
        }
        if (binding.isEmpty() || binding.size > MAXIMUM_BINDING_BYTES) {
            throw DurableStateStoreException.InvalidContextLength(binding.size)
        }
    }

    companion object {
        const val CURRENT_SCHEMA_VERSION = 1
        const val MAXIMUM_BINDING_BYTES = 4 * 1024
    }

    internal fun bindingForAuthentication(): ByteArray = authenticatedBinding.copyOf()
}

class DurableStateRecord(
    val generation: Long,
    plaintext: ByteArray,
) {
    private val checkpoint = plaintext.copyOf()
    val plaintext: ByteArray
        get() = checkpoint.copyOf()
}

sealed interface DurableStateLoadResult {
    data object Empty : DurableStateLoadResult

    class Record(val value: DurableStateRecord) : DurableStateLoadResult
}

/**
 * Narrow encrypted persistence boundary. Core serialization and lifecycle restoration are outside
 * this API; callers provide one canonical, already-bounded checkpoint.
 */
interface DurableStateStore {
    @Throws(DurableStateStoreException::class)
    fun load(context: DurableStateContext): DurableStateLoadResult

    @Throws(DurableStateStoreException::class)
    fun commit(
        expectedGeneration: Long,
        nextGeneration: Long,
        plaintext: ByteArray,
        context: DurableStateContext,
    ): DurableStateRecord
}

sealed class DurableStateStoreException(message: String, cause: Throwable? = null) :
    Exception(message, cause) {
    class InvalidApplicationIdentity :
        DurableStateStoreException("The Android application identity is absent or invalid")

    class InvalidContextLength(val actual: Int) :
        DurableStateStoreException("The durable-state context is $actual bytes")

    class UnsupportedSchemaVersion(val actual: Int) :
        DurableStateStoreException("Unsupported durable-state schema version $actual")

    class PlaintextTooLarge(val actual: Int, val maximum: Int) :
        DurableStateStoreException("Durable-state plaintext is $actual bytes; maximum is $maximum")

    class EnvelopeTooLarge(val actual: Long, val maximum: Int) :
        DurableStateStoreException("Durable-state envelope is $actual bytes; maximum is $maximum")

    class InvalidGenerationTransition(val expected: Long, val next: Long) :
        DurableStateStoreException("Invalid durable-state generation transition $expected -> $next")

    class GenerationConflict(val expected: Long, val actual: Long) :
        DurableStateStoreException("Durable-state CAS expected $expected, found $actual")

    class PhysicalDeviceRequired :
        DurableStateStoreException("Production durable state is unavailable on an emulator")

    class StrongBoxRequired(cause: Throwable? = null) :
        DurableStateStoreException(
            "StrongBox is unavailable and TEE use was not explicitly allowed",
            cause,
        )

    class MissingInstallationKey :
        DurableStateStoreException("Durable state exists but its AndroidKeyStore key is missing")

    class KeyAccessFailed(cause: Throwable) :
        DurableStateStoreException("Could not access the durable-state AndroidKeyStore key", cause)

    class KeyCreationFailed(cause: Throwable) :
        DurableStateStoreException("Could not create the durable-state AndroidKeyStore key", cause)

    class KeyPolicyViolation(val detail: String) :
        DurableStateStoreException("Durable-state key policy violation: $detail")

    class MissingAnchor :
        DurableStateStoreException("Durable slot state exists but its anchor is missing")

    class CorruptAnchor : DurableStateStoreException("The durable-state anchor is malformed")

    class UnsupportedAnchorVersion(val actual: Int) :
        DurableStateStoreException("Unsupported durable-state anchor version $actual")

    class UnsupportedEnvelopeVersion(val actual: Int) :
        DurableStateStoreException("Unsupported durable-state envelope version $actual")

    class SchemaMismatch(val expected: Int, val actual: Int) :
        DurableStateStoreException("Durable-state schema mismatch: $expected != $actual")

    class ApplicationIdentityMismatch :
        DurableStateStoreException("Durable state belongs to a different Android package")

    class ContextMismatch :
        DurableStateStoreException("Durable state belongs to a different caller context")

    class InvalidGenesisAnchor :
        DurableStateStoreException("The generation-zero durable-state anchor is invalid")

    class MissingAnchoredSlot(val slot: DurableStateSlot) :
        DurableStateStoreException("The anchored durable-state slot ${slot.name} is missing")

    class AnchorDigestMismatch :
        DurableStateStoreException("The anchored durable-state envelope digest does not match")

    class SlotMismatch(val expected: DurableStateSlot, val actual: DurableStateSlot) :
        DurableStateStoreException("Durable-state slot mismatch: $expected != $actual")

    class GenerationMismatch(val expected: Long, val actual: Long) :
        DurableStateStoreException("Durable-state generation mismatch: $expected != $actual")

    class CorruptEnvelope : DurableStateStoreException("The durable-state envelope is malformed")

    class AuthenticationFailed(cause: Throwable? = null) :
        DurableStateStoreException("Durable-state authentication failed", cause)

    class EncryptionFailed(cause: Throwable? = null) :
        DurableStateStoreException("Durable-state encryption failed", cause)

    class AnchorAlreadyExists :
        DurableStateStoreException("A durable-state anchor already exists")

    class StorageFailure(val operation: String, cause: Throwable? = null) :
        DurableStateStoreException("Durable-state storage failed during $operation", cause)

    class StoragePolicyViolation(val detail: String) :
        DurableStateStoreException("Durable-state file policy violation: $detail")

    class InterruptedWrite(val point: DurableStateFaultPoint) :
        DurableStateStoreException("Injected interruption at ${point.name}")
}

enum class DurableStateSlot(internal val encoded: Int) {
    A(0),
    B(1),
    ;

    val opposite: DurableStateSlot
        get() = if (this == A) B else A

    companion object {
        fun decode(value: Int): DurableStateSlot? = entries.firstOrNull { it.encoded == value }
    }
}

enum class DurableStateFaultPoint {
    AFTER_KEY_CREATION,
    BEFORE_GENESIS_ANCHOR,
    AFTER_GENESIS_ANCHOR,
    BEFORE_SLOT_TEMP_CREATE,
    AFTER_SLOT_TEMP_CREATE,
    AFTER_SLOT_TEMP_WRITE,
    AFTER_SLOT_TEMP_SYNC,
    AFTER_SLOT_RENAME,
    AFTER_SLOT_DIRECTORY_SYNC,
    BEFORE_ANCHOR_TEMP_CREATE,
    AFTER_ANCHOR_TEMP_CREATE,
    AFTER_ANCHOR_TEMP_WRITE,
    AFTER_ANCHOR_TEMP_SYNC,
    AFTER_ANCHOR_RENAME,
    AFTER_ANCHOR_DIRECTORY_SYNC,
}

internal fun interface DurableStateFaultInjector {
    fun hit(point: DurableStateFaultPoint)
}

internal data class DurableSealedPayload(
    val nonce: ByteArray,
    val ciphertext: ByteArray,
    val tag: ByteArray,
)

internal interface DurableStateCrypto {
    fun hasValidKey(): Boolean

    fun createKey()

    fun encrypt(plaintext: ByteArray, associatedData: ByteArray): DurableSealedPayload

    fun decrypt(payload: DurableSealedPayload, associatedData: ByteArray): ByteArray

    fun sha256(value: ByteArray): ByteArray
}

internal interface DurableStateFileSystem {
    fun acquireExclusiveLock()

    fun releaseExclusiveLock()

    fun cleanupTemporaryFiles()

    fun hasAnySlot(): Boolean

    fun readSlot(slot: DurableStateSlot, maximumBytes: Int): ByteArray?

    fun readAnchor(maximumBytes: Int): ByteArray?

    fun writeSlotDurably(
        slot: DurableStateSlot,
        value: ByteArray,
        faultInjector: DurableStateFaultInjector?,
    )

    fun writeAnchorDurably(
        value: ByteArray,
        createOnly: Boolean,
        faultInjector: DurableStateFaultInjector?,
    )
}

internal data class DurableAnchor(
    val schemaVersion: Int,
    val generation: Long,
    val slotEncoded: Int,
    val applicationDigest: ByteArray,
    val contextDigest: ByteArray,
    val envelopeDigest: ByteArray,
) {
    val slot: DurableStateSlot?
        get() = DurableStateSlot.decode(slotEncoded)

    companion object {
        const val GENESIS_SLOT = 0xff

        fun genesis(schemaVersion: Int, applicationDigest: ByteArray, contextDigest: ByteArray) =
            DurableAnchor(
                schemaVersion = schemaVersion,
                generation = 0,
                slotEncoded = GENESIS_SLOT,
                applicationDigest = applicationDigest.copyOf(),
                contextDigest = contextDigest.copyOf(),
                envelopeDigest = ByteArray(DIGEST_BYTES),
            )
    }
}

internal data class DurableEnvelopeHeader(
    val schemaVersion: Int,
    val generation: Long,
    val slotEncoded: Int,
    val applicationDigest: ByteArray,
    val contextDigest: ByteArray,
)

internal data class DecodedDurableEnvelope(
    val header: DurableEnvelopeHeader,
    val sealed: DurableSealedPayload,
)

internal object DurableStateLimits {
    const val MAXIMUM_ENVELOPE_BYTES = 32 * 1024 * 1024
    const val MAXIMUM_APPLICATION_IDENTITY_BYTES = 512
    const val MAXIMUM_PLAINTEXT_BYTES =
        MAXIMUM_ENVELOPE_BYTES - DurableSlotEnvelopeCodec.FIXED_OVERHEAD
    const val MAXIMUM_ANCHOR_BYTES = 1024
}

internal object DurableAnchorPlaintextCodec {
    const val FORMAT_VERSION = 1
    const val ENCODED_BYTES = 8 + 2 + 4 + 8 + 1 + DIGEST_BYTES * 3
    private val MAGIC = "EUWANCHR".encodeToByteArray()

    fun encode(anchor: DurableAnchor): ByteArray = StrictByteWriter().apply {
        bytes(MAGIC)
        u16(FORMAT_VERSION)
        u32(anchor.schemaVersion)
        u64(anchor.generation)
        u8(anchor.slotEncoded)
        fixed(anchor.applicationDigest, DIGEST_BYTES)
        fixed(anchor.contextDigest, DIGEST_BYTES)
        fixed(anchor.envelopeDigest, DIGEST_BYTES)
    }.toByteArray()

    fun decode(value: ByteArray): DurableAnchor {
        if (value.size != ENCODED_BYTES) throw DurableStateStoreException.CorruptAnchor()
        val reader = StrictByteReader(value, anchor = true)
        if (!reader.bytes(MAGIC.size).contentEquals(MAGIC)) {
            throw DurableStateStoreException.CorruptAnchor()
        }
        val version = reader.u16()
        if (version != FORMAT_VERSION) {
            throw DurableStateStoreException.UnsupportedAnchorVersion(version)
        }
        val schema = reader.u32AsInt()
        val generation = reader.u64()
        val slot = reader.u8()
        val app = reader.bytes(DIGEST_BYTES)
        val context = reader.bytes(DIGEST_BYTES)
        val envelope = reader.bytes(DIGEST_BYTES)
        if (!reader.atEnd() || slot != DurableAnchor.GENESIS_SLOT && DurableStateSlot.decode(slot) == null) {
            throw DurableStateStoreException.CorruptAnchor()
        }
        return DurableAnchor(schema, generation, slot, app, context, envelope)
    }
}

internal object DurableAnchorEnvelopeCodec {
    const val FORMAT_VERSION = 1
    private const val NONCE_BYTES = 12
    private const val TAG_BYTES = 16
    private const val CIPHERTEXT_BYTES = DurableAnchorPlaintextCodec.ENCODED_BYTES
    const val ENCODED_BYTES =
        8 + 2 + 4 + 8 + 1 + 1 + 2 + DIGEST_BYTES * 2 + NONCE_BYTES + CIPHERTEXT_BYTES + TAG_BYTES
    private val MAGIC = "EUWANCRY".encodeToByteArray()

    fun encode(header: DurableEnvelopeHeader, sealed: DurableSealedPayload): ByteArray {
        if (
            sealed.nonce.size != NONCE_BYTES ||
            sealed.ciphertext.size != CIPHERTEXT_BYTES ||
            sealed.tag.size != TAG_BYTES
        ) {
            throw DurableStateStoreException.EncryptionFailed()
        }
        return StrictByteWriter().apply {
            bytes(MAGIC)
            u16(FORMAT_VERSION)
            u32(header.schemaVersion)
            u64(header.generation)
            u8(header.slotEncoded)
            u8(NONCE_BYTES)
            u16(CIPHERTEXT_BYTES)
            fixed(header.applicationDigest, DIGEST_BYTES)
            fixed(header.contextDigest, DIGEST_BYTES)
            bytes(sealed.nonce)
            bytes(sealed.ciphertext)
            bytes(sealed.tag)
        }.toByteArray()
    }

    fun decode(value: ByteArray): DecodedDurableEnvelope {
        if (value.size != ENCODED_BYTES) throw DurableStateStoreException.CorruptAnchor()
        val reader = StrictByteReader(value, anchor = true)
        if (!reader.bytes(MAGIC.size).contentEquals(MAGIC)) {
            throw DurableStateStoreException.CorruptAnchor()
        }
        val version = reader.u16()
        if (version != FORMAT_VERSION) {
            throw DurableStateStoreException.UnsupportedAnchorVersion(version)
        }
        val header = DurableEnvelopeHeader(
            schemaVersion = reader.u32AsInt(),
            generation = reader.u64(),
            slotEncoded = reader.u8(),
            applicationDigest = ByteArray(0),
            contextDigest = ByteArray(0),
        )
        if (reader.u8() != NONCE_BYTES || reader.u16() != CIPHERTEXT_BYTES) {
            throw DurableStateStoreException.CorruptAnchor()
        }
        val completeHeader = header.copy(
            applicationDigest = reader.bytes(DIGEST_BYTES),
            contextDigest = reader.bytes(DIGEST_BYTES),
        )
        val sealed = DurableSealedPayload(
            nonce = reader.bytes(NONCE_BYTES),
            ciphertext = reader.bytes(CIPHERTEXT_BYTES),
            tag = reader.bytes(TAG_BYTES),
        )
        if (!reader.atEnd()) throw DurableStateStoreException.CorruptAnchor()
        return DecodedDurableEnvelope(completeHeader, sealed)
    }
}

internal object DurableSlotEnvelopeCodec {
    const val FORMAT_VERSION = 1
    private const val NONCE_BYTES = 12
    private const val TAG_BYTES = 16
    const val FIXED_OVERHEAD =
        8 + 2 + 4 + 8 + 1 + 1 + 4 + DIGEST_BYTES * 2 + NONCE_BYTES + TAG_BYTES
    private val MAGIC = "EUWSTATE".encodeToByteArray()

    fun encode(header: DurableEnvelopeHeader, sealed: DurableSealedPayload): ByteArray {
        if (
            sealed.nonce.size != NONCE_BYTES ||
            sealed.tag.size != TAG_BYTES ||
            sealed.ciphertext.size > DurableStateLimits.MAXIMUM_PLAINTEXT_BYTES
        ) {
            throw DurableStateStoreException.EncryptionFailed()
        }
        val total = FIXED_OVERHEAD.toLong() + sealed.ciphertext.size.toLong()
        if (total > DurableStateLimits.MAXIMUM_ENVELOPE_BYTES) {
            throw DurableStateStoreException.EnvelopeTooLarge(
                total,
                DurableStateLimits.MAXIMUM_ENVELOPE_BYTES,
            )
        }
        return StrictByteWriter().apply {
            bytes(MAGIC)
            u16(FORMAT_VERSION)
            u32(header.schemaVersion)
            u64(header.generation)
            u8(header.slotEncoded)
            u8(NONCE_BYTES)
            u32(sealed.ciphertext.size)
            fixed(header.applicationDigest, DIGEST_BYTES)
            fixed(header.contextDigest, DIGEST_BYTES)
            bytes(sealed.nonce)
            bytes(sealed.ciphertext)
            bytes(sealed.tag)
        }.toByteArray()
    }

    fun decode(value: ByteArray): DecodedDurableEnvelope {
        if (value.size > DurableStateLimits.MAXIMUM_ENVELOPE_BYTES) {
            throw DurableStateStoreException.EnvelopeTooLarge(
                value.size.toLong(),
                DurableStateLimits.MAXIMUM_ENVELOPE_BYTES,
            )
        }
        if (value.size < FIXED_OVERHEAD) throw DurableStateStoreException.CorruptEnvelope()
        val reader = StrictByteReader(value, anchor = false)
        if (!reader.bytes(MAGIC.size).contentEquals(MAGIC)) {
            throw DurableStateStoreException.CorruptEnvelope()
        }
        val version = reader.u16()
        if (version != FORMAT_VERSION) {
            throw DurableStateStoreException.UnsupportedEnvelopeVersion(version)
        }
        val header = DurableEnvelopeHeader(
            schemaVersion = reader.u32AsInt(),
            generation = reader.u64(),
            slotEncoded = reader.u8(),
            applicationDigest = ByteArray(0),
            contextDigest = ByteArray(0),
        )
        if (reader.u8() != NONCE_BYTES) throw DurableStateStoreException.CorruptEnvelope()
        val ciphertextLength = reader.u32AsInt()
        if (ciphertextLength > DurableStateLimits.MAXIMUM_PLAINTEXT_BYTES) {
            throw DurableStateStoreException.EnvelopeTooLarge(
                ciphertextLength.toLong() + FIXED_OVERHEAD,
                DurableStateLimits.MAXIMUM_ENVELOPE_BYTES,
            )
        }
        val expectedRemaining = DIGEST_BYTES * 2L + NONCE_BYTES + ciphertextLength.toLong() + TAG_BYTES
        if (expectedRemaining != reader.remaining().toLong()) {
            throw DurableStateStoreException.CorruptEnvelope()
        }
        val completeHeader = header.copy(
            applicationDigest = reader.bytes(DIGEST_BYTES),
            contextDigest = reader.bytes(DIGEST_BYTES),
        )
        val sealed = DurableSealedPayload(
            nonce = reader.bytes(NONCE_BYTES),
            ciphertext = reader.bytes(ciphertextLength),
            tag = reader.bytes(TAG_BYTES),
        )
        if (!reader.atEnd()) throw DurableStateStoreException.CorruptEnvelope()
        return DecodedDurableEnvelope(completeHeader, sealed)
    }
}

internal object DurableAssociatedDataCodec {
    private val MAGIC = "EUWAD001".encodeToByteArray()
    private const val SLOT_DOMAIN = 1
    private const val ANCHOR_DOMAIN = 2

    fun slot(
        applicationIdentity: ByteArray,
        context: DurableStateContext,
        generation: Long,
        slot: DurableStateSlot,
    ): ByteArray = encode(
        domain = SLOT_DOMAIN,
        applicationIdentity = applicationIdentity,
        context = context,
        generation = generation,
        slotEncoded = slot.encoded,
    )

    fun anchor(
        applicationIdentity: ByteArray,
        context: DurableStateContext,
        generation: Long,
        slotEncoded: Int,
    ): ByteArray = encode(
        domain = ANCHOR_DOMAIN,
        applicationIdentity = applicationIdentity,
        context = context,
        generation = generation,
        slotEncoded = slotEncoded,
    )

    private fun encode(
        domain: Int,
        applicationIdentity: ByteArray,
        context: DurableStateContext,
        generation: Long,
        slotEncoded: Int,
    ): ByteArray = StrictByteWriter().apply {
        bytes(MAGIC)
        u8(domain)
        u32(context.schemaVersion)
        u64(generation)
        u8(slotEncoded)
        u16(applicationIdentity.size)
        bytes(applicationIdentity)
        u16(context.bindingForAuthentication().size)
        bytes(context.bindingForAuthentication())
    }.toByteArray()
}

internal class DurableStateCoordinator(
    applicationIdentity: String,
    private val crypto: DurableStateCrypto,
    private val fileSystem: DurableStateFileSystem,
    private val faultInjector: DurableStateFaultInjector? = null,
    private val processLock: Any = GLOBAL_PROCESS_LOCK,
) : DurableStateStore {
    private val applicationIdentity = applicationIdentity.encodeToByteArray()

    init {
        if (
            this.applicationIdentity.isEmpty() ||
            this.applicationIdentity.size > DurableStateLimits.MAXIMUM_APPLICATION_IDENTITY_BYTES ||
            this.applicationIdentity.any { it == 0.toByte() }
        ) {
            throw DurableStateStoreException.InvalidApplicationIdentity()
        }
    }

    override fun load(context: DurableStateContext): DurableStateLoadResult = withLock {
        fileSystem.cleanupTemporaryFiles()
        val anchor = loadOrCreateAnchor(context)
        loadFromAnchor(anchor, context)
    }

    override fun commit(
        expectedGeneration: Long,
        nextGeneration: Long,
        plaintext: ByteArray,
        context: DurableStateContext,
    ): DurableStateRecord = withLock {
        validateTransition(expectedGeneration, nextGeneration)
        if (plaintext.size > DurableStateLimits.MAXIMUM_PLAINTEXT_BYTES) {
            throw DurableStateStoreException.PlaintextTooLarge(
                plaintext.size,
                DurableStateLimits.MAXIMUM_PLAINTEXT_BYTES,
            )
        }
        fileSystem.cleanupTemporaryFiles()
        val currentAnchor = loadOrCreateAnchor(context)
        if (currentAnchor.generation != expectedGeneration) {
            throw DurableStateStoreException.GenerationConflict(
                expectedGeneration,
                currentAnchor.generation,
            )
        }

        val nextSlot = currentAnchor.slot?.opposite ?: DurableStateSlot.A
        val header = expectedHeader(context, nextGeneration, nextSlot.encoded)
        val associatedData = DurableAssociatedDataCodec.slot(
            applicationIdentity,
            context,
            nextGeneration,
            nextSlot,
        )
        val envelope = DurableSlotEnvelopeCodec.encode(
            header,
            crypto.encrypt(plaintext.copyOf(), associatedData),
        )
        fileSystem.writeSlotDurably(nextSlot, envelope, faultInjector)

        val nextAnchor = DurableAnchor(
            schemaVersion = context.schemaVersion,
            generation = nextGeneration,
            slotEncoded = nextSlot.encoded,
            applicationDigest = header.applicationDigest,
            contextDigest = header.contextDigest,
            envelopeDigest = crypto.sha256(envelope),
        )
        val encodedAnchor = sealAnchor(nextAnchor, context)
        fileSystem.writeAnchorDurably(encodedAnchor, createOnly = false, faultInjector)
        DurableStateRecord(nextGeneration, plaintext)
    }

    private fun loadOrCreateAnchor(context: DurableStateContext): DurableAnchor {
        val encodedAnchor = fileSystem.readAnchor(DurableStateLimits.MAXIMUM_ANCHOR_BYTES)
        // Once an anchor exists, only its named slot is read. The other slot is deliberately not
        // consulted as a recovery candidate.
        val hasSlot = encodedAnchor == null && fileSystem.hasAnySlot()
        val hasKey = crypto.hasValidKey()
        if (!hasKey) {
            if (encodedAnchor != null || hasSlot) {
                throw DurableStateStoreException.MissingInstallationKey()
            }
            crypto.createKey()
            faultInjector?.hit(DurableStateFaultPoint.AFTER_KEY_CREATION)
        }

        if (encodedAnchor == null) {
            if (hasSlot) throw DurableStateStoreException.MissingAnchor()
            faultInjector?.hit(DurableStateFaultPoint.BEFORE_GENESIS_ANCHOR)
            val header = expectedHeader(context, generation = 0, DurableAnchor.GENESIS_SLOT)
            val genesis = DurableAnchor.genesis(
                context.schemaVersion,
                header.applicationDigest,
                header.contextDigest,
            )
            fileSystem.writeAnchorDurably(
                sealAnchor(genesis, context),
                createOnly = true,
                faultInjector,
            )
            faultInjector?.hit(DurableStateFaultPoint.AFTER_GENESIS_ANCHOR)
            return genesis
        }
        return openAnchor(encodedAnchor, context)
    }

    private fun loadFromAnchor(
        anchor: DurableAnchor,
        context: DurableStateContext,
    ): DurableStateLoadResult {
        validateAnchor(anchor, context)
        if (anchor.generation == 0L) return DurableStateLoadResult.Empty
        val slot = anchor.slot ?: throw DurableStateStoreException.CorruptAnchor()
        val encodedEnvelope = fileSystem.readSlot(
            slot,
            DurableStateLimits.MAXIMUM_ENVELOPE_BYTES,
        ) ?: throw DurableStateStoreException.MissingAnchoredSlot(slot)
        if (!constantTimeEquals(crypto.sha256(encodedEnvelope), anchor.envelopeDigest)) {
            throw DurableStateStoreException.AnchorDigestMismatch()
        }
        val decoded = DurableSlotEnvelopeCodec.decode(encodedEnvelope)
        validateHeader(decoded.header, context, anchor.generation, slot.encoded, anchor = false)
        val plaintext = crypto.decrypt(
            decoded.sealed,
            DurableAssociatedDataCodec.slot(
                applicationIdentity,
                context,
                anchor.generation,
                slot,
            ),
        )
        if (plaintext.size > DurableStateLimits.MAXIMUM_PLAINTEXT_BYTES) {
            throw DurableStateStoreException.CorruptEnvelope()
        }
        return DurableStateLoadResult.Record(DurableStateRecord(anchor.generation, plaintext))
    }

    private fun sealAnchor(anchor: DurableAnchor, context: DurableStateContext): ByteArray {
        val header = DurableEnvelopeHeader(
            schemaVersion = anchor.schemaVersion,
            generation = anchor.generation,
            slotEncoded = anchor.slotEncoded,
            applicationDigest = anchor.applicationDigest,
            contextDigest = anchor.contextDigest,
        )
        val associatedData = DurableAssociatedDataCodec.anchor(
            applicationIdentity,
            context,
            anchor.generation,
            anchor.slotEncoded,
        )
        return DurableAnchorEnvelopeCodec.encode(
            header,
            crypto.encrypt(DurableAnchorPlaintextCodec.encode(anchor), associatedData),
        )
    }

    private fun openAnchor(encoded: ByteArray, context: DurableStateContext): DurableAnchor {
        if (encoded.size > DurableStateLimits.MAXIMUM_ANCHOR_BYTES) {
            throw DurableStateStoreException.EnvelopeTooLarge(
                encoded.size.toLong(),
                DurableStateLimits.MAXIMUM_ANCHOR_BYTES,
            )
        }
        val decoded = DurableAnchorEnvelopeCodec.decode(encoded)
        validateHeader(
            decoded.header,
            context,
            decoded.header.generation,
            decoded.header.slotEncoded,
            anchor = true,
        )
        val plaintext = crypto.decrypt(
            decoded.sealed,
            DurableAssociatedDataCodec.anchor(
                applicationIdentity,
                context,
                decoded.header.generation,
                decoded.header.slotEncoded,
            ),
        )
        val anchor = DurableAnchorPlaintextCodec.decode(plaintext)
        if (
            anchor.schemaVersion != decoded.header.schemaVersion ||
            anchor.generation != decoded.header.generation ||
            anchor.slotEncoded != decoded.header.slotEncoded ||
            !constantTimeEquals(anchor.applicationDigest, decoded.header.applicationDigest) ||
            !constantTimeEquals(anchor.contextDigest, decoded.header.contextDigest)
        ) {
            throw DurableStateStoreException.CorruptAnchor()
        }
        validateAnchor(anchor, context)
        return anchor
    }

    private fun validateAnchor(anchor: DurableAnchor, context: DurableStateContext) {
        validateHeader(
            DurableEnvelopeHeader(
                anchor.schemaVersion,
                anchor.generation,
                anchor.slotEncoded,
                anchor.applicationDigest,
                anchor.contextDigest,
            ),
            context,
            anchor.generation,
            anchor.slotEncoded,
            anchor = true,
        )
        val digestIsZero = anchor.envelopeDigest.all { it == 0.toByte() }
        if (
            anchor.generation == 0L &&
            (anchor.slotEncoded != DurableAnchor.GENESIS_SLOT || !digestIsZero)
        ) {
            throw DurableStateStoreException.InvalidGenesisAnchor()
        }
        if (
            anchor.generation < 0L ||
            anchor.generation > 0L &&
            (anchor.slot == null || digestIsZero)
        ) {
            throw DurableStateStoreException.CorruptAnchor()
        }
    }

    private fun validateHeader(
        header: DurableEnvelopeHeader,
        context: DurableStateContext,
        generation: Long,
        slotEncoded: Int,
        anchor: Boolean,
    ) {
        if (header.schemaVersion != context.schemaVersion) {
            throw DurableStateStoreException.SchemaMismatch(
                context.schemaVersion,
                header.schemaVersion,
            )
        }
        if (!constantTimeEquals(header.applicationDigest, crypto.sha256(applicationIdentity))) {
            throw DurableStateStoreException.ApplicationIdentityMismatch()
        }
        if (
            !constantTimeEquals(
                header.contextDigest,
                crypto.sha256(context.bindingForAuthentication()),
            )
        ) {
            throw DurableStateStoreException.ContextMismatch()
        }
        if (header.generation != generation) {
            throw DurableStateStoreException.GenerationMismatch(generation, header.generation)
        }
        if (header.slotEncoded != slotEncoded) {
            val expected = DurableStateSlot.decode(slotEncoded)
            val actual = DurableStateSlot.decode(header.slotEncoded)
            if (!anchor && expected != null && actual != null) {
                throw DurableStateStoreException.SlotMismatch(expected, actual)
            }
            throw DurableStateStoreException.CorruptAnchor()
        }
        if (!anchor && (generation <= 0 || DurableStateSlot.decode(slotEncoded) == null)) {
            throw DurableStateStoreException.CorruptEnvelope()
        }
    }

    private fun expectedHeader(
        context: DurableStateContext,
        generation: Long,
        slotEncoded: Int,
    ) = DurableEnvelopeHeader(
        schemaVersion = context.schemaVersion,
        generation = generation,
        slotEncoded = slotEncoded,
        applicationDigest = crypto.sha256(applicationIdentity),
        contextDigest = crypto.sha256(context.bindingForAuthentication()),
    )

    private fun validateTransition(expected: Long, next: Long) {
        val expectedNext = if (expected >= 0 && expected < Long.MAX_VALUE) expected + 1 else -1
        if (expectedNext <= 0 || next != expectedNext) {
            throw DurableStateStoreException.InvalidGenerationTransition(expected, next)
        }
    }

    private fun <T> withLock(block: () -> T): T = synchronized(processLock) {
        var acquired = false
        try {
            fileSystem.acquireExclusiveLock()
            acquired = true
            block()
        } finally {
            if (acquired) fileSystem.releaseExclusiveLock()
        }
    }

    private companion object {
        val GLOBAL_PROCESS_LOCK = Any()
    }
}

private class StrictByteWriter {
    private val output = ByteArrayOutputStream()

    fun u8(value: Int) {
        if (value !in 0..0xff) throw DurableStateStoreException.EncryptionFailed()
        output.write(value)
    }

    fun u16(value: Int) {
        if (value !in 0..0xffff) throw DurableStateStoreException.EncryptionFailed()
        output.write(value ushr 8)
        output.write(value)
    }

    fun u32(value: Int) {
        if (value < 0) throw DurableStateStoreException.EncryptionFailed()
        repeat(Int.SIZE_BYTES) { shiftIndex ->
            output.write(value ushr ((Int.SIZE_BYTES - shiftIndex - 1) * Byte.SIZE_BITS))
        }
    }

    fun u64(value: Long) {
        if (value < 0) throw DurableStateStoreException.EncryptionFailed()
        repeat(Long.SIZE_BYTES) { shiftIndex ->
            output.write((value ushr ((Long.SIZE_BYTES - shiftIndex - 1) * Byte.SIZE_BITS)).toInt())
        }
    }

    fun bytes(value: ByteArray) {
        output.write(value)
    }

    fun fixed(value: ByteArray, expected: Int) {
        if (value.size != expected) throw DurableStateStoreException.EncryptionFailed()
        bytes(value)
    }

    fun toByteArray(): ByteArray = output.toByteArray()
}

private class StrictByteReader(
    private val value: ByteArray,
    private val anchor: Boolean,
) {
    private var offset = 0

    fun u8(): Int = bytes(1)[0].toInt() and 0xff

    fun u16(): Int {
        val bytes = bytes(2)
        return (bytes[0].toInt() and 0xff shl 8) or (bytes[1].toInt() and 0xff)
    }

    fun u32AsInt(): Int {
        val bytes = bytes(Int.SIZE_BYTES)
        var result = 0L
        for (byte in bytes) result = result shl Byte.SIZE_BITS or (byte.toLong() and 0xff)
        if (result > Int.MAX_VALUE) corrupt()
        return result.toInt()
    }

    fun u64(): Long {
        val bytes = bytes(Long.SIZE_BYTES)
        var result = 0L
        for (byte in bytes) {
            if (result > (Long.MAX_VALUE ushr Byte.SIZE_BITS)) corrupt()
            result = result shl Byte.SIZE_BITS or (byte.toLong() and 0xff)
        }
        return result
    }

    fun bytes(count: Int): ByteArray {
        if (count < 0 || count > remaining()) corrupt()
        val result = value.copyOfRange(offset, offset + count)
        offset += count
        return result
    }

    fun remaining(): Int = value.size - offset

    fun atEnd(): Boolean = offset == value.size

    private fun corrupt(): Nothing {
        if (anchor) throw DurableStateStoreException.CorruptAnchor()
        throw DurableStateStoreException.CorruptEnvelope()
    }
}

internal fun constantTimeEquals(left: ByteArray, right: ByteArray): Boolean {
    var difference = left.size xor right.size
    val count = maxOf(left.size, right.size)
    for (index in 0 until count) {
        val leftByte = if (index < left.size) left[index].toInt() else 0
        val rightByte = if (index < right.size) right[index].toInt() else 0
        difference = difference or (leftByte xor rightByte)
    }
    return difference == 0
}

internal const val DIGEST_BYTES = 32
