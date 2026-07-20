package eu.advatar.wallet.shell

import android.security.keystore.KeyProperties
import java.nio.ByteBuffer
import java.security.MessageDigest
import java.util.Date
import java.util.concurrent.CountDownLatch
import java.util.concurrent.Executors
import javax.crypto.Cipher
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.SecretKeySpec
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertTrue
import org.junit.Assert.fail
import org.junit.Test

class DurableStateStoreTest {
    private val context = DurableStateContext(binding = "profile-1|device-key-7".encodeToByteArray())

    @Test
    fun firstLoadCreatesCanonicalGenesisAndReturnsEmpty() {
        val fixture = Fixture()

        assertTrue(fixture.coordinator.load(context) === DurableStateLoadResult.Empty)
        assertTrue(fixture.crypto.hasValidKey())
        assertNotNull(fixture.fileSystem.anchor)
        assertTrue(fixture.fileSystem.slots.isEmpty())
        assertEquals(1, fixture.fileSystem.acquireCount)
        assertEquals(1, fixture.fileSystem.releaseCount)
    }

    @Test
    fun commitLoadAndSlotRotationUseStrictSequentialCas() {
        val fixture = Fixture()
        fixture.coordinator.load(context)
        val first = fixture.coordinator.commit(0, 1, bytes("first"), context)
        assertEquals(1, first.generation)
        assertArrayEquals(bytes("first"), first.plaintext)
        assertEquals(setOf(DurableStateSlot.A), fixture.fileSystem.slots.keys)

        assertRecord(fixture.coordinator.load(context), 1, bytes("first"))
        fixture.coordinator.commit(1, 2, bytes("second"), context)
        assertEquals(setOf(DurableStateSlot.A, DurableStateSlot.B), fixture.fileSystem.slots.keys)
        assertRecord(fixture.coordinator.load(context), 2, bytes("second"))

        fixture.coordinator.commit(2, 3, bytes("third"), context)
        assertRecord(fixture.coordinator.load(context), 3, bytes("third"))
    }

    @Test
    fun staleCasAndInvalidGenerationTransitionsFailBeforeWriting() {
        val fixture = Fixture()
        fixture.coordinator.commit(0, 1, bytes("first"), context)
        val slotSnapshot = fixture.fileSystem.copySlots()
        expect<DurableStateStoreException.GenerationConflict> {
            fixture.coordinator.commit(0, 1, bytes("stale"), context)
        }
        assertSlotMapsEqual(slotSnapshot, fixture.fileSystem.slots)

        val invalid = listOf(
            -1L to 0L,
            0L to 0L,
            0L to 2L,
            1L to 1L,
            Long.MAX_VALUE to Long.MAX_VALUE,
        )
        for ((expected, next) in invalid) {
            expect<DurableStateStoreException.InvalidGenerationTransition> {
                fixture.coordinator.commit(expected, next, bytes("bad"), context)
            }
        }
    }

    @Test
    fun recordAndContextDefensivelyCopyCallerBytes() {
        val binding = bytes("binding")
        val copiedContext = DurableStateContext(binding = binding)
        binding[0] = 0
        assertArrayEquals(bytes("binding"), copiedContext.binding)
        copiedContext.binding[0] = 0
        assertArrayEquals(bytes("binding"), copiedContext.binding)

        val plaintext = bytes("checkpoint")
        val fixture = Fixture()
        val record = fixture.coordinator.commit(0, 1, plaintext, copiedContext)
        plaintext[0] = 0
        assertArrayEquals(bytes("checkpoint"), record.plaintext)
        record.plaintext[0] = 0
        assertArrayEquals(bytes("checkpoint"), record.plaintext)
    }

    @Test
    fun contextAndApplicationIdentityAreAuthenticated() {
        val fixture = Fixture()
        fixture.coordinator.commit(0, 1, bytes("secret"), context)

        expect<DurableStateStoreException.ContextMismatch> {
            fixture.coordinator.load(DurableStateContext(binding = bytes("other")))
        }
        expect<DurableStateStoreException.ApplicationIdentityMismatch> {
            fixture.newCoordinator(applicationIdentity = "eu.advatar.other").load(context)
        }
    }

    @Test
    fun invalidContextSchemaAndApplicationIdentityAreRejected() {
        expect<DurableStateStoreException.InvalidContextLength> {
            DurableStateContext(binding = ByteArray(0))
        }
        expect<DurableStateStoreException.InvalidContextLength> {
            DurableStateContext(binding = ByteArray(DurableStateContext.MAXIMUM_BINDING_BYTES + 1))
        }
        expect<DurableStateStoreException.UnsupportedSchemaVersion> {
            DurableStateContext(schemaVersion = 2, binding = bytes("x"))
        }
        val fixture = Fixture()
        expect<DurableStateStoreException.InvalidApplicationIdentity> {
            fixture.newCoordinator(applicationIdentity = "")
        }
        expect<DurableStateStoreException.InvalidApplicationIdentity> {
            fixture.newCoordinator(applicationIdentity = "a".repeat(513))
        }
        expect<DurableStateStoreException.InvalidApplicationIdentity> {
            fixture.newCoordinator(applicationIdentity = "bad\u0000package")
        }
    }

    @Test
    fun exactMaximumEnvelopeIsAcceptedAndOneByteMoreIsRejected() {
        val fixture = Fixture()
        val exact = ByteArray(DurableStateLimits.MAXIMUM_PLAINTEXT_BYTES) { 0x5a }
        fixture.coordinator.commit(0, 1, exact, context)
        assertEquals(
            DurableStateLimits.MAXIMUM_ENVELOPE_BYTES,
            fixture.fileSystem.slots.getValue(DurableStateSlot.A).size,
        )
        assertRecord(fixture.coordinator.load(context), 1, exact)

        expect<DurableStateStoreException.PlaintextTooLarge> {
            fixture.coordinator.commit(1, 2, ByteArray(exact.size + 1), context)
        }
    }

    @Test
    fun allFirstInitializationFaultsRecoverOnlyCanonicalEmptyState() {
        val points = listOf(
            DurableStateFaultPoint.AFTER_KEY_CREATION,
            DurableStateFaultPoint.BEFORE_GENESIS_ANCHOR,
            DurableStateFaultPoint.BEFORE_ANCHOR_TEMP_CREATE,
            DurableStateFaultPoint.AFTER_ANCHOR_TEMP_CREATE,
            DurableStateFaultPoint.AFTER_ANCHOR_TEMP_WRITE,
            DurableStateFaultPoint.AFTER_ANCHOR_TEMP_SYNC,
            DurableStateFaultPoint.AFTER_ANCHOR_RENAME,
            DurableStateFaultPoint.AFTER_ANCHOR_DIRECTORY_SYNC,
            DurableStateFaultPoint.AFTER_GENESIS_ANCHOR,
        )
        for (point in points) {
            val fixture = Fixture(faultPoint = point)
            expect<DurableStateStoreException.InterruptedWrite> {
                fixture.coordinator.load(context)
            }
            val recovered = fixture.newCoordinator()
            assertTrue("recovery after $point", recovered.load(context) === DurableStateLoadResult.Empty)
            assertTrue(fixture.fileSystem.temporaryFiles.isEmpty())
        }
    }

    @Test
    fun everySlotWriteFaultLeavesPreviousGenerationAuthoritative() {
        val points = listOf(
            DurableStateFaultPoint.BEFORE_SLOT_TEMP_CREATE,
            DurableStateFaultPoint.AFTER_SLOT_TEMP_CREATE,
            DurableStateFaultPoint.AFTER_SLOT_TEMP_WRITE,
            DurableStateFaultPoint.AFTER_SLOT_TEMP_SYNC,
            DurableStateFaultPoint.AFTER_SLOT_RENAME,
            DurableStateFaultPoint.AFTER_SLOT_DIRECTORY_SYNC,
        )
        for (point in points) {
            val fixture = committedFixture()
            val interrupted = fixture.newCoordinator(faultPoint = point)
            expect<DurableStateStoreException.InterruptedWrite> {
                interrupted.commit(1, 2, bytes("second"), context)
            }
            assertRecord(fixture.newCoordinator().load(context), 1, bytes("first"))
            assertTrue(fixture.fileSystem.temporaryFiles.isEmpty())
        }
    }

    @Test
    fun anchorFaultsHaveDeterministicPreOrPostCommitRecovery() {
        val preCommit = listOf(
            DurableStateFaultPoint.BEFORE_ANCHOR_TEMP_CREATE,
            DurableStateFaultPoint.AFTER_ANCHOR_TEMP_CREATE,
            DurableStateFaultPoint.AFTER_ANCHOR_TEMP_WRITE,
            DurableStateFaultPoint.AFTER_ANCHOR_TEMP_SYNC,
        )
        for (point in preCommit) {
            val fixture = committedFixture()
            expect<DurableStateStoreException.InterruptedWrite> {
                fixture.newCoordinator(faultPoint = point)
                    .commit(1, 2, bytes("second"), context)
            }
            assertRecord(fixture.newCoordinator().load(context), 1, bytes("first"))
        }

        val postCommit = listOf(
            DurableStateFaultPoint.AFTER_ANCHOR_RENAME,
            DurableStateFaultPoint.AFTER_ANCHOR_DIRECTORY_SYNC,
        )
        for (point in postCommit) {
            val fixture = committedFixture()
            expect<DurableStateStoreException.InterruptedWrite> {
                fixture.newCoordinator(faultPoint = point)
                    .commit(1, 2, bytes("second"), context)
            }
            assertRecord(fixture.newCoordinator().load(context), 2, bytes("second"))
        }
    }

    @Test
    fun orphanedFirstSlotNeverOverridesGenesisAnchor() {
        val fixture = Fixture()
        expect<DurableStateStoreException.InterruptedWrite> {
            fixture.newCoordinator(faultPoint = DurableStateFaultPoint.AFTER_SLOT_DIRECTORY_SYNC)
                .commit(0, 1, bytes("unanchored"), context)
        }
        assertTrue(fixture.newCoordinator().load(context) === DurableStateLoadResult.Empty)
        fixture.newCoordinator().commit(0, 1, bytes("committed"), context)
        assertRecord(fixture.newCoordinator().load(context), 1, bytes("committed"))
    }

    @Test
    fun lockIsReleasedAfterEveryFailureAndLaterOperationCanRecover() {
        val fixture = Fixture(faultPoint = DurableStateFaultPoint.AFTER_KEY_CREATION)
        expect<DurableStateStoreException.InterruptedWrite> { fixture.coordinator.load(context) }
        assertFalse(fixture.fileSystem.locked)
        assertEquals(fixture.fileSystem.acquireCount, fixture.fileSystem.releaseCount)
        assertTrue(fixture.newCoordinator().load(context) === DurableStateLoadResult.Empty)
    }

    @Test
    fun competingInitialCasCommitsSerializeAndExactlyOneWins() {
        val fixture = Fixture()
        fixture.coordinator.load(context)
        val start = CountDownLatch(1)
        val pool = Executors.newFixedThreadPool(2)
        try {
            val outcomes = (1..2).map { number ->
                pool.submit<String> {
                    start.await()
                    try {
                        fixture.newCoordinator().commit(
                            0,
                            1,
                            bytes("candidate-$number"),
                            context,
                        )
                        "committed"
                    } catch (_: DurableStateStoreException.GenerationConflict) {
                        "conflict"
                    }
                }
            }
            start.countDown()
            assertEquals(setOf("committed", "conflict"), outcomes.map { it.get() }.toSet())
        } finally {
            pool.shutdownNow()
        }
    }

    @Test
    fun missingWrongOrReplacedKeyFailsClosed() {
        val fixture = committedFixture()
        fixture.crypto.removeKey()
        expect<DurableStateStoreException.MissingInstallationKey> {
            fixture.coordinator.load(context)
        }

        val replaced = committedFixture()
        replaced.crypto.replaceKey(0x55)
        expect<DurableStateStoreException.AuthenticationFailed> {
            replaced.coordinator.load(context)
        }
    }

    @Test
    fun keyOnlyWithoutFilesCanFinishGenesisButSlotWithoutAnchorIsRejected() {
        val fixture = Fixture()
        fixture.crypto.createKey()
        assertTrue(fixture.coordinator.load(context) === DurableStateLoadResult.Empty)

        val missingAnchor = committedFixture()
        missingAnchor.fileSystem.anchor = null
        expect<DurableStateStoreException.MissingAnchor> {
            missingAnchor.coordinator.load(context)
        }
    }

    @Test
    fun corruptOrMissingAnchoredSlotNeverFallsBackToOlderSlot() {
        val fixture = committedFixture()
        fixture.coordinator.commit(1, 2, bytes("second"), context)
        assertNotNull(fixture.fileSystem.slots[DurableStateSlot.A])
        fixture.fileSystem.slots[DurableStateSlot.B] =
            fixture.fileSystem.slots.getValue(DurableStateSlot.B).copyOf().also {
                it[it.lastIndex] = (it.last().toInt() xor 1).toByte()
            }
        expect<DurableStateStoreException.AnchorDigestMismatch> {
            fixture.coordinator.load(context)
        }

        val missing = committedFixture()
        missing.coordinator.commit(1, 2, bytes("second"), context)
        missing.fileSystem.slots.remove(DurableStateSlot.B)
        expect<DurableStateStoreException.MissingAnchoredSlot> {
            missing.coordinator.load(context)
        }
    }

    @Test
    fun staleSlotSubstitutionAndOversizedFilesFailClosed() {
        val fixture = committedFixture()
        fixture.coordinator.commit(1, 2, bytes("second"), context)
        fixture.fileSystem.slots[DurableStateSlot.B] =
            fixture.fileSystem.slots.getValue(DurableStateSlot.A).copyOf()
        expect<DurableStateStoreException.AnchorDigestMismatch> {
            fixture.coordinator.load(context)
        }

        val oversizedAnchor = Fixture()
        oversizedAnchor.crypto.createKey()
        oversizedAnchor.fileSystem.anchor =
            ByteArray(DurableStateLimits.MAXIMUM_ANCHOR_BYTES + 1)
        expect<DurableStateStoreException.EnvelopeTooLarge> {
            oversizedAnchor.coordinator.load(context)
        }
    }

    @Test
    fun anchorHeaderNonceCiphertextAndTagTamperingAreRejected() {
        val protectedOffsets = listOf(
            0,
            10,
            14,
            22,
            23,
            24,
            26,
            58,
            90,
            DurableAnchorEnvelopeCodec.ENCODED_BYTES - 17,
            DurableAnchorEnvelopeCodec.ENCODED_BYTES - 1,
        )
        for (offset in protectedOffsets) {
            val fixture = committedFixture()
            fixture.fileSystem.anchor = fixture.fileSystem.anchor!!.copyOf().also {
                it[offset] = (it[offset].toInt() xor 1).toByte()
            }
            expectAny(
                DurableStateStoreException.CorruptAnchor::class.java,
                DurableStateStoreException.SchemaMismatch::class.java,
                DurableStateStoreException.ApplicationIdentityMismatch::class.java,
                DurableStateStoreException.ContextMismatch::class.java,
                DurableStateStoreException.AuthenticationFailed::class.java,
            ) { fixture.coordinator.load(context) }
        }
    }

    @Test
    fun anchorTruncationTrailingAndFutureVersionAreRejected() {
        val fixture = committedFixture()
        val valid = fixture.fileSystem.anchor!!.copyOf()
        for (length in listOf(0, 7, 8, 25, valid.size - 1)) {
            fixture.fileSystem.anchor = valid.copyOf(length)
            expect<DurableStateStoreException.CorruptAnchor> {
                fixture.coordinator.load(context)
            }
        }
        fixture.fileSystem.anchor = valid + byteArrayOf(0)
        expect<DurableStateStoreException.CorruptAnchor> {
            fixture.coordinator.load(context)
        }
        fixture.fileSystem.anchor = valid.copyOf().also {
            it[8] = 0
            it[9] = 2
        }
        expect<DurableStateStoreException.UnsupportedAnchorVersion> {
            fixture.coordinator.load(context)
        }
    }

    @Test
    fun slotCodecStrictlyRejectsTruncationTrailingFutureAndImpossibleLengths() {
        val fixture = committedFixture()
        val valid = fixture.fileSystem.slots.getValue(DurableStateSlot.A)
        for (length in listOf(0, 7, 8, DurableSlotEnvelopeCodec.FIXED_OVERHEAD - 1, valid.size - 1)) {
            expect<DurableStateStoreException.CorruptEnvelope> {
                DurableSlotEnvelopeCodec.decode(valid.copyOf(length))
            }
        }
        expect<DurableStateStoreException.CorruptEnvelope> {
            DurableSlotEnvelopeCodec.decode(valid + byteArrayOf(0))
        }
        expect<DurableStateStoreException.UnsupportedEnvelopeVersion> {
            DurableSlotEnvelopeCodec.decode(valid.copyOf().also {
                it[8] = 0
                it[9] = 2
            })
        }
        expectAny(
            DurableStateStoreException.CorruptEnvelope::class.java,
            DurableStateStoreException.EnvelopeTooLarge::class.java,
        ) {
            DurableSlotEnvelopeCodec.decode(valid.copyOf().also {
                for (index in 24..27) it[index] = 0xff.toByte()
            })
        }
        expect<DurableStateStoreException.CorruptEnvelope> {
            DurableSlotEnvelopeCodec.decode(valid.copyOf().also { it[14] = 0x80.toByte() })
        }
    }

    @Test
    fun noncanonicalGenesisAndLiveAnchorShapesAreRejectedAfterAuthentication() {
        val fixture = Fixture()
        fixture.crypto.createKey()
        val app = "eu.advatar.wallet"
        val appDigest = fixture.crypto.sha256(app.encodeToByteArray())
        val contextDigest = fixture.crypto.sha256(context.bindingForAuthentication())

        val badGenesis = DurableAnchor(
            context.schemaVersion,
            0,
            DurableStateSlot.A.encoded,
            appDigest,
            contextDigest,
            ByteArray(DIGEST_BYTES),
        )
        fixture.fileSystem.anchor = sealTestAnchor(fixture.crypto, app, context, badGenesis)
        expect<DurableStateStoreException.InvalidGenesisAnchor> {
            fixture.coordinator.load(context)
        }

        val badLive = DurableAnchor(
            context.schemaVersion,
            1,
            DurableStateSlot.A.encoded,
            appDigest,
            contextDigest,
            ByteArray(DIGEST_BYTES),
        )
        fixture.fileSystem.anchor = sealTestAnchor(fixture.crypto, app, context, badLive)
        expect<DurableStateStoreException.CorruptAnchor> {
            fixture.coordinator.load(context)
        }
    }

    @Test
    fun slotWriteIsDurableBeforeAnchorAdvances() {
        val fixture = committedFixture()
        fixture.fileSystem.events.clear()
        fixture.coordinator.commit(1, 2, bytes("second"), context)
        val events = fixture.fileSystem.events
        assertTrue(events.indexOf("slot-sync") < events.indexOf("slot-rename"))
        assertTrue(events.indexOf("slot-rename") < events.indexOf("slot-directory-sync"))
        assertTrue(events.indexOf("slot-directory-sync") < events.indexOf("anchor-create"))
        assertTrue(events.indexOf("anchor-sync") < events.indexOf("anchor-rename"))
        assertTrue(events.indexOf("anchor-rename") < events.indexOf("anchor-directory-sync"))
    }

    @Test
    fun deterministicCleanupRemovesOnlyBoundedKnownTempsBeforeRead() {
        val fixture = committedFixture()
        fixture.fileSystem.temporaryFiles["slot-a"] = bytes("stale")
        fixture.fileSystem.temporaryFiles["slot-b"] = bytes("stale")
        fixture.fileSystem.temporaryFiles["anchor"] = bytes("stale")
        assertRecord(fixture.coordinator.load(context), 1, bytes("first"))
        assertTrue(fixture.fileSystem.temporaryFiles.isEmpty())
        assertEquals(2, fixture.fileSystem.cleanupCount)
    }

    @Test
    fun completeAuthenticatedSnapshotRollbackIsExplicitlyNotClaimedDetected() {
        val fixture = committedFixture()
        val oldAnchor = fixture.fileSystem.anchor!!.copyOf()
        val oldSlots = fixture.fileSystem.copySlots()
        fixture.coordinator.commit(1, 2, bytes("second"), context)
        assertRecord(fixture.coordinator.load(context), 2, bytes("second"))

        fixture.fileSystem.anchor = oldAnchor
        fixture.fileSystem.slots.clear()
        fixture.fileSystem.slots.putAll(oldSlots)
        assertRecord(fixture.coordinator.load(context), 1, bytes("first"))
    }

    private fun committedFixture(): Fixture = Fixture().also {
        it.coordinator.commit(0, 1, bytes("first"), context)
    }

    private class Fixture(faultPoint: DurableStateFaultPoint? = null) {
        val crypto = TestDurableCrypto()
        val fileSystem = MemoryDurableFileSystem()
        val processLock = Any()
        val coordinator = newCoordinator(faultPoint = faultPoint)

        fun newCoordinator(
            applicationIdentity: String = "eu.advatar.wallet",
            faultPoint: DurableStateFaultPoint? = null,
        ) = DurableStateCoordinator(
            applicationIdentity,
            crypto,
            fileSystem,
            faultPoint?.let { FailingFaultInjector(it) },
            processLock,
        )
    }
}

class DurableAesKeyPolicyTest {
    @Test
    fun strongBoxIsAcceptedAndTeeRequiresExplicitPolicy() {
        assertEquals(null, DurableAesKeyPolicyValidator.violation(approvedFacts(), HardwareKeyPolicy()))
        val tee = approvedFacts().copy(securityLevel = HardwareSecurityLevel.TRUSTED_ENVIRONMENT)
        assertEquals(
            "TEE use was not explicitly allowed",
            DurableAesKeyPolicyValidator.violation(tee, HardwareKeyPolicy()),
        )
        assertEquals(
            null,
            DurableAesKeyPolicyValidator.violation(
                tee,
                HardwareKeyPolicy(allowTrustedEnvironment = true),
            ),
        )
    }

    @Test
    fun softwareUnknownImportedAndExtractableKeysAreRejected() {
        val invalid = listOf(
            approvedFacts().copy(securityLevel = HardwareSecurityLevel.SOFTWARE),
            approvedFacts().copy(securityLevel = HardwareSecurityLevel.UNKNOWN),
            approvedFacts().copy(originGenerated = false),
            approvedFacts().copy(extractable = true),
        )
        for (facts in invalid) {
            assertNotNull(DurableAesKeyPolicyValidator.violation(facts, HardwareKeyPolicy()))
        }
    }

    @Test
    fun wrongOrExcessCryptographicCapabilitiesAreRejected() {
        val invalid = listOf(
            approvedFacts().copy(algorithm = "DESede"),
            approvedFacts().copy(keySize = 128),
            approvedFacts().copy(purposes = KeyProperties.PURPOSE_ENCRYPT),
            approvedFacts().copy(
                purposes = approvedFacts().purposes or KeyProperties.PURPOSE_SIGN,
            ),
            approvedFacts().copy(blockModes = setOf(KeyProperties.BLOCK_MODE_GCM, "CBC")),
            approvedFacts().copy(encryptionPaddings = setOf("PKCS7Padding")),
            approvedFacts().copy(signaturePaddings = setOf("PSS")),
            approvedFacts().copy(digests = setOf(KeyProperties.DIGEST_SHA256)),
        )
        for (facts in invalid) {
            assertNotNull(DurableAesKeyPolicyValidator.violation(facts, HardwareKeyPolicy()))
        }
    }

    @Test
    fun missingOrExcessAuthenticationCapabilitiesAreRejected() {
        val invalid = listOf(
            approvedFacts().copy(userAuthenticationRequired = false),
            approvedFacts().copy(authenticationEnforcedBySecureHardware = false),
            approvedFacts().copy(authenticationValiditySeconds = 31),
            approvedFacts().copy(authenticationTypes = KeyProperties.AUTH_BIOMETRIC_STRONG),
            approvedFacts().copy(trustedUserPresenceRequired = true),
            approvedFacts().copy(authenticationValidWhileOnBody = true),
            approvedFacts().copy(userConfirmationRequired = true),
            approvedFacts().copy(validityStart = Date(0)),
            approvedFacts().copy(originationEnd = Date(1)),
            approvedFacts().copy(consumptionEnd = Date(2)),
            approvedFacts().copy(remainingUsageCount = 100),
        )
        for (facts in invalid) {
            assertNotNull(DurableAesKeyPolicyValidator.violation(facts, HardwareKeyPolicy()))
        }
    }

    private fun approvedFacts() = DurableAesKeyFacts(
        securityLevel = HardwareSecurityLevel.STRONGBOX,
        algorithm = KeyProperties.KEY_ALGORITHM_AES,
        keySize = 256,
        originGenerated = true,
        purposes = KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT,
        blockModes = setOf(KeyProperties.BLOCK_MODE_GCM),
        encryptionPaddings = setOf(KeyProperties.ENCRYPTION_PADDING_NONE),
        signaturePaddings = emptySet(),
        digests = emptySet(),
        extractable = false,
        userAuthenticationRequired = true,
        authenticationEnforcedBySecureHardware = true,
        authenticationValiditySeconds = 30,
        authenticationTypes =
            KeyProperties.AUTH_BIOMETRIC_STRONG or KeyProperties.AUTH_DEVICE_CREDENTIAL,
        trustedUserPresenceRequired = false,
        authenticationValidWhileOnBody = false,
        userConfirmationRequired = false,
        validityStart = null,
        originationEnd = null,
        consumptionEnd = null,
        remainingUsageCount = KeyProperties.UNRESTRICTED_USAGE_COUNT,
    )
}

class DurablePathPolicyTest {
    @Test
    fun privateOwnedDirectoryAndRegularFileAreAccepted() {
        assertEquals(null, DurablePathPolicy.validateTrustedParent(directory(), UID, GID))
        assertEquals(
            null,
            DurablePathPolicy.validateTrustedParent(directory().copy(mode = 0x1f9), UID, GID),
        )
        assertEquals(null, DurablePathPolicy.validateRoot(directory(), UID))
        assertEquals(null, DurablePathPolicy.validateRegular(regular(), UID))
    }

    @Test
    fun symlinksSpecialFilesAndHardLinksAreRejectedForLockSlotsAnchorAndTemps() {
        val hostile = listOf(
            regular().copy(type = DurableNodeType.SYMLINK),
            regular().copy(type = DurableNodeType.OTHER),
            regular().copy(linkCount = 2),
        )
        for (facts in hostile) {
            assertNotNull(DurablePathPolicy.validateRegular(facts, UID))
        }
    }

    @Test
    fun wrongOwnerAndPermissiveModesAreRejected() {
        assertNotNull(DurablePathPolicy.validateRegular(regular().copy(ownerUid = UID + 1), UID))
        assertNotNull(DurablePathPolicy.validateRegular(regular().copy(mode = 0x1a0), UID))
        assertNotNull(DurablePathPolicy.validateRoot(directory().copy(mode = 0x1e8), UID))
        assertNotNull(
            DurablePathPolicy.validateTrustedParent(directory().copy(ownerGid = GID + 1), UID, GID),
        )
        assertNotNull(
            DurablePathPolicy.validateTrustedParent(directory().copy(mode = 0x1c2), UID, GID),
        )
    }

    @Test
    fun changedRootIdentityIsObservableToTheProductionPolicy() {
        val original = directory().copy(device = 4, inode = 7)
        val replacement = directory().copy(device = 4, inode = 8)
        assertFalse(original.device == replacement.device && original.inode == replacement.inode)
    }

    private fun regular() = DurablePathFacts(
        DurableNodeType.REGULAR,
        UID,
        GID,
        DurablePathPolicy.PRIVATE_FILE_MODE,
        1,
        4,
        7,
        100,
    )

    private fun directory() = DurablePathFacts(
        DurableNodeType.DIRECTORY,
        UID,
        GID,
        DurablePathPolicy.PRIVATE_DIRECTORY_MODE,
        2,
        4,
        6,
        0,
    )

    private companion object {
        const val UID = 10_123
        const val GID = 10_123
    }
}

private class FailingFaultInjector(private val target: DurableStateFaultPoint) :
    DurableStateFaultInjector {
    override fun hit(point: DurableStateFaultPoint) {
        if (point == target) throw DurableStateStoreException.InterruptedWrite(point)
    }
}

private class TestDurableCrypto : DurableStateCrypto {
    private var key: ByteArray? = null
    private var nonceCounter = 0L

    override fun hasValidKey(): Boolean = key != null

    override fun createKey() {
        if (key == null) key = ByteArray(32) { 0x19 }
    }

    fun removeKey() {
        key = null
    }

    fun replaceKey(seed: Int) {
        key = ByteArray(32) { seed.toByte() }
    }

    override fun encrypt(
        plaintext: ByteArray,
        associatedData: ByteArray,
    ): DurableSealedPayload {
        val keyBytes = key ?: throw DurableStateStoreException.MissingInstallationKey()
        val nonce = ByteArray(12)
        ByteBuffer.wrap(nonce).putInt(0x45555731).putLong(++nonceCounter)
        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        cipher.init(Cipher.ENCRYPT_MODE, SecretKeySpec(keyBytes, "AES"), GCMParameterSpec(128, nonce))
        cipher.updateAAD(associatedData)
        val combined = cipher.doFinal(plaintext)
        return DurableSealedPayload(
            nonce,
            combined.copyOfRange(0, combined.size - 16),
            combined.copyOfRange(combined.size - 16, combined.size),
        )
    }

    override fun decrypt(
        payload: DurableSealedPayload,
        associatedData: ByteArray,
    ): ByteArray {
        val keyBytes = key ?: throw DurableStateStoreException.MissingInstallationKey()
        return try {
            val cipher = Cipher.getInstance("AES/GCM/NoPadding")
            cipher.init(
                Cipher.DECRYPT_MODE,
                SecretKeySpec(keyBytes, "AES"),
                GCMParameterSpec(128, payload.nonce),
            )
            cipher.updateAAD(associatedData)
            cipher.doFinal(payload.ciphertext + payload.tag)
        } catch (error: Exception) {
            throw DurableStateStoreException.AuthenticationFailed(error)
        }
    }

    override fun sha256(value: ByteArray): ByteArray =
        MessageDigest.getInstance("SHA-256").digest(value)
}

private class MemoryDurableFileSystem : DurableStateFileSystem {
    var anchor: ByteArray? = null
    val slots = mutableMapOf<DurableStateSlot, ByteArray>()
    val temporaryFiles = mutableMapOf<String, ByteArray>()
    val events = mutableListOf<String>()
    var locked = false
    var acquireCount = 0
    var releaseCount = 0
    var cleanupCount = 0

    override fun acquireExclusiveLock() {
        check(!locked)
        locked = true
        acquireCount += 1
    }

    override fun releaseExclusiveLock() {
        check(locked)
        locked = false
        releaseCount += 1
    }

    override fun cleanupTemporaryFiles() {
        requireLocked()
        temporaryFiles.clear()
        cleanupCount += 1
    }

    override fun hasAnySlot(): Boolean {
        requireLocked()
        return slots.isNotEmpty()
    }

    override fun readSlot(slot: DurableStateSlot, maximumBytes: Int): ByteArray? {
        requireLocked()
        val value = slots[slot] ?: return null
        if (value.size > maximumBytes) {
            throw DurableStateStoreException.EnvelopeTooLarge(value.size.toLong(), maximumBytes)
        }
        return value.copyOf()
    }

    override fun readAnchor(maximumBytes: Int): ByteArray? {
        requireLocked()
        val value = anchor ?: return null
        if (value.size > maximumBytes) {
            throw DurableStateStoreException.EnvelopeTooLarge(value.size.toLong(), maximumBytes)
        }
        return value.copyOf()
    }

    override fun writeSlotDurably(
        slot: DurableStateSlot,
        value: ByteArray,
        faultInjector: DurableStateFaultInjector?,
    ) {
        requireLocked()
        faultInjector?.hit(DurableStateFaultPoint.BEFORE_SLOT_TEMP_CREATE)
        temporaryFiles["slot-${slot.name.lowercase()}"] = ByteArray(0)
        events += "slot-create"
        faultInjector?.hit(DurableStateFaultPoint.AFTER_SLOT_TEMP_CREATE)
        temporaryFiles["slot-${slot.name.lowercase()}"] = value.copyOf()
        events += "slot-write"
        faultInjector?.hit(DurableStateFaultPoint.AFTER_SLOT_TEMP_WRITE)
        events += "slot-sync"
        faultInjector?.hit(DurableStateFaultPoint.AFTER_SLOT_TEMP_SYNC)
        slots[slot] = value.copyOf()
        temporaryFiles.remove("slot-${slot.name.lowercase()}")
        events += "slot-rename"
        faultInjector?.hit(DurableStateFaultPoint.AFTER_SLOT_RENAME)
        events += "slot-directory-sync"
        faultInjector?.hit(DurableStateFaultPoint.AFTER_SLOT_DIRECTORY_SYNC)
    }

    override fun writeAnchorDurably(
        value: ByteArray,
        createOnly: Boolean,
        faultInjector: DurableStateFaultInjector?,
    ) {
        requireLocked()
        if (createOnly && anchor != null) throw DurableStateStoreException.AnchorAlreadyExists()
        if (!createOnly && anchor == null) throw DurableStateStoreException.MissingAnchor()
        faultInjector?.hit(DurableStateFaultPoint.BEFORE_ANCHOR_TEMP_CREATE)
        temporaryFiles["anchor"] = ByteArray(0)
        events += "anchor-create"
        faultInjector?.hit(DurableStateFaultPoint.AFTER_ANCHOR_TEMP_CREATE)
        temporaryFiles["anchor"] = value.copyOf()
        events += "anchor-write"
        faultInjector?.hit(DurableStateFaultPoint.AFTER_ANCHOR_TEMP_WRITE)
        events += "anchor-sync"
        faultInjector?.hit(DurableStateFaultPoint.AFTER_ANCHOR_TEMP_SYNC)
        anchor = value.copyOf()
        temporaryFiles.remove("anchor")
        events += "anchor-rename"
        faultInjector?.hit(DurableStateFaultPoint.AFTER_ANCHOR_RENAME)
        events += "anchor-directory-sync"
        faultInjector?.hit(DurableStateFaultPoint.AFTER_ANCHOR_DIRECTORY_SYNC)
    }

    fun copySlots(): Map<DurableStateSlot, ByteArray> =
        slots.mapValues { it.value.copyOf() }

    private fun requireLocked() = check(locked)
}

private fun sealTestAnchor(
    crypto: DurableStateCrypto,
    applicationIdentity: String,
    context: DurableStateContext,
    anchor: DurableAnchor,
): ByteArray {
    val header = DurableEnvelopeHeader(
        anchor.schemaVersion,
        anchor.generation,
        anchor.slotEncoded,
        anchor.applicationDigest,
        anchor.contextDigest,
    )
    val aad = DurableAssociatedDataCodec.anchor(
        applicationIdentity.encodeToByteArray(),
        context,
        anchor.generation,
        anchor.slotEncoded,
    )
    return DurableAnchorEnvelopeCodec.encode(
        header,
        crypto.encrypt(DurableAnchorPlaintextCodec.encode(anchor), aad),
    )
}

private fun assertRecord(result: DurableStateLoadResult, generation: Long, plaintext: ByteArray) {
    assertTrue(result is DurableStateLoadResult.Record)
    result as DurableStateLoadResult.Record
    assertEquals(generation, result.value.generation)
    assertArrayEquals(plaintext, result.value.plaintext)
}

private fun assertSlotMapsEqual(
    expected: Map<DurableStateSlot, ByteArray>,
    actual: Map<DurableStateSlot, ByteArray>,
) {
    assertEquals(expected.keys, actual.keys)
    for ((slot, bytes) in expected) assertArrayEquals(bytes, actual.getValue(slot))
}

private inline fun <reified T : Throwable> expect(noinline block: () -> Unit): T {
    try {
        block()
        fail("Expected ${T::class.java.simpleName}")
    } catch (error: Throwable) {
        if (error !is T) throw error
        return error
    }
    error("unreachable")
}

private fun expectAny(vararg types: Class<out Throwable>, block: () -> Unit) {
    try {
        block()
        fail("Expected one of ${types.joinToString { it.simpleName }}")
    } catch (error: Throwable) {
        if (types.none { it.isInstance(error) }) throw error
    }
}

private fun bytes(value: String): ByteArray = value.encodeToByteArray()
