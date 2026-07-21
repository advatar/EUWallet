package eu.advatar.wallet.shell

import android.content.Context
import android.content.pm.PackageManager
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyInfo
import android.security.keystore.KeyProperties
import android.security.keystore.StrongBoxUnavailableException
import android.system.ErrnoException
import android.system.Os
import android.system.OsConstants
import java.io.ByteArrayOutputStream
import java.io.File
import java.io.FileOutputStream
import java.security.KeyStore
import java.security.MessageDigest
import java.security.ProviderException
import java.security.SecureRandom
import java.util.Date
import javax.crypto.AEADBadTagException
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.SecretKeyFactory
import javax.crypto.spec.GCMParameterSpec

/**
 * Production Android implementation. It has no software, demo, emulator or in-memory fallback.
 * State is placed only below [Context.getNoBackupFilesDir].
 */
class AndroidDurableStateStore(
    context: Context,
    hardwareKeyPolicy: HardwareKeyPolicy = HardwareKeyPolicy(),
) : DurableStateStore {
    private val applicationContext = context.applicationContext
    private val coordinator = DurableStateCoordinator(
        applicationIdentity = applicationContext.packageName,
        crypto = AndroidKeystoreDurableStateCrypto(applicationContext, hardwareKeyPolicy),
        fileSystem = AndroidNoBackupDurableStateFileSystem(applicationContext.noBackupFilesDir),
    )

    override fun load(context: DurableStateContext): DurableStateLoadResult =
        coordinator.load(context)

    override fun commit(
        expectedGeneration: Long,
        nextGeneration: Long,
        plaintext: ByteArray,
        context: DurableStateContext,
    ): DurableStateRecord = coordinator.commit(
        expectedGeneration,
        nextGeneration,
        plaintext,
        context,
    )
}

internal data class DurableAesKeyFacts(
    val securityLevel: HardwareSecurityLevel,
    val algorithm: String,
    val keySize: Int,
    val originGenerated: Boolean,
    val purposes: Int,
    val blockModes: Set<String>,
    val encryptionPaddings: Set<String>,
    val signaturePaddings: Set<String>,
    val digests: Set<String>,
    val extractable: Boolean,
    val userAuthenticationRequired: Boolean,
    val authenticationEnforcedBySecureHardware: Boolean,
    val authenticationValiditySeconds: Int,
    val authenticationTypes: Int,
    val trustedUserPresenceRequired: Boolean,
    val authenticationValidWhileOnBody: Boolean,
    val userConfirmationRequired: Boolean,
    val validityStart: Date?,
    val originationEnd: Date?,
    val consumptionEnd: Date?,
    val remainingUsageCount: Int,
)

internal object DurableAesKeyPolicyValidator {
    fun violation(facts: DurableAesKeyFacts, policy: HardwareKeyPolicy): String? {
        when (facts.securityLevel) {
            HardwareSecurityLevel.STRONGBOX -> Unit
            HardwareSecurityLevel.TRUSTED_ENVIRONMENT -> {
                if (!policy.allowTrustedEnvironment) return "TEE use was not explicitly allowed"
            }
            HardwareSecurityLevel.SOFTWARE -> return "key is software-backed"
            HardwareSecurityLevel.UNKNOWN -> return "key security level is not provable"
        }
        if (facts.algorithm != KeyProperties.KEY_ALGORITHM_AES) return "key is not AES"
        if (facts.keySize != AES_KEY_BITS) return "key is not AES-256"
        if (!facts.originGenerated) return "key was not generated in AndroidKeyStore"
        if (facts.purposes != REQUIRED_PURPOSES) return "key purposes are not exactly encrypt/decrypt"
        if (facts.blockModes != setOf(KeyProperties.BLOCK_MODE_GCM)) {
            return "key is not restricted to GCM"
        }
        if (facts.encryptionPaddings != setOf(KeyProperties.ENCRYPTION_PADDING_NONE)) {
            return "key is not restricted to no padding"
        }
        if (facts.signaturePaddings.isNotEmpty()) return "key has signature padding capabilities"
        if (facts.digests.isNotEmpty()) return "key has unexpected digest capabilities"
        if (facts.extractable) return "key material is exportable"
        if (!facts.userAuthenticationRequired) return "user authentication is not required"
        if (!facts.authenticationEnforcedBySecureHardware) {
            return "user authentication is not enforced by secure hardware"
        }
        if (facts.authenticationValiditySeconds != policy.authenticationValiditySeconds) {
            return "user-authentication validity does not match policy"
        }
        if (facts.authenticationTypes != policy.authenticationTypes) {
            return "user-authentication types do not match policy"
        }
        if (facts.trustedUserPresenceRequired) return "trusted-user-presence capability is unexpected"
        if (facts.authenticationValidWhileOnBody) return "on-body authentication extension is enabled"
        if (facts.userConfirmationRequired) return "user-confirmation capability is unexpected"
        if (facts.validityStart != null || facts.originationEnd != null || facts.consumptionEnd != null) {
            return "key has unexpected validity dates"
        }
        if (facts.remainingUsageCount != KeyProperties.UNRESTRICTED_USAGE_COUNT) {
            return "key has an unexpected usage-count limit"
        }
        return null
    }

    private const val AES_KEY_BITS = 256
    private const val REQUIRED_PURPOSES =
        KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT
}

internal class AndroidKeystoreDurableStateCrypto(
    private val context: Context,
    private val policy: HardwareKeyPolicy,
) : DurableStateCrypto {
    private val keyStore: KeyStore by lazy(LazyThreadSafetyMode.SYNCHRONIZED) {
        try {
            KeyStore.getInstance(ANDROID_KEYSTORE).apply { load(null) }
        } catch (error: Exception) {
            throw DurableStateStoreException.KeyAccessFailed(error)
        }
    }

    override fun hasValidKey(): Boolean {
        requirePhysicalDevice()
        val containsAlias = try {
            keyStore.containsAlias(KEY_ALIAS)
        } catch (error: Exception) {
            throw DurableStateStoreException.KeyAccessFailed(error)
        }
        if (!containsAlias) return false
        loadAndVerifyKey()
        return true
    }

    override fun createKey() {
        requirePhysicalDevice()
        if (hasValidKey()) return
        val strongBoxAvailable = context.packageManager.hasSystemFeature(
            PackageManager.FEATURE_STRONGBOX_KEYSTORE,
        )
        if (strongBoxAvailable) {
            try {
                createAndVerify(strongBox = true)
                return
            } catch (error: StrongBoxUnavailableException) {
                if (!policy.allowTrustedEnvironment) {
                    throw DurableStateStoreException.StrongBoxRequired(error)
                }
            } catch (error: ProviderException) {
                throw DurableStateStoreException.KeyCreationFailed(error)
            }
        } else if (!policy.allowTrustedEnvironment) {
            throw DurableStateStoreException.StrongBoxRequired()
        }

        try {
            createAndVerify(strongBox = false)
        } catch (error: ProviderException) {
            throw DurableStateStoreException.KeyCreationFailed(error)
        }
    }

    override fun encrypt(
        plaintext: ByteArray,
        associatedData: ByteArray,
    ): DurableSealedPayload {
        val key = loadAndVerifyKey()
        try {
            val cipher = Cipher.getInstance(AES_GCM_TRANSFORMATION)
            cipher.init(Cipher.ENCRYPT_MODE, key, SecureRandom())
            cipher.updateAAD(associatedData)
            val combined = cipher.doFinal(plaintext)
            val nonce = cipher.iv ?: throw DurableStateStoreException.EncryptionFailed()
            if (nonce.size != GCM_NONCE_BYTES || combined.size != plaintext.size + GCM_TAG_BYTES) {
                throw DurableStateStoreException.EncryptionFailed()
            }
            return DurableSealedPayload(
                nonce = nonce.copyOf(),
                ciphertext = combined.copyOfRange(0, combined.size - GCM_TAG_BYTES),
                tag = combined.copyOfRange(combined.size - GCM_TAG_BYTES, combined.size),
            )
        } catch (error: DurableStateStoreException) {
            throw error
        } catch (error: Exception) {
            throw DurableStateStoreException.EncryptionFailed(error)
        }
    }

    override fun decrypt(
        payload: DurableSealedPayload,
        associatedData: ByteArray,
    ): ByteArray {
        if (payload.nonce.size != GCM_NONCE_BYTES || payload.tag.size != GCM_TAG_BYTES) {
            throw DurableStateStoreException.AuthenticationFailed()
        }
        val key = loadAndVerifyKey()
        try {
            val cipher = Cipher.getInstance(AES_GCM_TRANSFORMATION)
            cipher.init(
                Cipher.DECRYPT_MODE,
                key,
                GCMParameterSpec(GCM_TAG_BITS, payload.nonce),
            )
            cipher.updateAAD(associatedData)
            return cipher.doFinal(payload.ciphertext + payload.tag)
        } catch (error: AEADBadTagException) {
            throw DurableStateStoreException.AuthenticationFailed(error)
        } catch (error: Exception) {
            throw DurableStateStoreException.AuthenticationFailed(error)
        }
    }

    override fun sha256(value: ByteArray): ByteArray =
        MessageDigest.getInstance(SHA256).digest(value)

    private fun createAndVerify(strongBox: Boolean) {
        try {
            val builder = KeyGenParameterSpec.Builder(KEY_ALIAS, REQUIRED_PURPOSES)
                .setKeySize(AES_KEY_BITS)
                .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
                .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
                .setRandomizedEncryptionRequired(true)
                .setUserAuthenticationRequired(true)
                .setUnlockedDeviceRequired(true)
                .setIsStrongBoxBacked(strongBox)
            builder.setUserAuthenticationParameters(
                policy.authenticationValiditySeconds,
                policy.authenticationTypes,
            )
            val generator = KeyGenerator.getInstance(
                KeyProperties.KEY_ALGORITHM_AES,
                ANDROID_KEYSTORE,
            )
            generator.init(builder.build())
            generator.generateKey()
            loadAndVerifyKey()
        } catch (error: StrongBoxUnavailableException) {
            throw error
        } catch (error: ProviderException) {
            throw error
        } catch (error: DurableStateStoreException) {
            deleteRejectedCreatedKey(error)
            throw error
        } catch (error: Exception) {
            val wrapped = DurableStateStoreException.KeyCreationFailed(error)
            deleteRejectedCreatedKey(wrapped)
            throw wrapped
        }
    }

    private fun loadAndVerifyKey(): SecretKey {
        requirePhysicalDevice()
        val key = try {
            keyStore.getKey(KEY_ALIAS, null) as? SecretKey
                ?: throw DurableStateStoreException.KeyPolicyViolation(
                    "existing alias is not a secret key",
                )
        } catch (error: DurableStateStoreException) {
            throw error
        } catch (error: Exception) {
            throw DurableStateStoreException.KeyAccessFailed(error)
        }
        val keyInfo = try {
            SecretKeyFactory.getInstance(key.algorithm, ANDROID_KEYSTORE)
                .getKeySpec(key, KeyInfo::class.java) as KeyInfo
        } catch (error: Exception) {
            throw DurableStateStoreException.KeyAccessFailed(error)
        }
        val facts = DurableAesKeyFacts(
            securityLevel = when (keyInfo.securityLevel) {
                KeyProperties.SECURITY_LEVEL_SOFTWARE -> HardwareSecurityLevel.SOFTWARE
                KeyProperties.SECURITY_LEVEL_TRUSTED_ENVIRONMENT ->
                    HardwareSecurityLevel.TRUSTED_ENVIRONMENT
                KeyProperties.SECURITY_LEVEL_STRONGBOX -> HardwareSecurityLevel.STRONGBOX
                else -> HardwareSecurityLevel.UNKNOWN
            },
            algorithm = key.algorithm,
            keySize = keyInfo.keySize,
            originGenerated = keyInfo.origin == KeyProperties.ORIGIN_GENERATED,
            purposes = keyInfo.purposes,
            blockModes = keyInfo.blockModes.toSet(),
            encryptionPaddings = keyInfo.encryptionPaddings.toSet(),
            signaturePaddings = keyInfo.signaturePaddings.toSet(),
            digests = keyInfo.digests.toSet(),
            extractable = key.encoded != null,
            userAuthenticationRequired = keyInfo.isUserAuthenticationRequired,
            authenticationEnforcedBySecureHardware =
                keyInfo.isUserAuthenticationRequirementEnforcedBySecureHardware,
            authenticationValiditySeconds = keyInfo.userAuthenticationValidityDurationSeconds,
            authenticationTypes = keyInfo.userAuthenticationType,
            trustedUserPresenceRequired = keyInfo.isTrustedUserPresenceRequired,
            authenticationValidWhileOnBody = keyInfo.isUserAuthenticationValidWhileOnBody,
            userConfirmationRequired = keyInfo.isUserConfirmationRequired,
            validityStart = keyInfo.keyValidityStart,
            originationEnd = keyInfo.keyValidityForOriginationEnd,
            consumptionEnd = keyInfo.keyValidityForConsumptionEnd,
            remainingUsageCount = keyInfo.remainingUsageCount,
        )
        DurableAesKeyPolicyValidator.violation(facts, policy)?.let { detail ->
            throw DurableStateStoreException.KeyPolicyViolation(detail)
        }
        return key
    }

    private fun deleteRejectedCreatedKey(error: Exception) {
        try {
            keyStore.deleteEntry(KEY_ALIAS)
        } catch (deleteError: Exception) {
            error.addSuppressed(deleteError)
        }
    }

    private fun requirePhysicalDevice() {
        if (AndroidDeviceEnvironment.isProbablyEmulator()) {
            throw DurableStateStoreException.PhysicalDeviceRequired()
        }
    }

    private companion object {
        const val ANDROID_KEYSTORE = "AndroidKeyStore"
        const val KEY_ALIAS = "eu.advatar.wallet.durable-state.aes-gcm.v1"
        const val AES_GCM_TRANSFORMATION = "AES/GCM/NoPadding"
        const val AES_KEY_BITS = 256
        const val GCM_NONCE_BYTES = 12
        const val GCM_TAG_BYTES = 16
        const val GCM_TAG_BITS = GCM_TAG_BYTES * Byte.SIZE_BITS
        const val SHA256 = "SHA-256"
        const val REQUIRED_PURPOSES =
            KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT
    }
}

internal enum class DurableNodeType {
    REGULAR,
    DIRECTORY,
    SYMLINK,
    OTHER,
}

internal data class DurablePathFacts(
    val type: DurableNodeType,
    val ownerUid: Int,
    val ownerGid: Int,
    val mode: Int,
    val linkCount: Long,
    val device: Long,
    val inode: Long,
    val size: Long,
)

internal object DurablePathPolicy {
    const val PRIVATE_FILE_MODE = 0x180 // 0600
    const val PRIVATE_DIRECTORY_MODE = 0x1c0 // 0700
    private const val PERMISSION_MASK = 0x1ff // 0777
    private const val OWNER_DIRECTORY_ACCESS = 0x1c0 // 0700
    private const val OTHER_WRITE = 0x2 // 0002

    fun validateTrustedParent(
        facts: DurablePathFacts,
        expectedUid: Int,
        expectedGid: Int,
    ): String? {
        if (facts.type != DurableNodeType.DIRECTORY) return "no-backup parent is not a directory"
        if (facts.ownerUid != expectedUid) return "no-backup parent has the wrong owner"
        if (facts.ownerGid != expectedGid) return "no-backup parent has the wrong group"
        if (facts.mode and OWNER_DIRECTORY_ACCESS != OWNER_DIRECTORY_ACCESS) {
            return "no-backup parent denies owner access"
        }
        if (facts.mode and OTHER_WRITE != 0) {
            return "no-backup parent is writable by other users"
        }
        return null
    }

    fun validateRoot(facts: DurablePathFacts, expectedUid: Int): String? {
        if (facts.type != DurableNodeType.DIRECTORY) return "storage root is not a directory"
        if (facts.ownerUid != expectedUid) return "storage root has the wrong owner"
        if (facts.mode and PERMISSION_MASK != PRIVATE_DIRECTORY_MODE) {
            return "storage root permissions are not 0700"
        }
        if (facts.linkCount < 1) return "storage root has an invalid link count"
        return null
    }

    fun validateRegular(facts: DurablePathFacts, expectedUid: Int): String? {
        if (facts.type != DurableNodeType.REGULAR) return "state path is not a regular file"
        if (facts.ownerUid != expectedUid) return "state file has the wrong owner"
        if (facts.mode and PERMISSION_MASK != PRIVATE_FILE_MODE) {
            return "state file permissions are not 0600"
        }
        if (facts.linkCount != 1L) return "state file has multiple hard links"
        if (facts.size < 0) return "state file has a negative size"
        return null
    }
}

internal class AndroidNoBackupDurableStateFileSystem(
    noBackupFilesDir: File,
) : DurableStateFileSystem {
    private val expectedUid = Os.geteuid()
    private val expectedGid = Os.getegid()
    private val parent = noBackupFilesDir.absoluteFile
    private val root = File(parent, ROOT_NAME)
    private val rootIdentity: FileIdentity
    private var lockStream: FileOutputStream? = null
    private var fileLock: java.nio.channels.FileLock? = null

    init {
        if (root.parentFile?.absolutePath != parent.absolutePath) {
            throw DurableStateStoreException.StoragePolicyViolation("invalid no-backup root path")
        }
        rootIdentity = initializeRoot()
    }

    override fun acquireExclusiveLock() {
        storage("acquire lock") {
            if (lockStream != null || fileLock != null) {
                throw DurableStateStoreException.StoragePolicyViolation("lock is already held")
            }
            ensureRootIdentity()
            val lockFile = child(LOCK_FILE)
            var created = false
            val descriptor = try {
                Os.open(
                    lockFile.absolutePath,
                    OsConstants.O_RDWR or OsConstants.O_CREAT or OsConstants.O_EXCL or
                        OsConstants.O_CLOEXEC or OsConstants.O_NOFOLLOW or OsConstants.O_NONBLOCK,
                    DurablePathPolicy.PRIVATE_FILE_MODE,
                ).also { created = true }
            } catch (error: ErrnoException) {
                if (error.errno != OsConstants.EEXIST) throw error
                Os.open(
                    lockFile.absolutePath,
                    OsConstants.O_RDWR or OsConstants.O_CLOEXEC or OsConstants.O_NOFOLLOW or
                        OsConstants.O_NONBLOCK,
                    0,
                )
            }
            try {
                if (created) Os.fchmod(descriptor, DurablePathPolicy.PRIVATE_FILE_MODE)
                validateRegular(Os.fstat(descriptor))
                if (created) {
                    Os.fsync(descriptor)
                    synchronizeRootDirectory()
                }
                val stream = FileOutputStream(descriptor)
                try {
                    val acquiredLock = stream.channel.lock()
                    lockStream = stream
                    fileLock = acquiredLock
                } catch (error: Exception) {
                    stream.close()
                    throw error
                }
            } catch (error: Exception) {
                if (descriptor.valid()) {
                    try {
                        Os.close(descriptor)
                    } catch (_: Exception) {
                        // Preserve the primary validation/lock failure.
                    }
                }
                throw error
            }
            ensureRootIdentity()
        }
    }

    override fun releaseExclusiveLock() {
        val heldLock = fileLock
        val heldStream = lockStream
        fileLock = null
        lockStream = null
        try {
            heldLock?.release()
        } finally {
            heldStream?.close()
        }
    }

    override fun cleanupTemporaryFiles() {
        storage("clean temporary files") {
            ensureRootIdentity()
            var removed = false
            for (name in TEMPORARY_FILES) {
                val file = child(name)
                val facts = lstatOrNull(file) ?: continue
                validateRegular(facts)
                Os.remove(file.absolutePath)
                removed = true
            }
            if (removed) synchronizeRootDirectory()
        }
    }

    override fun hasAnySlot(): Boolean = storage("inspect slots") {
        ensureRootIdentity()
        SLOT_FILES.values.any { name ->
            val facts = lstatOrNull(child(name)) ?: return@any false
            validateRegular(facts)
            true
        }
    }

    override fun readSlot(slot: DurableStateSlot, maximumBytes: Int): ByteArray? =
        readRegular(child(SLOT_FILES.getValue(slot)), maximumBytes)

    override fun readAnchor(maximumBytes: Int): ByteArray? =
        readRegular(child(ANCHOR_FILE), maximumBytes)

    override fun writeSlotDurably(
        slot: DurableStateSlot,
        value: ByteArray,
        faultInjector: DurableStateFaultInjector?,
    ) {
        writeRegularDurably(
            destination = child(SLOT_FILES.getValue(slot)),
            temporary = child(SLOT_TEMP_FILES.getValue(slot)),
            value = value,
            createOnly = false,
            beforeCreate = DurableStateFaultPoint.BEFORE_SLOT_TEMP_CREATE,
            afterCreate = DurableStateFaultPoint.AFTER_SLOT_TEMP_CREATE,
            afterWrite = DurableStateFaultPoint.AFTER_SLOT_TEMP_WRITE,
            afterSync = DurableStateFaultPoint.AFTER_SLOT_TEMP_SYNC,
            afterRename = DurableStateFaultPoint.AFTER_SLOT_RENAME,
            afterDirectorySync = DurableStateFaultPoint.AFTER_SLOT_DIRECTORY_SYNC,
            faultInjector = faultInjector,
        )
    }

    override fun writeAnchorDurably(
        value: ByteArray,
        createOnly: Boolean,
        faultInjector: DurableStateFaultInjector?,
    ) {
        writeRegularDurably(
            destination = child(ANCHOR_FILE),
            temporary = child(ANCHOR_TEMP_FILE),
            value = value,
            createOnly = createOnly,
            beforeCreate = DurableStateFaultPoint.BEFORE_ANCHOR_TEMP_CREATE,
            afterCreate = DurableStateFaultPoint.AFTER_ANCHOR_TEMP_CREATE,
            afterWrite = DurableStateFaultPoint.AFTER_ANCHOR_TEMP_WRITE,
            afterSync = DurableStateFaultPoint.AFTER_ANCHOR_TEMP_SYNC,
            afterRename = DurableStateFaultPoint.AFTER_ANCHOR_RENAME,
            afterDirectorySync = DurableStateFaultPoint.AFTER_ANCHOR_DIRECTORY_SYNC,
            faultInjector = faultInjector,
        )
    }

    private fun initializeRoot(): FileIdentity = storage("initialize no-backup root") {
        val parentDescriptor = Os.open(
            parent.absolutePath,
            OsConstants.O_RDONLY or OsConstants.O_CLOEXEC or OsConstants.O_NOFOLLOW or
                OsConstants.O_NONBLOCK,
            0,
        )
        try {
            val parentFacts = facts(Os.fstat(parentDescriptor))
            DurablePathPolicy.validateTrustedParent(parentFacts, expectedUid, expectedGid)?.let {
                throw DurableStateStoreException.StoragePolicyViolation(it)
            }
            var created = false
            if (lstatOrNull(root) == null) {
                try {
                    Os.mkdir(root.absolutePath, DurablePathPolicy.PRIVATE_DIRECTORY_MODE)
                    created = true
                } catch (error: ErrnoException) {
                    if (error.errno != OsConstants.EEXIST) throw error
                }
            }
            val identity = openAndValidateRoot(applyPrivateMode = created)
            if (created) Os.fsync(parentDescriptor)
            identity
        } finally {
            Os.close(parentDescriptor)
        }
    }

    private fun openAndValidateRoot(applyPrivateMode: Boolean = false): FileIdentity {
        val descriptor = Os.open(
            root.absolutePath,
            OsConstants.O_RDONLY or OsConstants.O_CLOEXEC or OsConstants.O_NOFOLLOW or
                OsConstants.O_NONBLOCK,
            0,
        )
        try {
            if (applyPrivateMode) {
                Os.fchmod(descriptor, DurablePathPolicy.PRIVATE_DIRECTORY_MODE)
            }
            val rootFacts = facts(Os.fstat(descriptor))
            DurablePathPolicy.validateRoot(rootFacts, expectedUid)?.let {
                throw DurableStateStoreException.StoragePolicyViolation(it)
            }
            return FileIdentity(rootFacts.device, rootFacts.inode)
        } finally {
            Os.close(descriptor)
        }
    }

    private fun ensureRootIdentity() {
        val current = openAndValidateRoot()
        if (current != rootIdentity) {
            throw DurableStateStoreException.StoragePolicyViolation(
                "storage root identity changed",
            )
        }
    }

    private fun synchronizeRootDirectory() {
        val descriptor = Os.open(
            root.absolutePath,
            OsConstants.O_RDONLY or OsConstants.O_CLOEXEC or OsConstants.O_NOFOLLOW or
                OsConstants.O_NONBLOCK,
            0,
        )
        try {
            val rootFacts = facts(Os.fstat(descriptor))
            DurablePathPolicy.validateRoot(rootFacts, expectedUid)?.let {
                throw DurableStateStoreException.StoragePolicyViolation(it)
            }
            if (FileIdentity(rootFacts.device, rootFacts.inode) != rootIdentity) {
                throw DurableStateStoreException.StoragePolicyViolation(
                    "storage root identity changed",
                )
            }
            Os.fsync(descriptor)
        } finally {
            Os.close(descriptor)
        }
    }

    private fun readRegular(file: File, maximumBytes: Int): ByteArray? = storage("read ${file.name}") {
        ensureRootIdentity()
        val before = lstatOrNull(file) ?: return@storage null
        validateRegular(before)
        if (before.size > maximumBytes.toLong()) {
            throw DurableStateStoreException.EnvelopeTooLarge(before.size, maximumBytes)
        }
        val descriptor = Os.open(
            file.absolutePath,
            OsConstants.O_RDONLY or OsConstants.O_CLOEXEC or OsConstants.O_NOFOLLOW or
                OsConstants.O_NONBLOCK,
            0,
        )
        try {
            val opened = facts(Os.fstat(descriptor))
            validateRegular(opened)
            if (opened.device != before.device || opened.inode != before.inode) {
                throw DurableStateStoreException.StoragePolicyViolation(
                    "state file identity changed during open",
                )
            }
            if (opened.size > maximumBytes.toLong()) {
                throw DurableStateStoreException.EnvelopeTooLarge(opened.size, maximumBytes)
            }
            val output = ByteArrayOutputStream(minOf(opened.size.toInt(), READ_CHUNK_BYTES))
            val buffer = ByteArray(READ_CHUNK_BYTES)
            while (true) {
                val count = Os.read(descriptor, buffer, 0, buffer.size)
                if (count == 0) break
                if (output.size().toLong() + count.toLong() > maximumBytes.toLong()) {
                    throw DurableStateStoreException.EnvelopeTooLarge(
                        output.size().toLong() + count.toLong(),
                        maximumBytes,
                    )
                }
                output.write(buffer, 0, count)
            }
            output.toByteArray()
        } finally {
            Os.close(descriptor)
        }
    }

    private fun writeRegularDurably(
        destination: File,
        temporary: File,
        value: ByteArray,
        createOnly: Boolean,
        beforeCreate: DurableStateFaultPoint,
        afterCreate: DurableStateFaultPoint,
        afterWrite: DurableStateFaultPoint,
        afterSync: DurableStateFaultPoint,
        afterRename: DurableStateFaultPoint,
        afterDirectorySync: DurableStateFaultPoint,
        faultInjector: DurableStateFaultInjector?,
    ) {
        storage("write ${destination.name}") {
            ensureRootIdentity()
            removeExistingTemporary(temporary)
            val existing = lstatOrNull(destination)
            if (existing != null) {
                validateRegular(existing)
                if (createOnly) throw DurableStateStoreException.AnchorAlreadyExists()
            } else if (!createOnly && destination.name == ANCHOR_FILE) {
                throw DurableStateStoreException.MissingAnchor()
            }

            faultInjector?.hit(beforeCreate)
            var descriptor = Os.open(
                temporary.absolutePath,
                OsConstants.O_WRONLY or OsConstants.O_CREAT or OsConstants.O_EXCL or
                    OsConstants.O_CLOEXEC or OsConstants.O_NOFOLLOW or OsConstants.O_NONBLOCK,
                DurablePathPolicy.PRIVATE_FILE_MODE,
            )
            var temporaryIdentity: FileIdentity? = null
            try {
                Os.fchmod(descriptor, DurablePathPolicy.PRIVATE_FILE_MODE)
                val createdFacts = facts(Os.fstat(descriptor))
                validateRegular(createdFacts)
                temporaryIdentity = FileIdentity(createdFacts.device, createdFacts.inode)
                faultInjector?.hit(afterCreate)
                writeAll(descriptor, value)
                faultInjector?.hit(afterWrite)
                Os.fsync(descriptor)
                faultInjector?.hit(afterSync)
                Os.close(descriptor)
                descriptor = java.io.FileDescriptor()

                ensureRootIdentity()
                val destinationNow = lstatOrNull(destination)
                if (destinationNow != null) {
                    validateRegular(destinationNow)
                    if (createOnly) throw DurableStateStoreException.AnchorAlreadyExists()
                } else if (!createOnly && destination.name == ANCHOR_FILE) {
                    throw DurableStateStoreException.MissingAnchor()
                }
                Os.rename(temporary.absolutePath, destination.absolutePath)
                temporaryIdentity = null
                validateRegular(Os.lstat(destination.absolutePath))
                faultInjector?.hit(afterRename)
                synchronizeRootDirectory()
                faultInjector?.hit(afterDirectorySync)
            } finally {
                if (descriptor.valid()) {
                    try {
                        Os.close(descriptor)
                    } catch (_: Exception) {
                        // Preserve the primary failure.
                    }
                }
                temporaryIdentity?.let { identity ->
                    removeTemporaryIfIdentityMatches(temporary, identity)
                }
            }
        }
    }

    private fun writeAll(descriptor: java.io.FileDescriptor, value: ByteArray) {
        var offset = 0
        while (offset < value.size) {
            val written = Os.write(descriptor, value, offset, value.size - offset)
            if (written <= 0) {
                throw DurableStateStoreException.StorageFailure("write returned no progress")
            }
            offset += written
        }
    }

    private fun removeExistingTemporary(file: File) {
        val facts = lstatOrNull(file) ?: return
        validateRegular(facts)
        Os.remove(file.absolutePath)
        synchronizeRootDirectory()
    }

    private fun removeTemporaryIfIdentityMatches(file: File, identity: FileIdentity) {
        try {
            val facts = lstatOrNull(file) ?: return
            validateRegular(facts)
            if (facts.device == identity.device && facts.inode == identity.inode) {
                Os.remove(file.absolutePath)
                synchronizeRootDirectory()
            }
        } catch (_: Exception) {
            // Cleanup must not hide the original write failure. The next locked operation performs
            // strict deterministic cleanup and will reject a hostile replacement.
        }
    }

    private fun validateRegular(stat: android.system.StructStat) = validateRegular(facts(stat))

    private fun validateRegular(facts: DurablePathFacts) {
        DurablePathPolicy.validateRegular(facts, expectedUid)?.let {
            throw DurableStateStoreException.StoragePolicyViolation(it)
        }
    }

    private fun lstatOrNull(file: File): DurablePathFacts? = try {
        facts(Os.lstat(file.absolutePath))
    } catch (error: ErrnoException) {
        if (error.errno == OsConstants.ENOENT) null else throw error
    }

    private fun facts(stat: android.system.StructStat): DurablePathFacts {
        val typeBits = stat.st_mode and OsConstants.S_IFMT
        val type = when (typeBits) {
            OsConstants.S_IFREG -> DurableNodeType.REGULAR
            OsConstants.S_IFDIR -> DurableNodeType.DIRECTORY
            OsConstants.S_IFLNK -> DurableNodeType.SYMLINK
            else -> DurableNodeType.OTHER
        }
        return DurablePathFacts(
            type = type,
            ownerUid = stat.st_uid,
            ownerGid = stat.st_gid,
            mode = stat.st_mode,
            linkCount = stat.st_nlink,
            device = stat.st_dev,
            inode = stat.st_ino,
            size = stat.st_size,
        )
    }

    private fun child(name: String): File {
        if (name !in ALLOWED_CHILDREN) {
            throw DurableStateStoreException.StoragePolicyViolation("invalid state filename")
        }
        val file = File(root, name)
        if (file.parentFile?.absolutePath != root.absolutePath) {
            throw DurableStateStoreException.StoragePolicyViolation("state path escaped its root")
        }
        return file
    }

    private inline fun <T> storage(operation: String, block: () -> T): T = try {
        block()
    } catch (error: DurableStateStoreException) {
        throw error
    } catch (error: Exception) {
        throw DurableStateStoreException.StorageFailure(operation, error)
    }

    private data class FileIdentity(val device: Long, val inode: Long)

    private companion object {
        const val ROOT_NAME = "eudi-wallet-state-v1"
        const val LOCK_FILE = "state.lock"
        const val ANCHOR_FILE = "anchor.bin"
        const val ANCHOR_TEMP_FILE = ".anchor.tmp"
        const val READ_CHUNK_BYTES = 8 * 1024
        val SLOT_FILES = mapOf(
            DurableStateSlot.A to "slot-a.bin",
            DurableStateSlot.B to "slot-b.bin",
        )
        val SLOT_TEMP_FILES = mapOf(
            DurableStateSlot.A to ".slot-a.tmp",
            DurableStateSlot.B to ".slot-b.tmp",
        )
        val TEMPORARY_FILES = SLOT_TEMP_FILES.values + ANCHOR_TEMP_FILE
        val ALLOWED_CHILDREN = SLOT_FILES.values + TEMPORARY_FILES + ANCHOR_FILE + LOCK_FILE
    }
}
