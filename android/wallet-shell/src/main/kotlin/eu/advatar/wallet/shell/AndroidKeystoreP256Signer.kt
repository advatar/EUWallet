package eu.advatar.wallet.shell

import android.content.Context
import android.content.pm.PackageManager
import android.os.Build
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyInfo
import android.security.keystore.KeyProperties
import android.security.keystore.StrongBoxUnavailableException
import java.security.KeyFactory
import java.security.KeyPairGenerator
import java.security.KeyStore
import java.security.PrivateKey
import java.security.ProviderException
import java.security.Signature
import java.security.spec.ECGenParameterSpec
import java.util.Locale

/**
 * Explicit production policy. StrongBox is always preferred; a TEE key is accepted only when
 * [allowTrustedEnvironment] is deliberately enabled by the integrating application.
 */
data class HardwareKeyPolicy(
    val allowTrustedEnvironment: Boolean = false,
    val authenticationValiditySeconds: Int = 30,
    val authenticationTypes: Int =
        KeyProperties.AUTH_BIOMETRIC_STRONG or KeyProperties.AUTH_DEVICE_CREDENTIAL,
) {
    init {
        require(authenticationValiditySeconds >= 0) {
            "authenticationValiditySeconds must not be negative"
        }
        require(authenticationTypes != 0) { "authenticationTypes must not be empty" }
        require(
            (authenticationTypes and ALLOWED_AUTHENTICATION_TYPES) == authenticationTypes,
        ) {
            "authenticationTypes may contain only biometric-strong or device-credential"
        }
    }

    internal fun violation(facts: HardwareKeyFacts): String? {
        when (facts.securityLevel) {
            HardwareSecurityLevel.STRONGBOX -> Unit
            HardwareSecurityLevel.TRUSTED_ENVIRONMENT -> {
                if (!allowTrustedEnvironment) return "TEE use was not explicitly allowed"
            }
            HardwareSecurityLevel.SOFTWARE -> return "key is software-backed"
            HardwareSecurityLevel.UNKNOWN -> return "key security level is not provable"
        }
        if (facts.algorithm != KeyProperties.KEY_ALGORITHM_EC) return "key is not elliptic-curve"
        if (facts.keySize != 256) return "key is not P-256"
        if (!facts.originGenerated) return "key was not generated in Android Keystore"
        if (facts.purposes != KeyProperties.PURPOSE_SIGN) return "key is not signing-only"
        if (facts.digests != setOf(KeyProperties.DIGEST_SHA256)) {
            return "key is not restricted to SHA-256"
        }
        if (facts.extractable) return "private key is extractable"
        if (!facts.userAuthenticationRequired) return "user authentication is not required"
        if (!facts.authenticationEnforcedBySecureHardware) {
            return "user authentication is not enforced by secure hardware"
        }
        if (facts.authenticationValiditySeconds != authenticationValiditySeconds) {
            return "user-authentication validity does not match policy"
        }
        if (facts.authenticationTypes != authenticationTypes) {
            return "user-authentication types do not match policy"
        }
        return null
    }

    private companion object {
        const val ALLOWED_AUTHENTICATION_TYPES =
            KeyProperties.AUTH_BIOMETRIC_STRONG or KeyProperties.AUTH_DEVICE_CREDENTIAL
    }
}

internal enum class HardwareSecurityLevel {
    SOFTWARE,
    TRUSTED_ENVIRONMENT,
    STRONGBOX,
    UNKNOWN,
}

internal data class HardwareKeyFacts(
    val securityLevel: HardwareSecurityLevel,
    val algorithm: String,
    val keySize: Int,
    val originGenerated: Boolean,
    val purposes: Int,
    val digests: Set<String>,
    val extractable: Boolean,
    val userAuthenticationRequired: Boolean,
    val authenticationEnforcedBySecureHardware: Boolean,
    val authenticationValiditySeconds: Int,
    val authenticationTypes: Int,
)

sealed class AndroidKeystoreSignerException(message: String, cause: Throwable? = null) :
    Exception(message, cause) {
    class PhysicalDeviceRequired :
        AndroidKeystoreSignerException("Production signing is unavailable on an emulator")

    class StrongBoxRequired(cause: Throwable? = null) :
        AndroidKeystoreSignerException(
            "StrongBox is unavailable and TEE use was not explicitly allowed",
            cause,
        )

    class KeyAccessFailed(cause: Throwable) :
        AndroidKeystoreSignerException("Could not access the Android Keystore key", cause)

    class KeyCreationFailed(cause: Throwable) :
        AndroidKeystoreSignerException("Could not create the Android Keystore key", cause)

    class PolicyViolation(val detail: String) :
        AndroidKeystoreSignerException("Android Keystore policy violation: $detail")

    class SigningFailed(cause: Throwable) :
        AndroidKeystoreSignerException("Android Keystore signing failed", cause)
}

/**
 * P-256 ES256 signer for physical devices. It never creates or accepts a software key and returns
 * JOSE fixed-width r||s signatures, matching the wallet core rather than Java's DER encoding.
 */
class AndroidKeystoreP256Signer(
    context: Context,
    private val policy: HardwareKeyPolicy = HardwareKeyPolicy(),
) : WalletSigner {
    private val applicationContext = context.applicationContext
    private val lock = Any()
    private val keyStore: KeyStore by lazy(LazyThreadSafetyMode.SYNCHRONIZED) {
        try {
            KeyStore.getInstance(ANDROID_KEYSTORE).apply { load(null) }
        } catch (error: Exception) {
            throw AndroidKeystoreSignerException.KeyAccessFailed(error)
        }
    }

    override fun sign(keyRef: String, payload: ByteArray): ByteArray {
        if (AndroidDeviceEnvironment.isProbablyEmulator()) {
            throw AndroidKeystoreSignerException.PhysicalDeviceRequired()
        }
        return synchronized(lock) {
            val key = loadOrCreate(androidKeystoreAlias(keyRef))
            try {
                val signer = Signature.getInstance(ES256_JCA_SIGNATURE)
                signer.initSign(key)
                signer.update(payload)
                EcdsaJoseSignature.fromDer(signer.sign())
            } catch (error: AndroidKeystoreSignerException) {
                throw error
            } catch (error: Exception) {
                throw AndroidKeystoreSignerException.SigningFailed(error)
            }
        }
    }

    private fun loadOrCreate(alias: String): PrivateKey {
        try {
            if (keyStore.containsAlias(alias)) {
                val existing = keyStore.getKey(alias, null) as? PrivateKey
                    ?: throw AndroidKeystoreSignerException.PolicyViolation(
                        "existing alias is not a private key",
                    )
                verifyPolicy(existing)
                return existing
            }
        } catch (error: AndroidKeystoreSignerException) {
            throw error
        } catch (error: Exception) {
            throw AndroidKeystoreSignerException.KeyAccessFailed(error)
        }

        val strongBoxAvailable = applicationContext.packageManager.hasSystemFeature(
            PackageManager.FEATURE_STRONGBOX_KEYSTORE,
        )
        if (strongBoxAvailable) {
            try {
                return createAndVerify(alias, strongBox = true)
            } catch (error: StrongBoxUnavailableException) {
                if (!policy.allowTrustedEnvironment) {
                    throw AndroidKeystoreSignerException.StrongBoxRequired(error)
                }
            } catch (error: ProviderException) {
                throw AndroidKeystoreSignerException.KeyCreationFailed(error)
            }
        } else if (!policy.allowTrustedEnvironment) {
            throw AndroidKeystoreSignerException.StrongBoxRequired()
        }

        return try {
            createAndVerify(alias, strongBox = false)
        } catch (error: ProviderException) {
            throw AndroidKeystoreSignerException.KeyCreationFailed(error)
        }
    }

    private fun createAndVerify(alias: String, strongBox: Boolean): PrivateKey {
        val key = try {
            val builder = KeyGenParameterSpec.Builder(alias, KeyProperties.PURPOSE_SIGN)
                .setAlgorithmParameterSpec(ECGenParameterSpec(P256_CURVE))
                .setDigests(KeyProperties.DIGEST_SHA256)
                .setUserAuthenticationRequired(true)
                .setIsStrongBoxBacked(strongBox)
            builder.setUserAuthenticationParameters(
                policy.authenticationValiditySeconds,
                policy.authenticationTypes,
            )

            val generator = KeyPairGenerator.getInstance(
                KeyProperties.KEY_ALGORITHM_EC,
                ANDROID_KEYSTORE,
            )
            generator.initialize(builder.build())
            generator.generateKeyPair().private
        } catch (error: StrongBoxUnavailableException) {
            throw error
        } catch (error: ProviderException) {
            throw error
        } catch (error: Exception) {
            throw AndroidKeystoreSignerException.KeyCreationFailed(error)
        }

        try {
            verifyPolicy(key)
            return key
        } catch (error: Exception) {
            try {
                keyStore.deleteEntry(alias)
            } catch (deleteError: Exception) {
                error.addSuppressed(deleteError)
            }
            throw error
        }
    }

    private fun verifyPolicy(key: PrivateKey) {
        val keyInfo = try {
            KeyFactory.getInstance(key.algorithm, ANDROID_KEYSTORE)
                .getKeySpec(key, KeyInfo::class.java)
        } catch (error: Exception) {
            throw AndroidKeystoreSignerException.KeyAccessFailed(error)
        }
        val facts = HardwareKeyFacts(
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
            digests = keyInfo.digests.toSet(),
            extractable = key.encoded != null,
            userAuthenticationRequired = keyInfo.isUserAuthenticationRequired,
            authenticationEnforcedBySecureHardware =
                keyInfo.isUserAuthenticationRequirementEnforcedBySecureHardware,
            authenticationValiditySeconds = keyInfo.userAuthenticationValidityDurationSeconds,
            authenticationTypes = keyInfo.userAuthenticationType,
        )
        policy.violation(facts)?.let { detail ->
            throw AndroidKeystoreSignerException.PolicyViolation(detail)
        }
    }

    private companion object {
        const val ANDROID_KEYSTORE = "AndroidKeyStore"
        const val P256_CURVE = "secp256r1"
        const val ES256_JCA_SIGNATURE = "SHA256withECDSA"
    }
}

internal object AndroidDeviceEnvironment {
    fun isProbablyEmulator(): Boolean {
        val fingerprint = Build.FINGERPRINT.lowercase(Locale.ROOT)
        val model = Build.MODEL.lowercase(Locale.ROOT)
        val manufacturer = Build.MANUFACTURER.lowercase(Locale.ROOT)
        val brand = Build.BRAND.lowercase(Locale.ROOT)
        val device = Build.DEVICE.lowercase(Locale.ROOT)
        val product = Build.PRODUCT.lowercase(Locale.ROOT)
        val hardware = Build.HARDWARE.lowercase(Locale.ROOT)
        return fingerprint.startsWith("generic") ||
            fingerprint.contains("emulator") ||
            model.contains("emulator") ||
            model.contains("android sdk built for") ||
            manufacturer.contains("genymotion") ||
            (brand.startsWith("generic") && device.startsWith("generic")) ||
            product.contains("sdk_gphone") ||
            hardware.contains("goldfish") ||
            hardware.contains("ranchu")
    }
}
