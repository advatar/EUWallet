package eu.advatar.wallet.shell

import android.security.keystore.KeyProperties
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Test

class HardwareKeyPolicyTest {
    @Test
    fun strongBoxSatisfiesDefaultPolicy() {
        assertNull(HardwareKeyPolicy().violation(approvedFacts()))
    }

    @Test
    fun teeRequiresExplicitPolicy() {
        val tee = approvedFacts().copy(securityLevel = HardwareSecurityLevel.TRUSTED_ENVIRONMENT)

        assertEquals("TEE use was not explicitly allowed", HardwareKeyPolicy().violation(tee))
        assertNull(HardwareKeyPolicy(allowTrustedEnvironment = true).violation(tee))
    }

    @Test
    fun softwareAndUnknownLevelsAlwaysFail() {
        val policy = HardwareKeyPolicy(allowTrustedEnvironment = true)

        assertEquals(
            "key is software-backed",
            policy.violation(approvedFacts().copy(securityLevel = HardwareSecurityLevel.SOFTWARE)),
        )
        assertEquals(
            "key security level is not provable",
            policy.violation(approvedFacts().copy(securityLevel = HardwareSecurityLevel.UNKNOWN)),
        )
    }

    @Test
    fun rejectsExtractableOrOverAuthorizedKeys() {
        val policy = HardwareKeyPolicy()

        assertEquals("private key is extractable", policy.violation(approvedFacts().copy(extractable = true)))
        assertEquals(
            "key is not signing-only",
            policy.violation(
                approvedFacts().copy(
                    purposes = KeyProperties.PURPOSE_SIGN or KeyProperties.PURPOSE_VERIFY,
                ),
            ),
        )
    }

    @Test
    fun verifiesHardwareEnforcedAuthenticationConfiguration() {
        val policy = HardwareKeyPolicy()

        assertEquals(
            "user authentication is not enforced by secure hardware",
            policy.violation(
                approvedFacts().copy(authenticationEnforcedBySecureHardware = false),
            ),
        )
        assertTrue(
            policy.violation(approvedFacts().copy(authenticationValiditySeconds = 5))
                ?.contains("validity") == true,
        )
    }

    @Test
    fun disallowsEmptyOrUnapprovedAuthenticationTypes() {
        assertThrows(IllegalArgumentException::class.java) {
            HardwareKeyPolicy(authenticationTypes = 0)
        }
        assertThrows(IllegalArgumentException::class.java) {
            HardwareKeyPolicy(authenticationTypes = 1 shl 8)
        }
    }

    private fun approvedFacts(): HardwareKeyFacts = HardwareKeyFacts(
        securityLevel = HardwareSecurityLevel.STRONGBOX,
        algorithm = KeyProperties.KEY_ALGORITHM_EC,
        keySize = 256,
        originGenerated = true,
        purposes = KeyProperties.PURPOSE_SIGN,
        digests = setOf(KeyProperties.DIGEST_SHA256),
        extractable = false,
        userAuthenticationRequired = true,
        authenticationEnforcedBySecureHardware = true,
        authenticationValiditySeconds = 30,
        authenticationTypes =
            KeyProperties.AUTH_BIOMETRIC_STRONG or KeyProperties.AUTH_DEVICE_CREDENTIAL,
    )
}
