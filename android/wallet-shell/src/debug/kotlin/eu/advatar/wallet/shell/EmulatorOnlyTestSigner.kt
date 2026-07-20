package eu.advatar.wallet.shell

import java.security.KeyPair
import java.security.KeyPairGenerator
import java.security.Signature
import java.security.spec.ECGenParameterSpec
import java.util.concurrent.ConcurrentHashMap

fun interface EmulatorDetector {
    fun isEmulator(): Boolean
}

class EmulatorOnlySignerException :
    Exception("The debug test signer may only run on an emulator")

/** Explicit software signer compiled into debug artifacts only. */
class EmulatorOnlyTestSigner(
    private val emulatorDetector: EmulatorDetector = EmulatorDetector {
        AndroidDeviceEnvironment.isProbablyEmulator()
    },
) : WalletSigner {
    private val keys = ConcurrentHashMap<String, KeyPair>()

    override fun sign(keyRef: String, payload: ByteArray): ByteArray {
        if (!emulatorDetector.isEmulator()) throw EmulatorOnlySignerException()
        val validatedReference = validatedSigningKeyReference(keyRef)
        val keyPair = keys.computeIfAbsent(validatedReference) {
            KeyPairGenerator.getInstance("EC").apply {
                initialize(ECGenParameterSpec("secp256r1"))
            }.generateKeyPair()
        }
        val signer = Signature.getInstance("SHA256withECDSA")
        signer.initSign(keyPair.private)
        signer.update(payload)
        return EcdsaJoseSignature.fromDer(signer.sign())
    }
}
