package eu.advatar.wallet.shell

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertThrows
import org.junit.Test

class EmulatorOnlyTestSignerTest {
    @Test
    fun signsOnlyWhenExplicitDetectorReportsEmulator() {
        val signer = EmulatorOnlyTestSigner(EmulatorDetector { true })

        val signature = signer.sign("test-key", "payload".encodeToByteArray())

        assertEquals(64, signature.size)
        assertFalse(signature.all { it == 0.toByte() })
    }

    @Test
    fun rejectsPhysicalDeviceAndInvalidReferences() {
        val physical = EmulatorOnlyTestSigner(EmulatorDetector { false })
        assertThrows(EmulatorOnlySignerException::class.java) {
            physical.sign("test-key", byteArrayOf(1))
        }

        val emulator = EmulatorOnlyTestSigner(EmulatorDetector { true })
        assertThrows(IllegalArgumentException::class.java) {
            emulator.sign("../invalid key", byteArrayOf(1))
        }
    }
}
