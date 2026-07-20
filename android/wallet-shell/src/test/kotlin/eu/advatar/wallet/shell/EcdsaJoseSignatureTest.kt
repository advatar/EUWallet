package eu.advatar.wallet.shell

import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertThrows
import org.junit.Test

class EcdsaJoseSignatureTest {
    @Test
    fun convertsDerIntegersToFixedWidthJoseSignature() {
        val converted = EcdsaJoseSignature.fromDer(
            byteArrayOf(0x30, 0x06, 0x02, 0x01, 0x01, 0x02, 0x01, 0x02),
        )

        assertEquals(64, converted.size)
        assertArrayEquals(ByteArray(31) + byteArrayOf(1), converted.copyOfRange(0, 32))
        assertArrayEquals(ByteArray(31) + byteArrayOf(2), converted.copyOfRange(32, 64))
    }

    @Test
    fun acceptsRequiredPositiveSignPadding() {
        val converted = EcdsaJoseSignature.fromDer(
            byteArrayOf(0x30, 0x07, 0x02, 0x02, 0x00, -0x80, 0x02, 0x01, 0x01),
        )

        assertEquals(-0x80, converted[31].toInt())
    }

    @Test
    fun rejectsMalformedOrNonCanonicalDer() {
        listOf(
            byteArrayOf(),
            byteArrayOf(0x31, 0x00),
            byteArrayOf(0x30, 0x07, 0x02, 0x02, 0x00, 0x01, 0x02, 0x01, 0x01),
            byteArrayOf(0x30, 0x06, 0x02, 0x01, -0x01, 0x02, 0x01, 0x01),
            byteArrayOf(0x30, 0x07, 0x02, 0x01, 0x01, 0x02, 0x01, 0x01, 0x00),
        ).forEach { der ->
            assertThrows(IllegalArgumentException::class.java) {
                EcdsaJoseSignature.fromDer(der)
            }
        }
    }
}
