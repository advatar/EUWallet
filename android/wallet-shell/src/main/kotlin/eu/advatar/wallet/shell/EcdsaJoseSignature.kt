package eu.advatar.wallet.shell

/** Strict DER ECDSA to ES256 JOSE r||s conversion. */
internal object EcdsaJoseSignature {
    private const val P256_COMPONENT_BYTES = 32

    fun fromDer(der: ByteArray): ByteArray {
        val cursor = DerCursor(der)
        cursor.requireByte(0x30, "ECDSA signature is not a DER sequence")
        val sequenceLength = cursor.readLength()
        if (sequenceLength != cursor.remaining) {
            throw IllegalArgumentException("DER sequence length does not match input")
        }

        val r = cursor.readPositiveInteger(P256_COMPONENT_BYTES)
        val s = cursor.readPositiveInteger(P256_COMPONENT_BYTES)
        if (cursor.remaining != 0) {
            throw IllegalArgumentException("DER signature contains trailing data")
        }
        return r + s
    }

    private class DerCursor(private val bytes: ByteArray) {
        private var offset = 0

        val remaining: Int
            get() = bytes.size - offset

        fun requireByte(expected: Int, message: String) {
            if (readUnsignedByte() != expected) throw IllegalArgumentException(message)
        }

        fun readLength(): Int {
            val first = readUnsignedByte()
            if (first < 0x80) return first

            val octets = first and 0x7f
            if (octets == 0 || octets > 4 || octets > remaining) {
                throw IllegalArgumentException("Invalid DER length")
            }
            if (peekUnsignedByte() == 0) {
                throw IllegalArgumentException("Non-canonical DER length")
            }
            var length = 0
            repeat(octets) {
                val next = readUnsignedByte()
                if (length > (Int.MAX_VALUE ushr 8)) {
                    throw IllegalArgumentException("DER length overflows Int")
                }
                length = (length shl 8) or next
            }
            if (length < 0x80) throw IllegalArgumentException("Non-canonical DER length")
            return length
        }

        fun readPositiveInteger(width: Int): ByteArray {
            requireByte(0x02, "DER signature component is not an integer")
            val length = readLength()
            if (length == 0 || length > remaining) {
                throw IllegalArgumentException("Invalid DER integer length")
            }

            val encoded = bytes.copyOfRange(offset, offset + length)
            offset += length
            if ((encoded[0].toInt() and 0x80) != 0) {
                throw IllegalArgumentException("DER signature component is negative")
            }
            if (
                encoded.size > 1 &&
                encoded[0] == 0.toByte() &&
                (encoded[1].toInt() and 0x80) == 0
            ) {
                throw IllegalArgumentException("DER signature component has redundant padding")
            }

            val magnitude = if (encoded.size > 1 && encoded[0] == 0.toByte()) {
                encoded.copyOfRange(1, encoded.size)
            } else {
                encoded
            }
            if (magnitude.size > width) {
                throw IllegalArgumentException("DER signature component exceeds P-256 width")
            }
            return ByteArray(width - magnitude.size) + magnitude
        }

        private fun peekUnsignedByte(): Int {
            if (remaining == 0) throw IllegalArgumentException("Truncated DER input")
            return bytes[offset].toInt() and 0xff
        }

        private fun readUnsignedByte(): Int {
            val value = peekUnsignedByte()
            offset += 1
            return value
        }
    }
}
