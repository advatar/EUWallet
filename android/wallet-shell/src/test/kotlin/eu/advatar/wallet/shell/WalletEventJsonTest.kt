package eu.advatar.wallet.shell

import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Test

class WalletEventJsonTest {
    @Test
    fun emitsFullUInt64AsJsonNumberRatherThanString() {
        val root = parse(WalletEventJson.tokenReceived(7, TokenResult(true, ULong.MAX_VALUE)))
        val nonce = root["cNonce"] as JsonPrimitive

        assertFalse(nonce.isString)
        assertEquals(ULong.MAX_VALUE.toString(), nonce.content)
    }

    @Test
    fun approvalEchoesOperationAndAuthorizationHash() {
        val hash = ByteArray(32) { it.toByte() }
        val root = parse(WalletEventJson.userConsented(42, hash))

        assertEquals("42", (root["operationId"] as JsonPrimitive).content)
        val emitted = root["authorizationHash"] as JsonArray
        assertEquals((0..31).map(Int::toString), emitted.map { (it as JsonPrimitive).content })
    }

    @Test
    fun escapesStringsAndEmitsUnsignedBytes() {
        val root = parse(
            WalletEventJson.credentialOfferReceived(
                offer = byteArrayOf(-1),
                issuerCertificateChain = listOf(byteArrayOf(0, -128)),
                issuerId = "issuer\"\\line\n",
            ),
        )

        assertEquals("issuer\"\\line\n", (root["issuerId"] as JsonPrimitive).content)
        assertEquals("255", ((root["offer"] as JsonArray)[0] as JsonPrimitive).content)
        val chain = root["issuerCertChain"] as JsonArray
        val certificate = chain[0] as JsonArray
        assertEquals(listOf("0", "128"), certificate.map { (it as JsonPrimitive).content })
    }

    @Test
    fun mirrorsWalletTransferFieldNames() {
        val root = parse(
            WalletEventJson.walletTransferReceived(
                credential = byteArrayOf(1),
                issuerCertificateChain = listOf(byteArrayOf(2)),
                senderPublicKey = byteArrayOf(3),
                senderSignature = byteArrayOf(4),
                senderConsentHash = byteArrayOf(5),
                nonce = 6u,
            ),
        )

        assertEquals("walletTransferReceived", (root["type"] as JsonPrimitive).content)
        assertEquals(
            setOf(
                "type",
                "credential",
                "issuerCertChain",
                "senderPublicKey",
                "senderSignature",
                "senderConsentHash",
                "nonce",
            ),
            root.keys,
        )
    }

    private fun parse(value: String): JsonObject = Json.parseToJsonElement(value) as JsonObject
}
