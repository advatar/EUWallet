package eu.advatar.wallet.shell

import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Test

class WalletEffectDecoderTest {
    @Test
    fun decodesEveryEffectAndFullUInt64Values() {
        val effects = WalletEffectDecoder.decodeCoreOutput(
            """[
                {"type":"resolveRpTrust","clientId":"https://rp.example"},
                {"type":"persistNonce","nonce":18446744073709551615},
                {"type":"render","screen":{"screen":"consent","rpDisplayName":"RP","purpose":"Age","requestedClaims":["age_over_18"]}},
                {"type":"sign","keyRef":"device","payload":[0,127,255]},
                {"type":"http","url":"https://rp.example/cb","body":[1]},
                {"type":"pushPar"},
                {"type":"openAuthBrowser"},
                {"type":"promptTxCode"},
                {"type":"requestToken"},
                {"type":"requestCredential","proofJwt":[2]},
                {"type":"publishTransferOffer","offeredKey":[3]},
                {"type":"close"}
            ]""".trimIndent(),
        )

        assertEquals(12, effects.size)
        assertEquals(ULong.MAX_VALUE, (effects[1] as WalletEffect.PersistNonce).nonce)
        val screen = (effects[2] as WalletEffect.Render).screen as WalletScreen.Consent
        assertEquals("RP", screen.relyingPartyName)
        assertEquals(listOf("age_over_18"), screen.requestedClaims)
        assertArrayEquals(byteArrayOf(0, 127, -1), (effects[3] as WalletEffect.Sign).payload)
        assertTrue(effects.last() is WalletEffect.Close)
    }

    @Test
    fun decodesClosedScreenVocabulary() {
        val effects = WalletEffectDecoder.decodeCoreOutput(
            """[
                {"type":"render","screen":{"screen":"loading"}},
                {"type":"render","screen":{"screen":"error","code":"E1","message":"No"}},
                {"type":"render","screen":{"screen":"paymentConfirmation","creditorName":"Shop","creditorAccount":"DE89","amountMinor":18446744073709551615,"currency":"EUR"}},
                {"type":"render","screen":{"screen":"signConfirmation","documentName":"Contract","qtspId":"qtsp","documentHashHex":"ab"}},
                {"type":"render","screen":{"screen":"credentialList"}},
                {"type":"render","screen":{"screen":"credentialDetail"}},
                {"type":"render","screen":{"screen":"issuanceOffer"}},
                {"type":"render","screen":{"screen":"presentQr"}},
                {"type":"render","screen":{"screen":"scanQr"}},
                {"type":"render","screen":{"screen":"authPrompt"}},
                {"type":"render","screen":{"screen":"transactionHistory"}}
            ]""".trimIndent(),
        )

        val payment = (effects[2] as WalletEffect.Render).screen as
            WalletScreen.PaymentConfirmation
        assertEquals(ULong.MAX_VALUE, payment.amountMinor)
        assertTrue((effects[3] as WalletEffect.Render).screen is WalletScreen.SignConfirmation)
        assertTrue((effects.last() as WalletEffect.Render).screen is WalletScreen.TransactionHistory)
    }

    @Test
    fun distinguishesCoreRejectionFromMalformedOutput() {
        val rejected = assertThrows(WalletShellException.CoreRejected::class.java) {
            WalletEffectDecoder.decodeCoreOutput("{\"error\":\"bad event\"}")
        }
        assertEquals("bad event", rejected.detail)

        listOf(
            "{\"error\":\"bad\",\"extra\":true}",
            "{\"error\":7}",
            "not-json",
            "[] trailing",
            "null",
        ).forEach { output ->
            assertThrows(WalletShellException.MalformedCoreOutput::class.java) {
                WalletEffectDecoder.decodeCoreOutput(output)
            }
        }
    }

    @Test
    fun rejectsUnknownContractVariantsAndInvalidScalarTypes() {
        listOf(
            "[{\"type\":\"futureEffect\"}]",
            "[{\"type\":\"render\",\"screen\":{\"screen\":\"futureScreen\"}}]",
            "[{\"type\":\"persistNonce\",\"nonce\":-1}]",
            "[{\"type\":\"persistNonce\",\"nonce\":1.0}]",
            "[{\"type\":\"persistNonce\",\"nonce\":\"1\"}]",
            "[{\"type\":\"sign\",\"keyRef\":\"k\",\"payload\":[-1]}]",
            "[{\"type\":\"sign\",\"keyRef\":\"k\",\"payload\":[256]}]",
            "[{\"type\":\"sign\",\"keyRef\":\"k\",\"payload\":[1.0]}]",
        ).forEach { output ->
            assertThrows(WalletShellException.MalformedCoreOutput::class.java) {
                WalletEffectDecoder.decodeCoreOutput(output)
            }
        }
    }
}
