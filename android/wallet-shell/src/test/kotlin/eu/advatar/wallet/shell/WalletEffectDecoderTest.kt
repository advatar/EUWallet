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
                {"type":"resolveRpTrust","operationId":1,"clientId":"https://rp.example"},
                {"type":"persistNonce","operationId":2,"nonce":18446744073709551615},
                {"type":"render","operationId":3,"authorizationHash":[0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0],"screen":{"screen":"consent","rpDisplayName":"RP","purpose":"Age","requestedClaims":["age_over_18"],"notSharedClaims":["family_name"],"verifierRegistration":"registered","trustMark":"eudiWallet","retention":{"policy":"days","days":30},"overAsk":{"result":"withinRegisteredScope"}}},
                {"type":"sign","operationId":4,"keyRef":"device","payload":[0,127,255]},
                {"type":"http","operationId":5,"resultType":"presentationDelivered","profile":"openid4vpDirectPost","url":"https://rp.example/cb","body":[1]},
                {"type":"pushPar","operationId":6},
                {"type":"openAuthBrowser","operationId":7},
                {"type":"promptTxCode","operationId":8},
                {"type":"requestToken","operationId":9},
                {"type":"requestCredential","operationId":10,"proofJwt":[2]},
                {"type":"fetchStatusList","operationId":11,"uri":"https://status.example/list"},
                {"type":"publishTransferOffer","operationId":12,"offeredKey":[3]},
                {"type":"close"}
            ]""".trimIndent(),
        )

        assertEquals(13, effects.size)
        assertEquals(ULong.MAX_VALUE, (effects[1] as WalletEffect.PersistNonce).nonce)
        val screen = (effects[2] as WalletEffect.Render).screen as WalletScreen.Consent
        assertEquals("RP", screen.relyingPartyName)
        assertEquals(listOf("age_over_18"), screen.requestedClaims)
        assertEquals(listOf("family_name"), screen.notSharedClaims)
        assertEquals(WalletScreen.VerifierRegistration.REGISTERED, screen.verifierRegistration)
        assertEquals(WalletScreen.VerifierTrustMark.EUDI_WALLET, screen.trustMark)
        assertEquals(30.toUShort(), screen.retention.days)
        assertEquals(3L, (effects[2] as WalletEffect.Render).operationId)
        assertEquals(32, (effects[2] as WalletEffect.Render).authorizationHash?.size)
        assertArrayEquals(byteArrayOf(0, 127, -1), (effects[3] as WalletEffect.Sign).payload)
        assertEquals(
            "https://status.example/list",
            (effects[10] as WalletEffect.FetchStatusList).uri,
        )
        assertTrue(effects.last() is WalletEffect.Close)
    }

    @Test
    fun decodesClosedScreenVocabulary() {
        val effects = WalletEffectDecoder.decodeCoreOutput(
            """[
                {"type":"render","screen":{"screen":"loading"}},
                {"type":"render","screen":{"screen":"error","code":"E1","message":"No"}},
                {"type":"render","operationId":20,"authorizationHash":[0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0],"screen":{"screen":"paymentConfirmation","creditorName":"Shop","creditorAccount":"DE89","amountMinor":18446744073709551615,"currency":"EUR"}},
                {"type":"render","operationId":21,"authorizationHash":[0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0],"screen":{"screen":"signConfirmation","documentName":"Contract","qtspId":"qtsp","documentHashHex":"ab"}},
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
            "[{\"type\":\"sign\",\"operationId\":9223372036854775808,\"keyRef\":\"k\",\"payload\":[1]}]",
            "[{\"type\":\"http\",\"operationId\":1,\"resultType\":\"wrong\",\"url\":\"https://rp\",\"body\":[]}]",
            "[{\"type\":\"http\",\"operationId\":1,\"resultType\":\"presentationDelivered\",\"profile\":\"paymentAuthorization\",\"url\":\"https://rp\",\"body\":[]}]",
            "[{\"type\":\"http\",\"operationId\":1,\"resultType\":\"presentationDelivered\",\"profile\":\"futureProfile\",\"url\":\"https://rp\",\"body\":[]}]",
            "[{\"type\":\"render\",\"operationId\":1,\"screen\":{\"screen\":\"consent\",\"rpDisplayName\":\"RP\",\"purpose\":\"Age\",\"requestedClaims\":[],\"notSharedClaims\":[],\"verifierRegistration\":\"certificateValidated\",\"trustMark\":null,\"retention\":{\"policy\":\"unspecified\"},\"overAsk\":{\"result\":\"registrationScopeUnavailable\"}}}]",
        ).forEach { output ->
            assertThrows(WalletShellException.MalformedCoreOutput::class.java) {
                WalletEffectDecoder.decodeCoreOutput(output)
            }
        }
    }
}
