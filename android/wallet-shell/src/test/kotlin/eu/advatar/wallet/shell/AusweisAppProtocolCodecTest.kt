package eu.advatar.wallet.shell

import org.json.JSONObject
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertThrows
import org.junit.Test

class AusweisAppProtocolCodecTest {
    @Test
    fun commandsUseExactOfficialVocabularyAndProductionFlags() {
        val api = encoded(GermanEidSdkCommand.GetApiLevel)
        assertEquals("GET_API_LEVEL", api.getString("cmd"))

        val level = encoded(GermanEidSdkCommand.SetApiLevel(3))
        assertEquals("SET_API_LEVEL", level.getString("cmd"))
        assertEquals(3, level.getInt("level"))

        val rights = encoded(
            GermanEidSdkCommand.SetAccessRights(
                setOf(GermanEidAccessRight.NATIONALITY, GermanEidAccessRight.FAMILY_NAME),
            ),
        )
        assertEquals("SET_ACCESS_RIGHTS", rights.getString("cmd"))
        assertEquals(
            listOf("FamilyName", "Nationality"),
            (0 until rights.getJSONArray("chat").length()).map {
                rights.getJSONArray("chat").getString(it)
            },
        )
        assertFalse(rights.has("header"))
    }

    @Test
    fun unsupportedLocalInterruptAndMalformedMessagesFailClosed() {
        val error = assertThrows(GermanEidClientException::class.java) {
            AusweisAppProtocolCodec.encode(GermanEidSdkCommand.InterruptSystemDialog)
        }
        assertEquals(GermanEidClientError.INVALID_TRANSITION, error.reason)

        val contract = GermanEidProviderContract(
            tcTokenOrigin = "https://issuer.example",
            refreshOrigin = "https://issuer.example",
            expectedSubjectName = "Issuer",
            expectedSubjectOrigin = "https://issuer.example",
            requiredRights = setOf(GermanEidAccessRight.FAMILY_NAME),
        )
        val malformed = assertThrows(GermanEidClientException::class.java) {
            AusweisAppProtocolCodec.decode(
                """{"msg":"API_LEVEL","available":["three"]}""",
                contract,
                GermanEidSessionId(ByteArray(32) { 7 }),
            )
        }
        assertEquals(GermanEidClientError.ADAPTER_FAILURE, malformed.reason)
    }

    private fun encoded(command: GermanEidSdkCommand): JSONObject {
        val chars = AusweisAppProtocolCodec.encode(command)
        return try {
            JSONObject(String(chars))
        } finally {
            chars.fill('\u0000')
        }
    }
}
