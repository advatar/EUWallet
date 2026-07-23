package eu.advatar.wallet.shell

import org.json.JSONArray
import org.json.JSONException
import org.json.JSONObject

/**
 * Strict codec for the official AusweisApp 2.5.4 JSON SDK protocol.
 *
 * The Android AIDL transport accepts [CharArray], so encoded commands never require a long-lived
 * immutable String. Callers must clear the returned array immediately after `transmit`.
 */
internal object AusweisAppProtocolCodec {
    private const val MAXIMUM_MESSAGE_CHARS = 64 * 1024
    private const val RESULT_OK =
        "http://www.bsi.bund.de/ecard/api/1.1/resultmajor#ok"

    fun encode(command: GermanEidSdkCommand): CharArray {
        val value = JSONObject()
        when (command) {
            GermanEidSdkCommand.GetApiLevel -> value.put("cmd", "GET_API_LEVEL")
            is GermanEidSdkCommand.SetApiLevel -> {
                value.put("cmd", "SET_API_LEVEL")
                value.put("level", command.level)
            }
            is GermanEidSdkCommand.RunAuth -> {
                value.put("cmd", "RUN_AUTH")
                command.value.tcTokenUrl.consume {
                    value.put("tcTokenURL", it.toString(Charsets.US_ASCII))
                }
                value.put("developerMode", false)
                value.put("status", true)
            }
            is GermanEidSdkCommand.SetAccessRights -> {
                value.put("cmd", "SET_ACCESS_RIGHTS")
                value.put(
                    "chat",
                    JSONArray(command.rights.map { it.wireValue }.sorted()),
                )
            }
            GermanEidSdkCommand.GetCertificate -> value.put("cmd", "GET_CERTIFICATE")
            GermanEidSdkCommand.Accept -> value.put("cmd", "ACCEPT")
            GermanEidSdkCommand.Cancel -> value.put("cmd", "CANCEL")
            GermanEidSdkCommand.InterruptSystemDialog ->
                throw GermanEidClientException(GermanEidClientError.INVALID_TRANSITION)
            GermanEidSdkCommand.ContinueAfterPause -> value.put("cmd", "CONTINUE")
            is GermanEidSdkCommand.SetSecret -> {
                value.put(
                    "cmd",
                    when (command.secret.kind) {
                        GermanEidSecretKind.PIN -> "SET_PIN"
                        GermanEidSecretKind.CAN -> "SET_CAN"
                        GermanEidSecretKind.PUK -> "SET_PUK"
                    },
                )
                command.secret.consume { value.put("value", it.toString(Charsets.US_ASCII)) }
            }
        }
        val encoded = value.toString().toCharArray()
        if (encoded.size > MAXIMUM_MESSAGE_CHARS) {
            encoded.fill('\u0000')
            throw GermanEidClientException(GermanEidClientError.INVALID_CONFIGURATION)
        }
        return encoded
    }

    fun decode(
        message: String,
        contract: GermanEidProviderContract,
        sessionId: GermanEidSessionId,
    ): GermanEidSdkEvent {
        if (message.isEmpty() || message.length > MAXIMUM_MESSAGE_CHARS) {
            throw GermanEidClientException(GermanEidClientError.ADAPTER_FAILURE)
        }
        try {
            val root = JSONObject(message)
            return when (root.requiredString("msg")) {
                "API_LEVEL" -> apiLevel(root)
                "AUTH" -> auth(root, contract, sessionId)
                "ACCESS_RIGHTS" -> accessRights(root)
                "CERTIFICATE" -> certificate(root)
                "READER" -> GermanEidSdkEvent.Reader(reader(root))
                "INSERT_CARD" -> if (root.hasNonNull("error")) {
                    GermanEidSdkEvent.AdapterFailed
                } else {
                    GermanEidSdkEvent.CardRequired
                }
                "PAUSE" -> if (root.requiredString("cause") == "BadCardPosition") {
                    GermanEidSdkEvent.Paused(GermanEidPauseCause.BAD_CARD_POSITION)
                } else {
                    GermanEidSdkEvent.AdapterFailed
                }
                "ENTER_PIN" -> secret(root, GermanEidSecretKind.PIN)
                "ENTER_CAN" -> secret(root, GermanEidSecretKind.CAN)
                "ENTER_PUK" -> secret(root, GermanEidSecretKind.PUK)
                "BAD_STATE", "INTERNAL_ERROR", "INVALID", "UNKNOWN_COMMAND" ->
                    GermanEidSdkEvent.AdapterFailed
                else -> GermanEidSdkEvent.AdapterFailed
            }
        } catch (_: JSONException) {
            throw GermanEidClientException(GermanEidClientError.ADAPTER_FAILURE)
        } catch (_: IllegalArgumentException) {
            throw GermanEidClientException(GermanEidClientError.ADAPTER_FAILURE)
        }
    }

    private fun apiLevel(root: JSONObject): GermanEidSdkEvent {
        if (root.hasNonNull("error")) return GermanEidSdkEvent.AdapterFailed
        val current = root.optInt("current", -1)
        if (current >= 0) return GermanEidSdkEvent.ApiLevelSelected(current)
        val available = root.requiredArray("available").integers()
        return GermanEidSdkEvent.ApiLevels(available)
    }

    private fun auth(
        root: JSONObject,
        contract: GermanEidProviderContract,
        sessionId: GermanEidSessionId,
    ): GermanEidSdkEvent {
        if (root.hasNonNull("error")) return GermanEidSdkEvent.AuthenticationStartFailed
        val result = root.optJSONObject("result")
            ?: return GermanEidSdkEvent.AuthenticationStarted
        val success = result.requiredString("major") == RESULT_OK
        val reason = when (result.optString("reason")) {
            "User_Cancelled" -> GermanEidFailureReason.CANCELLED
            "Card_Removed", "Card_Deactivated", "Card_Inoperative" ->
                GermanEidFailureReason.CARD
            "Communication_Error" -> GermanEidFailureReason.COMMUNICATION
            "Internal_Error" -> GermanEidFailureReason.SDK
            else -> GermanEidFailureReason.UNKNOWN
        }
        val url = root.optString("url").takeIf { it.isNotEmpty() }?.toByteArray(Charsets.US_ASCII)
        return GermanEidSdkEvent.AuthenticationFinished(
            GermanEidAuthenticationResult(
                outcome = if (success) {
                    GermanEidAuthenticationOutcome.Success
                } else {
                    GermanEidAuthenticationOutcome.Failure(reason)
                },
                url = url,
                contract = contract,
                sessionId = sessionId,
            ),
        )
    }

    private fun accessRights(root: JSONObject): GermanEidSdkEvent {
        if (root.hasNonNull("error")) return GermanEidSdkEvent.AdapterFailed
        val chat = root.requiredObject("chat")
        val auxiliary = root.optJSONObject("aux")?.let {
            val values = listOf(
                it.optionalString("ageVerificationDate"),
                it.optionalString("requiredAge"),
                it.optionalString("validityDate"),
                it.optionalString("communityId"),
            )
            if (values.all { value -> value == null }) null else GermanEidAuxiliaryData(
                ageVerificationDate = values[0],
                requiredAge = values[1],
                validityDate = values[2],
                communityId = values[3],
            )
        }
        return GermanEidSdkEvent.AccessRights(
            GermanEidAccessRights(
                required = chat.requiredArray("required").rights(),
                optional = chat.requiredArray("optional").rights(),
                effective = chat.requiredArray("effective").rights(),
                transactionInfo = root.optionalString("transactionInfo"),
                auxiliaryData = auxiliary,
            ),
        )
    }

    private fun certificate(root: JSONObject): GermanEidSdkEvent {
        val description = root.requiredObject("description")
        val validity = root.requiredObject("validity")
        return GermanEidSdkEvent.Certificate(
            GermanEidCertificate(
                issuerName = description.requiredString("issuerName"),
                issuerUrl = description.requiredString("issuerUrl"),
                subjectName = description.requiredString("subjectName"),
                subjectUrl = description.requiredString("subjectUrl"),
                termsOfUsage = description.requiredString("termsOfUsage"),
                purpose = description.requiredString("purpose"),
                effectiveDate = validity.requiredString("effectiveDate"),
                expirationDate = validity.requiredString("expirationDate"),
            ),
        )
    }

    private fun secret(
        root: JSONObject,
        kind: GermanEidSecretKind,
    ): GermanEidSdkEvent = if (root.hasNonNull("error")) {
        GermanEidSdkEvent.AdapterFailed
    } else {
        GermanEidSdkEvent.SecretRequested(kind, reader(root.requiredObject("reader")))
    }

    private fun reader(value: JSONObject): GermanEidReaderState {
        val card = when {
            value.isNull("card") || !value.has("card") -> GermanEidCardState.Absent
            else -> {
                val objectValue = value.requiredObject("card")
                if (objectValue.length() == 0) {
                    GermanEidCardState.Unknown
                } else {
                    GermanEidCardState.Present(
                        retryCounter = objectValue.optInt("retryCounter", -1)
                            .takeIf { it in 0..3 },
                        deactivated = objectValue.optBoolean("deactivated", false),
                        inoperative = objectValue.optBoolean("inoperative", false),
                    )
                }
            }
        }
        val name = value.requiredString("name")
        return GermanEidReaderState(
            kind = if (name == "NFC") {
                GermanEidReaderKind.TRUSTED_PLATFORM_INTEGRATED_NFC
            } else {
                GermanEidReaderKind.UNSUPPORTED_OR_EXTERNAL
            },
            attached = value.requiredBoolean("attached"),
            insertable = value.requiredBoolean("insertable"),
            keypad = value.optBoolean("keypad", false),
            card = card,
        )
    }

    private fun JSONObject.requiredString(name: String): String =
        getString(name).takeIf { it.isNotEmpty() } ?: throw JSONException(name)

    private fun JSONObject.requiredBoolean(name: String): Boolean {
        if (!has(name) || get(name) !is Boolean) throw JSONException(name)
        return getBoolean(name)
    }

    private fun JSONObject.requiredObject(name: String): JSONObject =
        optJSONObject(name) ?: throw JSONException(name)

    private fun JSONObject.requiredArray(name: String): JSONArray =
        optJSONArray(name) ?: throw JSONException(name)

    private fun JSONObject.optionalString(name: String): String? =
        optString(name).takeIf { it.isNotEmpty() }

    private fun JSONObject.hasNonNull(name: String): Boolean = has(name) && !isNull(name)

    private fun JSONArray.integers(): Set<Int> =
        (0 until length()).map { getInt(it) }.toSet()

    private fun JSONArray.rights(): Set<GermanEidAccessRight> =
        (0 until length()).map {
            GermanEidAccessRight.fromWire(getString(it))
                ?: throw JSONException("unknown access right")
        }.toSet()
}
