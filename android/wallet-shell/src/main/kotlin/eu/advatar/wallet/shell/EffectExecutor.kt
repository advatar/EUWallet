package eu.advatar.wallet.shell

import java.util.ArrayDeque
import org.json.JSONObject

sealed interface EffectAbortReason {
    data class CoreError(val code: String, val message: String) : EffectAbortReason

    data object ClosedWithoutSuccess : EffectAbortReason

    data object MissingTerminalOutcome : EffectAbortReason

    data object EffectAfterClose : EffectAbortReason
}

sealed interface EffectCascadeOutcome {
    data object Idle : EffectCascadeOutcome

    data object AwaitingInput : EffectCascadeOutcome

    data object Succeeded : EffectCascadeOutcome

    data object Declined : EffectCascadeOutcome

    data class Aborted(val reason: EffectAbortReason) : EffectCascadeOutcome
}

/**
 * Drains the sans-I/O core's effect cascade. Infrastructure failures stop the cascade and are
 * never translated into semantic decline or success events.
 */
class EffectExecutor(
    private val engine: WalletEngineDriving,
    private val signer: WalletSigner,
    private val httpClient: WalletHttpClient,
    private val storage: WalletStorage,
    private val trustResolver: TrustResolver,
    private val renderer: ScreenRenderer,
    private val issuerResponder: IssuerResponder? = null,
    private val statusListResolver: StatusListResolver? = null,
) {
    fun send(eventJson: String): EffectCascadeOutcome {
        val queue = ArrayDeque(invokeCore(eventJson))
        val initialEventType = eventType(eventJson)
        var executedEffects = 0
        var acknowledged = false
        var renderedInput = false
        var abortReason: EffectAbortReason? = null
        var closed = false

        while (queue.isNotEmpty()) {
            executedEffects += 1
            if (executedEffects > MAX_EFFECTS_PER_CASCADE) {
                throw WalletShellException.EffectCascadeLimitExceeded(MAX_EFFECTS_PER_CASCADE)
            }
            val effect = queue.removeFirst()
            if (closed) {
                return EffectCascadeOutcome.Aborted(EffectAbortReason.EffectAfterClose)
            }
            when (effect) {
                is WalletEffect.Render -> when (val screen = effect.screen) {
                    is WalletScreen.Error -> {
                        abortReason = EffectAbortReason.CoreError(screen.code, screen.message)
                    }
                    else -> renderedInput = true
                }
                WalletEffect.Close -> closed = true
                else -> Unit
            }
            val followUp = execute(effect) ?: continue
            if (effect is WalletEffect.Http || effect is WalletEffect.RequestCredential) {
                acknowledged = true
            }
            queue.addAll(invokeCore(followUp))
        }

        return when {
            abortReason != null -> EffectCascadeOutcome.Aborted(abortReason)
            closed && initialEventType in DECLINE_EVENT_TYPES -> EffectCascadeOutcome.Declined
            closed && acknowledged -> EffectCascadeOutcome.Succeeded
            closed -> EffectCascadeOutcome.Aborted(EffectAbortReason.ClosedWithoutSuccess)
            renderedInput -> EffectCascadeOutcome.AwaitingInput
            initialEventType in IDLE_EVENT_TYPES -> EffectCascadeOutcome.Idle
            else -> EffectCascadeOutcome.Aborted(EffectAbortReason.MissingTerminalOutcome)
        }
    }

    private fun eventType(eventJson: String): String? = try {
        JSONObject(eventJson).optString("type").takeIf(String::isNotEmpty)
    } catch (_: Exception) {
        null
    }

    private fun invokeCore(eventJson: String): List<WalletEffect> {
        val output = try {
            engine.handleEventJson(eventJson)
        } catch (error: Exception) {
            throw WalletShellException.CoreInvocationFailure(error)
        }
        return WalletEffectDecoder.decodeCoreOutput(output)
    }

    private fun execute(effect: WalletEffect): String? = when (effect) {
        is WalletEffect.ResolveRpTrust -> {
            val resolution = wrap(
                failure = ::trustFailure,
                action = { trustResolver.resolve(effect.clientId) },
            )
            WalletEventJson.rpCertChainResolved(resolution)
        }
        is WalletEffect.PersistNonce -> {
            wrap(
                failure = ::storageFailure,
                action = { storage.put("nonce:${effect.nonce}", ByteArray(0)) },
            )
            null
        }
        is WalletEffect.Render -> {
            wrap(
                failure = ::renderingFailure,
                action = { renderer.render(effect.screen) },
            )
            null
        }
        is WalletEffect.Sign -> {
            val signature = wrap(
                failure = ::signingFailure,
                action = { signer.sign(effect.keyRef, effect.payload) },
            )
            WalletEventJson.deviceSignatureProduced(signature)
        }
        is WalletEffect.Http -> {
            val response = wrap(
                failure = ::transportFailure,
                action = { httpClient.post(effect.url, effect.body) },
            )
            if (response.statusCode !in 200..299) {
                throw WalletShellException.HttpStatusFailure(response.statusCode, response.body)
            }
            WalletEventJson.presentationDelivered()
        }
        WalletEffect.RequestToken -> {
            val issuer = issuerResponder
                ?: throw WalletShellException.MissingDependency("requestToken")
            val result = wrap(
                failure = ::issuerFailure,
                action = issuer::token,
            )
            WalletEventJson.tokenReceived(result)
        }
        is WalletEffect.RequestCredential -> {
            val issuer = issuerResponder
                ?: throw WalletShellException.MissingDependency("requestCredential")
            val result = wrap(
                failure = ::issuerFailure,
                action = { issuer.credential(effect.proofJwt) },
            )
            WalletEventJson.credentialReceived(result)
        }
        is WalletEffect.FetchStatusList -> statusListResult(effect.uri)
        WalletEffect.PushPar -> unsupported("pushPar")
        WalletEffect.OpenAuthBrowser -> unsupported("openAuthBrowser")
        WalletEffect.PromptTxCode -> unsupported("promptTxCode")
        is WalletEffect.PublishTransferOffer -> unsupported("publishTransferOffer")
        WalletEffect.Close -> null
    }

    private inline fun <T> wrap(
        failure: (Exception) -> WalletShellException,
        action: () -> T,
    ): T = try {
        action()
    } catch (error: Exception) {
        throw failure(error)
    }

    private fun unsupported(type: String): Nothing =
        throw WalletShellException.UnsupportedEffect(type)

    private fun signingFailure(error: Exception) = WalletShellException.SigningFailure(error)

    private fun storageFailure(error: Exception) = WalletShellException.StorageFailure(error)

    private fun transportFailure(error: Exception) = WalletShellException.TransportFailure(error)

    private fun trustFailure(error: Exception) = WalletShellException.TrustResolutionFailure(error)

    private fun renderingFailure(error: Exception) = WalletShellException.RenderingFailure(error)

    private fun issuerFailure(error: Exception) = WalletShellException.IssuerFailure(error)

    private fun statusListResult(uri: String): String {
        val resolution = try {
            statusListResolver?.fetch(uri)
        } catch (_: Exception) {
            null
        }
        val response = resolution?.response
        val validStatus = response != null && response.statusCode in 0..UShort.MAX_VALUE.toInt()
        val validBody = response != null && response.body.size <= MAX_STATUS_LIST_TOKEN_BYTES
        return if (resolution != null && response != null && validStatus && validBody) {
            WalletEventJson.statusListReceived(
                uri = uri,
                httpStatus = response.statusCode,
                token = response.body,
                providerCertificateChain = resolution.providerCertificateChain,
            )
        } else {
            // Drive Rust's explicit status-unavailable terminal transition. Never translate a
            // missing adapter, transport error, invalid status, or oversized body into consent.
            WalletEventJson.statusListReceived(
                uri = uri,
                httpStatus = 0,
                token = ByteArray(0),
                providerCertificateChain = emptyList(),
            )
        }
    }

    private companion object {
        const val MAX_EFFECTS_PER_CASCADE = 1_024
        const val MAX_STATUS_LIST_TOKEN_BYTES = 2 * 1_024 * 1_024
        val DECLINE_EVENT_TYPES = setOf("userDeclined", "paymentDeclined", "qesDeclined")
        val IDLE_EVENT_TYPES = setOf("setClock")
    }
}
