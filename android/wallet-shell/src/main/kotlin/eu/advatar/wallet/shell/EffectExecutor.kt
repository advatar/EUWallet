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
 * Drains the sans-I/O core's effect cascade through a durable lifecycle coordinator.
 * Infrastructure failures stop the cascade and are never translated into semantic decline or
 * success events. Requiring the concrete coordinator prevents callers from releasing native
 * effects from a raw, uncommitted Core transition.
 */
class EffectExecutor(
    private val lifecycle: DurableLifecycleCoordinator,
    private val signer: WalletSigner,
    private val httpClient: WalletHttpClient,
    private val storage: WalletStorage,
    private val trustResolver: TrustResolver,
    private val renderer: ScreenRenderer,
    private val issuerResponder: IssuerResponder? = null,
    private val statusListResolver: StatusListResolver? = null,
    private val transferOfferPublisher: TransferOfferPublisher? = null,
    private val presentationRedirectHandler: OpenId4VpRedirectHandler? = null,
) {
    private var pendingDurableEventJson: String? = null

    fun send(eventJson: String): EffectCascadeOutcome {
        val effects = invokeCore(eventJson)
        return drain(effects, eventType(eventJson))
    }

    /**
     * Commit and resume the exact transition blocked by durable persistence. The coordinator
     * returns its retained effects without invoking Core again.
     */
    fun retryPendingDurableCommit(): EffectCascadeOutcome {
        val (eventJson, output) = retryPendingCoreOutput()
        return drain(WalletEffectDecoder.decodeCoreOutput(output), eventType(eventJson))
    }

    @Synchronized
    private fun retryPendingCoreOutput(): Pair<String, String> {
        val eventJson = pendingDurableEventJson
            ?: throw WalletShellException.NoPendingDurableCommit()
        val output = try {
            lifecycle.retryPendingEvent(eventJson)
        } catch (error: DurableLifecycleException) {
            if (!lifecycle.hasPendingCommit) pendingDurableEventJson = null
            // Preserve the stable lifecycle code rather than hiding it behind a generic Core
            // invocation failure.
            throw error
        } catch (error: Exception) {
            throw WalletShellException.CoreInvocationFailure(error)
        }
        pendingDurableEventJson = null
        return eventJson to output
    }

    private fun drain(
        initialEffects: List<WalletEffect>,
        initialEventType: String?,
    ): EffectCascadeOutcome {
        val queue = ArrayDeque(initialEffects)
        var executedEffects = 0
        var acknowledged = false
        var renderedInput = false
        var awaitingExternalInput = false
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
            val followUpEffects = invokeCore(followUp)
            if (
                eventType(followUp) in COMPLETION_EVENT_TYPES &&
                followUpEffects.none(::isErrorScreen)
            ) {
                acknowledged = true
            }
            if (
                effect is WalletEffect.PublishTransferOffer &&
                eventType(followUp) == "operationSucceeded"
            ) {
                awaitingExternalInput = true
            }
            queue.addAll(followUpEffects)
        }

        return when {
            abortReason != null -> EffectCascadeOutcome.Aborted(abortReason)
            closed && initialEventType in DECLINE_EVENT_TYPES -> EffectCascadeOutcome.Declined
            closed && acknowledged -> EffectCascadeOutcome.Succeeded
            closed -> EffectCascadeOutcome.Aborted(EffectAbortReason.ClosedWithoutSuccess)
            renderedInput || awaitingExternalInput -> EffectCascadeOutcome.AwaitingInput
            initialEventType in IDLE_EVENT_TYPES -> EffectCascadeOutcome.Idle
            else -> EffectCascadeOutcome.Aborted(EffectAbortReason.MissingTerminalOutcome)
        }
    }

    private fun eventType(eventJson: String): String? = try {
        JSONObject(eventJson).optString("type").takeIf(String::isNotEmpty)
    } catch (_: Exception) {
        null
    }

    private fun isErrorScreen(effect: WalletEffect): Boolean =
        effect is WalletEffect.Render && effect.screen is WalletScreen.Error

    @Synchronized
    private fun invokeCore(eventJson: String): List<WalletEffect> {
        // Do not overwrite the event associated with an exact retained checkpoint/effect batch.
        if (pendingDurableEventJson != null) {
            throw DurableLifecycleException(DurableLifecycleErrorCode.COMMIT_PENDING)
        }
        // A coordinator can outlive an executor. A replacement executor must reject a new event
        // without mistaking it for the exact transition already retained by that coordinator.
        if (lifecycle.hasPendingCommit) {
            throw DurableLifecycleException(DurableLifecycleErrorCode.COMMIT_PENDING)
        }
        pendingDurableEventJson = eventJson
        val output = try {
            lifecycle.handleEventJson(eventJson)
        } catch (error: DurableLifecycleException) {
            if (!lifecycle.hasPendingCommit) pendingDurableEventJson = null
            throw error
        } catch (error: Exception) {
            pendingDurableEventJson = null
            throw WalletShellException.CoreInvocationFailure(error)
        }
        pendingDurableEventJson = null
        return WalletEffectDecoder.decodeCoreOutput(output)
    }

    private fun execute(effect: WalletEffect): String? = when (effect) {
        is WalletEffect.ResolveRpTrust -> {
            try {
                val resolution = trustResolver.resolve(effect.clientId)
                WalletEventJson.rpCertChainResolved(effect.operationId, resolution)
            } catch (error: Exception) {
                operationFailure(effect.operationId, WalletOperationFailure.TRUST, error)
            }
        }
        is WalletEffect.PersistNonce -> {
            try {
                storage.put("nonce:${effect.nonce}", ByteArray(0))
                WalletEventJson.operationSucceeded(effect.operationId)
            } catch (error: Exception) {
                operationFailure(effect.operationId, WalletOperationFailure.STORAGE, error)
            }
        }
        is WalletEffect.Render -> {
            try {
                renderer.render(effect.operationId, effect.authorizationHash, effect.screen)
                null
            } catch (error: Exception) {
                effect.operationId?.let {
                    operationFailure(it, WalletOperationFailure.RENDERING, error)
                } ?: throw WalletShellException.RenderingFailure(error)
            }
        }
        is WalletEffect.Sign -> {
            try {
                val signature = signer.sign(effect.keyRef, effect.payload)
                WalletEventJson.deviceSignatureProduced(effect.operationId, signature)
            } catch (error: Exception) {
                operationFailure(effect.operationId, WalletOperationFailure.SIGNING, error)
            }
        }
        is WalletEffect.Http -> try {
            if (effect.profile.resultType != effect.resultType) {
                WalletEventJson.operationFailed(
                    effect.operationId,
                    WalletOperationFailure.UNSUPPORTED,
                )
            } else if (
                effect.profile == HttpDeliveryProfile.OPENID4VP_DIRECT_POST &&
                !OpenId4VpDirectPostResponse.isUtf8(effect.body)
            ) {
                WalletEventJson.operationFailed(
                    effect.operationId,
                    WalletOperationFailure.TRANSPORT,
                )
            } else {
                val response = httpClient.post(effect.url, effect.body, effect.profile)
                when (effect.profile) {
                    HttpDeliveryProfile.OPENID4VP_DIRECT_POST -> {
                        if (response.statusCode != 200) {
                            WalletEventJson.operationFailed(
                                effect.operationId,
                                WalletOperationFailure.HTTP_STATUS,
                            )
                        } else {
                            val parsed = OpenId4VpDirectPostResponse.parse(response)
                            val redirectUri = parsed.redirectUri
                            val handler = presentationRedirectHandler
                            if (redirectUri != null && handler == null) {
                                WalletEventJson.operationFailed(
                                    effect.operationId,
                                    WalletOperationFailure.MISSING_DEPENDENCY,
                                )
                            } else {
                                if (redirectUri != null) handler?.handle(redirectUri)
                                WalletEventJson.presentationDelivered(effect.operationId)
                            }
                        }
                    }
                    HttpDeliveryProfile.PAYMENT_AUTHORIZATION -> if (
                        response.statusCode in 200..299
                    ) {
                        WalletEventJson.paymentAuthorizationDelivered(effect.operationId)
                    } else {
                        WalletEventJson.operationFailed(
                            effect.operationId,
                            WalletOperationFailure.HTTP_STATUS,
                        )
                    }
                    HttpDeliveryProfile.QES_AUTHORIZATION -> if (
                        response.statusCode in 200..299
                    ) {
                        WalletEventJson.qesAuthorizationDelivered(effect.operationId)
                    } else {
                        WalletEventJson.operationFailed(
                            effect.operationId,
                            WalletOperationFailure.HTTP_STATUS,
                        )
                    }
                }
            }
        } catch (error: Exception) {
            operationFailure(
                effect.operationId,
                WalletOperationFailure.TRANSPORT,
                error,
            )
        }
        is WalletEffect.RequestToken -> {
            val issuer = issuerResponder
            if (issuer == null) {
                WalletEventJson.operationFailed(
                    effect.operationId,
                    WalletOperationFailure.MISSING_DEPENDENCY,
                )
            } else try {
                WalletEventJson.tokenReceived(effect.operationId, issuer.token())
            } catch (error: Exception) {
                operationFailure(effect.operationId, WalletOperationFailure.ISSUER, error)
            }
        }
        is WalletEffect.RequestCredential -> {
            val issuer = issuerResponder
            if (issuer == null) {
                WalletEventJson.operationFailed(
                    effect.operationId,
                    WalletOperationFailure.MISSING_DEPENDENCY,
                )
            } else try {
                WalletEventJson.credentialReceived(
                    effect.operationId,
                    issuer.credential(effect.proofJwt),
                )
            } catch (error: Exception) {
                operationFailure(effect.operationId, WalletOperationFailure.ISSUER, error)
            }
        }
        is WalletEffect.FetchStatusList -> statusListResult(effect.operationId, effect.uri)
        is WalletEffect.PushPar -> WalletEventJson.operationFailed(
            effect.operationId,
            WalletOperationFailure.UNSUPPORTED,
        )
        is WalletEffect.OpenAuthBrowser -> WalletEventJson.operationFailed(
            effect.operationId,
            WalletOperationFailure.UNSUPPORTED,
        )
        is WalletEffect.PromptTxCode -> WalletEventJson.operationFailed(
            effect.operationId,
            WalletOperationFailure.UNSUPPORTED,
        )
        is WalletEffect.PublishTransferOffer -> {
            val publisher = transferOfferPublisher
            if (publisher == null) {
                WalletEventJson.operationFailed(
                    effect.operationId,
                    WalletOperationFailure.MISSING_DEPENDENCY,
                )
            } else try {
                publisher.publish(effect.offeredKey)
                WalletEventJson.operationSucceeded(effect.operationId)
            } catch (error: Exception) {
                operationFailure(effect.operationId, WalletOperationFailure.TRANSPORT, error)
            }
        }
        WalletEffect.Close -> null
    }

    private fun operationFailure(
        operationId: Long,
        failure: WalletOperationFailure,
        error: Exception,
    ): String = if (
        error is InterruptedException || error is java.util.concurrent.CancellationException
    ) {
        if (error is InterruptedException) Thread.currentThread().interrupt()
        WalletEventJson.operationCancelled(operationId)
    } else {
        WalletEventJson.operationFailed(operationId, failure)
    }

    private fun statusListResult(operationId: Long, uri: String): String {
        val resolution = try {
            statusListResolver?.fetch(uri)
        } catch (error: Exception) {
            return operationFailure(operationId, WalletOperationFailure.STATUS, error)
        }
        val response = resolution?.response
        val validStatus = response != null && response.statusCode in 0..UShort.MAX_VALUE.toInt()
        val validBody = response != null && response.body.size <= MAX_STATUS_LIST_TOKEN_BYTES
        return if (resolution != null && response != null && validStatus && validBody) {
            WalletEventJson.statusListReceived(
                operationId = operationId,
                uri = uri,
                httpStatus = response.statusCode,
                token = response.body,
                providerCertificateChain = resolution.providerCertificateChain,
            )
        } else {
            WalletEventJson.operationFailed(
                operationId,
                WalletOperationFailure.STATUS,
            )
        }
    }

    private companion object {
        const val MAX_EFFECTS_PER_CASCADE = 1_024
        const val MAX_STATUS_LIST_TOKEN_BYTES = 2 * 1_024 * 1_024
        val DECLINE_EVENT_TYPES = setOf("userDeclined", "paymentDeclined", "qesDeclined")
        val IDLE_EVENT_TYPES = setOf(
            "setClock",
            "redactTransaction",
            "wipeTransactionLog",
        )
        val COMPLETION_EVENT_TYPES = setOf(
            "presentationDelivered",
            "paymentAuthorizationDelivered",
            "qesAuthorizationDelivered",
            "credentialReceived",
        )
    }
}
