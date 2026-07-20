package eu.advatar.wallet.shell

import java.util.ArrayDeque

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
) {
    fun send(eventJson: String) {
        val queue = ArrayDeque(invokeCore(eventJson))
        var executedEffects = 0

        while (queue.isNotEmpty()) {
            executedEffects += 1
            if (executedEffects > MAX_EFFECTS_PER_CASCADE) {
                throw WalletShellException.EffectCascadeLimitExceeded(MAX_EFFECTS_PER_CASCADE)
            }
            val followUp = execute(queue.removeFirst()) ?: continue
            queue.addAll(invokeCore(followUp))
        }
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

    private companion object {
        const val MAX_EFFECTS_PER_CASCADE = 1_024
    }
}
