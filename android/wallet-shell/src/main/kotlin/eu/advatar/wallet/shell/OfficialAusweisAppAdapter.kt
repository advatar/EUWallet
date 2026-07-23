package eu.advatar.wallet.shell

import android.content.ComponentName
import android.content.Context
import android.content.Intent
import android.content.ServiceConnection
import android.nfc.Tag
import android.os.IBinder
import com.governikus.ausweisapp2.IAusweisApp2Sdk
import com.governikus.ausweisapp2.IAusweisApp2SdkCallback

/**
 * Production AIDL bridge to Governikus's official AusweisApp 2.5.4 AAR.
 *
 * Binder callbacks are correlated to one wallet generation before entering the deterministic
 * coordinator. The SDK session identifier is process-local and is never persisted. A process
 * restart therefore produces an honest restart-required journey instead of replaying stale NFC or
 * secret callbacks.
 */
class OfficialAusweisAppAdapter(
    context: Context,
    private val coordinator: DeterministicGermanEidClient = DeterministicGermanEidClient(),
    private val outputHandler: (GermanEidOutput) -> Unit,
) : GermanEidClient, AutoCloseable {
    private val applicationContext = context.applicationContext
    private val lock = Any()
    private var sdk: IAusweisApp2Sdk? = null
    private var sdkSessionId: String? = null
    private var activeSessionId: GermanEidSessionId? = null
    private var bound = false
    private var closed = false

    private val callback = object : IAusweisApp2SdkCallback.Stub() {
        override fun sessionIdGenerated(value: String?) {
            synchronized(lock) {
                if (closed || value.isNullOrEmpty() || value.length > 256) {
                    adapterFailure()
                    return
                }
                sdkSessionId = value
                executePending(GermanEidSdkCommand.GetApiLevel)
            }
        }

        override fun receive(message: String?) {
            synchronized(lock) {
                val session = activeSessionId ?: return
                if (closed || message == null) return
                try {
                    val event = AusweisAppProtocolCodec.decode(
                        message,
                        coordinator.activeProviderContractForAdapter,
                        session,
                    )
                    deliver(coordinator.receive(event, session))
                } catch (_: RuntimeException) {
                    adapterFailure()
                }
            }
        }

        override fun sdkDisconnected() {
            synchronized(lock) { adapterFailure() }
        }
    }

    private val connection = object : ServiceConnection {
        override fun onServiceConnected(name: ComponentName?, binder: IBinder?) {
            synchronized(lock) {
                if (closed || binder == null) return
                try {
                    sdk = IAusweisApp2Sdk.Stub.asInterface(binder)
                    if (sdk?.connectSdk(callback) != true) adapterFailure()
                } catch (_: Exception) {
                    adapterFailure()
                }
            }
        }

        override fun onServiceDisconnected(name: ComponentName?) {
            synchronized(lock) {
                sdk = null
                sdkSessionId = null
                adapterFailure()
            }
        }
    }

    override fun start(request: GermanEidStartRequest): GermanEidOutput = synchronized(lock) {
        if (closed || activeSessionId != null) {
            throw GermanEidClientException(GermanEidClientError.INVALID_TRANSITION)
        }
        activeSessionId = request.sessionId
        val output = coordinator.start(request)
        val intent = Intent(SERVICE_ACTION).setPackage(applicationContext.packageName)
        bound = applicationContext.bindService(intent, connection, Context.BIND_AUTO_CREATE)
        if (!bound) {
            deliver(coordinator.receive(GermanEidSdkEvent.AdapterFailed, request.sessionId))
        }
        output
    }

    override fun receive(
        event: GermanEidSdkEvent,
        sessionId: GermanEidSessionId,
    ): GermanEidOutput = synchronized(lock) {
        ensureActive(sessionId)
        deliver(coordinator.receive(event, sessionId))
    }

    override fun act(
        action: GermanEidUserAction,
        sessionId: GermanEidSessionId,
    ): GermanEidOutput = synchronized(lock) {
        ensureActive(sessionId)
        deliver(coordinator.act(action, sessionId))
    }

    override fun shutdown(sessionId: GermanEidSessionId): GermanEidOutput = synchronized(lock) {
        ensureActive(sessionId)
        val output = coordinator.shutdown(sessionId)
        execute(output.commands)
        closeLocked()
        output
    }

    /** Pass the foreground-discovered physical NFC tag directly to the official SDK service. */
    fun updateNfcTag(tag: Tag): Boolean = synchronized(lock) {
        val service = sdk ?: return false
        val session = sdkSessionId ?: return false
        try {
            service.updateNfcTag(session, tag)
        } catch (_: Exception) {
            false
        }
    }

    private fun deliver(output: GermanEidOutput): GermanEidOutput {
        execute(output.commands)
        if (output.uiEvents.isNotEmpty()) outputHandler(output)
        if (output.uiEvents.any { it is GermanEidUiEvent.Completed }) closeLocked()
        return output
    }

    private fun execute(commands: List<GermanEidSdkCommand>) {
        for (command in commands) {
            if (command == GermanEidSdkCommand.InterruptSystemDialog) continue
            executePending(command)
        }
    }

    private fun executePending(command: GermanEidSdkCommand) {
        val service = sdk ?: return
        val session = sdkSessionId ?: return
        val chars = try {
            AusweisAppProtocolCodec.encode(command)
        } catch (_: RuntimeException) {
            adapterFailure()
            return
        }
        try {
            if (!service.transmit(session, chars)) adapterFailure()
        } catch (_: Exception) {
            adapterFailure()
        } finally {
            chars.fill('\u0000')
            command.close()
        }
    }

    private fun adapterFailure() {
        val session = activeSessionId ?: return
        try {
            deliver(coordinator.receive(GermanEidSdkEvent.AdapterFailed, session))
        } catch (_: RuntimeException) {
            closeLocked()
        }
    }

    private fun ensureActive(sessionId: GermanEidSessionId) {
        if (closed || activeSessionId != sessionId) {
            throw GermanEidClientException(GermanEidClientError.STALE_SESSION)
        }
    }

    override fun close() = synchronized(lock) { closeLocked() }

    private fun closeLocked() {
        if (closed) return
        closed = true
        activeSessionId = null
        sdkSessionId = null
        sdk = null
        if (bound) {
            applicationContext.unbindService(connection)
            bound = false
        }
    }

    private companion object {
        const val SERVICE_ACTION = "com.governikus.ausweisapp2.START_SERVICE"
    }
}
