package eu.advatar.wallet.shell

import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertThrows
import org.junit.Test
import uniffi.wallet_core.FfiDurableCheckpoint
import uniffi.wallet_core.WalletEngineInterface

class RustWalletEngineAdapterTest {
    @Test
    fun mapsDurableContractWithoutChangingBytesOrGeneration() {
        val fake = FakeGeneratedEngine()
        val adapter = RustWalletEngineAdapter.wrapping(fake)
        val environment = environment()

        adapter.prepareForDurableRestore(environment)
        val exported = adapter.makeDurableCheckpoint(7)
        adapter.restoreDurableCheckpointRecord(exported)

        assertEquals(7L, exported.generation)
        assertArrayEquals(byteArrayOf(1, 2, 3), exported.bytes)
        assertEquals(7UL, fake.exportedGeneration)
        assertEquals(7UL, fake.restored?.generation)
        assertArrayEquals(byteArrayOf(1, 2, 3), fake.restored?.bytes)
        assertEquals("""[{"type":"render"}]""", adapter.handleEventJson("""{"type":"start"}"""))
        assertEquals("[]", adapter.durableResumeEffectsJson())
    }

    @Test
    fun rejectsNonPositiveNativeCheckpointGeneration() {
        val adapter = RustWalletEngineAdapter.wrapping(FakeGeneratedEngine())
        assertThrows(IllegalArgumentException::class.java) {
            adapter.makeDurableCheckpoint(0)
        }
    }

    private fun environment() = CoreDurableEnvironment(
        clockEpoch = 9,
        signedTrustList = byteArrayOf(1),
        operatorPublicKey = byteArrayOf(2),
        devicePublicKey = byteArrayOf(3),
        wuaJwt = byteArrayOf(4),
        wuaProviderPublicKey = byteArrayOf(5),
    )
}

private class FakeGeneratedEngine : WalletEngineInterface {
    var exportedGeneration: ULong? = null
    var restored: FfiDurableCheckpoint? = null

    override fun handleEventJson(eventJson: String) = """[{"type":"render"}]"""
    override fun durableResumeEffectsJson() = "[]"
    override fun exportDurableCheckpoint(generation: ULong): FfiDurableCheckpoint {
        exportedGeneration = generation
        return FfiDurableCheckpoint(generation, byteArrayOf(1, 2, 3))
    }
    override fun restoreDurableCheckpoint(checkpoint: FfiDurableCheckpoint) {
        restored = checkpoint
    }
    override fun prepareDurableEnvironment(
        clockEpoch: Long,
        signedTrustList: ByteArray,
        operatorPublicKey: ByteArray,
        devicePublicKey: ByteArray,
        wuaJwt: ByteArray,
        wuaProviderPublicKey: ByteArray,
    ) = Unit
    override fun attestationCatalogueJson() = "[]"
    override fun exportJson() = "{}"
    override fun heldCredentialsJson() = "[]"
    override fun ingestCredential(
        format: String,
        credential: ByteArray,
        issuerCertChain: List<ByteArray>,
        issuerId: String,
    ) = ""
    override fun loadCredential(
        issuerJwt: String,
        disclosuresByClaimJson: String,
        statusIndex: ULong?,
    ) = Unit
    override fun loadDeviceKey(devicePublicKey: ByteArray) = Unit
    override fun loadStatusList(
        uri: String,
        token: ByteArray,
        providerCertChain: List<ByteArray>,
    ) = ""
    override fun loadTrustList(signedList: ByteArray, operatorPublicKey: ByteArray) = ""
    override fun loadWua(wuaJwt: ByteArray, providerPublicKey: ByteArray) = ""
    override fun redactTransaction(seq: ULong) = true
    override fun transactionLogJson() = "[]"
    override fun transactionReportJson() = "{}"
    override fun wipeTransactionLog() = Unit
}
