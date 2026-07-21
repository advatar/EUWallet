package eu.advatar.wallet.shell

import org.junit.Assert.assertThrows
import org.junit.Test

class UrlConnectionHttpClientTest {
    @Test
    fun rejectsNonHttpsAndAmbiguousUrlsBeforeNetworkAccess() {
        val client = UrlConnectionHttpClient()

        listOf(
            "http://rp.example",
            "https://user:pass@rp.example",
            "https://rp.example/callback#fragment",
            "not a url",
        ).forEach { url ->
            assertThrows(WalletHttpClientException.InvalidUrl::class.java) {
                client.post(url, ByteArray(0))
            }
        }
    }

    @Test
    fun validatesResourceLimits() {
        assertThrows(IllegalArgumentException::class.java) {
            UrlConnectionHttpClient(timeoutMilliseconds = 0)
        }
        assertThrows(IllegalArgumentException::class.java) {
            UrlConnectionHttpClient(maximumResponseBytes = 0)
        }
    }
}
