package eu.advatar.wallet.shell

import java.io.ByteArrayInputStream
import java.net.InetAddress
import org.junit.Assert.assertArrayEquals
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
            "HTTPS://rp.example/callback",
            "https://rp.example:0/callback",
            "not a url",
        ).forEach { url ->
            assertThrows(WalletHttpClientException.InvalidUrl::class.java) {
                client.post(url, ByteArray(0))
            }
        }
    }

    @Test
    fun rejectsPrivateReservedAndMixedDnsAnswers() {
        listOf(
            "https://localhost/callback",
            "https://service.local/callback",
            "https://single-label/callback",
            "https://0177.0.0.1/callback",
            "https://2130706433/callback",
        ).forEach { url ->
            assertThrows(WalletHttpClientException.UnsafeDestination::class.java) {
                ProductionUrlPolicy().validate(url)
            }
        }

        val privateAddresses = listOf(
            "127.0.0.1",
            "10.0.0.1",
            "100.64.0.1",
            "169.254.1.1",
            "172.16.0.1",
            "192.168.1.1",
            "198.18.0.1",
            "192.0.2.1",
            "203.0.113.1",
            "::1",
            "fc00::1",
            "fe80::1",
            "2001:db8::1",
            "3fff::1",
        )
        privateAddresses.forEach { address ->
            val policy = ProductionUrlPolicy(
                HostAddressResolver { listOf(InetAddress.getByName(address)) },
            )
            assertThrows(WalletHttpClientException.UnsafeDestination::class.java) {
                policy.validate("https://wallet.example/callback")
            }
        }

        val mixed = ProductionUrlPolicy(
            HostAddressResolver {
                listOf(
                    InetAddress.getByName("93.184.216.34"),
                    InetAddress.getByName("127.0.0.1"),
                )
            },
        )
        assertThrows(WalletHttpClientException.UnsafeDestination::class.java) {
            mixed.validate("https://wallet.example/callback")
        }
    }

    @Test
    fun acceptsCanonicalPublicDnsAndIpDestinations() {
        val policy = ProductionUrlPolicy(
            HostAddressResolver { listOf(InetAddress.getByName("93.184.216.34")) },
        )
        policy.validate("https://wallet.example:8443/callback?state=one")
        policy.validate("https://93.184.216.34/callback")
    }

    @Test
    fun validatesResourceLimits() {
        assertThrows(IllegalArgumentException::class.java) {
            UrlConnectionHttpClient(timeoutMilliseconds = 0)
        }
        assertThrows(IllegalArgumentException::class.java) {
            UrlConnectionHttpClient(maximumResponseBytes = 0)
        }

        val bounded = UrlConnectionHttpClient(maximumResponseBytes = 4)
        assertArrayEquals(
            byteArrayOf(1, 2, 3, 4),
            bounded.readBody(ByteArrayInputStream(byteArrayOf(1, 2, 3, 4))),
        )
        assertThrows(WalletHttpClientException.ResponseTooLarge::class.java) {
            bounded.readBody(ByteArrayInputStream(byteArrayOf(1, 2, 3, 4, 5)))
        }
    }
}
