package eu.advatar.wallet

import androidx.compose.ui.test.assertIsDisplayed
import androidx.compose.ui.test.junit4.createComposeRule
import androidx.compose.ui.test.onNodeWithContentDescription
import androidx.compose.ui.test.onNodeWithText
import org.junit.Rule
import org.junit.Test

class EUWalletAppTest {
    @get:Rule
    val compose = createComposeRule()

    @Test
    fun homePrioritisesQrIssuanceAndExplainsConsent() {
        compose.setContent { EUWalletApp() }

        compose.onNodeWithText("Add a document").assertIsDisplayed()
        compose.onNodeWithContentDescription("Scan QR code to add a document").assertIsDisplayed()
        compose.onNodeWithText("Nothing is shared without you").assertIsDisplayed()
    }

    @Test
    fun deepLinkOfferIsClearlyAnnounced() {
        compose.setContent { EUWalletApp("openid-credential-offer://example") }

        compose.onNodeWithText("A document offer is ready").assertIsDisplayed()
    }
}
