package eu.advatar.wallet

import androidx.compose.foundation.background
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.outlined.Add
import androidx.compose.material.icons.outlined.History
import androidx.compose.material.icons.outlined.Home
import androidx.compose.material.icons.outlined.Lock
import androidx.compose.material.icons.outlined.QrCodeScanner
import androidx.compose.material.icons.outlined.Settings
import androidx.compose.material3.Button
import androidx.compose.material3.ButtonDefaults
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.Icon
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.NavigationBar
import androidx.compose.material3.NavigationBarItem
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Text
import androidx.compose.material3.lightColorScheme
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.vector.ImageVector
import androidx.compose.ui.semantics.contentDescription
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp

private val Ink = Color(0xFF14213D)
private val Brand = Color(0xFF1646D8)
private val Canvas = Color(0xFFF5F7FB)
private val Muted = Color(0xFF526078)
private val Success = Color(0xFF0A6C51)

private enum class Destination(val label: String, val icon: ImageVector) {
    HOME("Wallet", Icons.Outlined.Home),
    HISTORY("Activity", Icons.Outlined.History),
    SETTINGS("Settings", Icons.Outlined.Settings),
}

@Composable
fun EUWalletApp(initialOffer: String? = null) {
    var destination by remember { mutableStateOf(Destination.HOME) }
    MaterialTheme(
        colorScheme = lightColorScheme(
            primary = Brand,
            onPrimary = Color.White,
            background = Canvas,
            onBackground = Ink,
            surface = Color.White,
            onSurface = Ink,
        ),
    ) {
        Scaffold(
            containerColor = Canvas,
            bottomBar = {
                NavigationBar(containerColor = Color.White) {
                    Destination.entries.forEach { item ->
                        NavigationBarItem(
                            selected = destination == item,
                            onClick = { destination = item },
                            icon = { Icon(item.icon, contentDescription = null) },
                            label = { Text(item.label) },
                        )
                    }
                }
            },
        ) { insets ->
            when (destination) {
                Destination.HOME -> WalletHome(initialOffer, Modifier.padding(insets))
                Destination.HISTORY -> PlaceholderJourney(
                    title = "Activity",
                    body = "Your private history stays on this device.",
                    modifier = Modifier.padding(insets),
                )
                Destination.SETTINGS -> PlaceholderJourney(
                    title = "Protected on this device",
                    body = "You will always see who is asking and what they need before you share.",
                    modifier = Modifier.padding(insets),
                )
            }
        }
    }
}

@Composable
private fun WalletHome(initialOffer: String?, modifier: Modifier = Modifier) {
    Column(
        modifier = modifier.fillMaxSize().padding(horizontal = 24.dp, vertical = 20.dp),
        verticalArrangement = Arrangement.spacedBy(18.dp),
    ) {
        Row(verticalAlignment = Alignment.CenterVertically) {
            Column(modifier = Modifier.weight(1f)) {
                Text("EU Wallet", color = Ink, fontSize = 30.sp, fontWeight = FontWeight.Bold)
                Text("Your documents, under your control", color = Muted, fontSize = 16.sp)
            }
            Box(
                modifier = Modifier
                    .size(48.dp)
                    .background(Color(0xFFE2E9FF), RoundedCornerShape(16.dp)),
                contentAlignment = Alignment.Center,
            ) {
                Icon(Icons.Outlined.Lock, contentDescription = "Device protected", tint = Brand)
            }
        }

        if (initialOffer != null) {
            NoticeCard("A document offer is ready", "Review who issued it before adding it.")
        }

        Card(
            modifier = Modifier.fillMaxWidth(),
            shape = RoundedCornerShape(24.dp),
            colors = CardDefaults.cardColors(containerColor = Color.White),
            elevation = CardDefaults.cardElevation(defaultElevation = 2.dp),
        ) {
            Column(modifier = Modifier.padding(24.dp), verticalArrangement = Arrangement.spacedBy(14.dp)) {
                Icon(Icons.Outlined.Add, contentDescription = null, tint = Brand, modifier = Modifier.size(34.dp))
                Text("Add a document", fontSize = 24.sp, fontWeight = FontWeight.Bold)
                Text(
                    "Scan the QR code from the organisation issuing your document. You can review everything before it is saved.",
                    color = Muted,
                    fontSize = 16.sp,
                    lineHeight = 23.sp,
                )
                Button(
                    onClick = { },
                    modifier = Modifier.fillMaxWidth().height(54.dp)
                        .semantics { contentDescription = "Scan QR code to add a document" },
                    shape = RoundedCornerShape(16.dp),
                    colors = ButtonDefaults.buttonColors(containerColor = Brand),
                ) {
                    Icon(Icons.Outlined.QrCodeScanner, contentDescription = null)
                    Spacer(Modifier.size(10.dp))
                    Text("Scan QR code", fontSize = 17.sp, fontWeight = FontWeight.SemiBold)
                }
            }
        }

        NoticeCard(
            title = "Nothing is shared without you",
            body = "This wallet checks the organisation and shows the exact information requested before you approve.",
        )
    }
}

@Composable
private fun NoticeCard(title: String, body: String) {
    Card(
        modifier = Modifier.fillMaxWidth(),
        shape = RoundedCornerShape(18.dp),
        colors = CardDefaults.cardColors(containerColor = Color(0xFFE7F5F0)),
    ) {
        Row(
            modifier = Modifier.padding(18.dp),
            horizontalArrangement = Arrangement.spacedBy(14.dp),
            verticalAlignment = Alignment.Top,
        ) {
            Icon(Icons.Outlined.Lock, contentDescription = null, tint = Success)
            Column(verticalArrangement = Arrangement.spacedBy(4.dp)) {
                Text(title, color = Ink, fontWeight = FontWeight.Bold, fontSize = 17.sp)
                Text(body, color = Muted, fontSize = 15.sp, lineHeight = 21.sp)
            }
        }
    }
}

@Composable
private fun PlaceholderJourney(title: String, body: String, modifier: Modifier = Modifier) {
    Column(
        modifier = modifier.fillMaxSize().padding(24.dp),
        verticalArrangement = Arrangement.spacedBy(12.dp),
    ) {
        Text(title, color = Ink, fontSize = 28.sp, fontWeight = FontWeight.Bold)
        Text(body, color = Muted, fontSize = 17.sp, lineHeight = 24.sp)
    }
}
