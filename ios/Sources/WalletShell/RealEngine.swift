import Foundation

// The generated UniFFI `WalletEngine` (ios/Generated/wallet_core.swift, built into
// WalletCore.xcframework) already exposes `handleEventJson(eventJson:)` and
// `loadCredential(issuerJwt:disclosuresByClaimJson:)`, so it conforms with an empty extension.
// Guarded so the package still builds on hosts without the xcframework linked.
#if canImport(wallet_coreFFI)
import wallet_coreFFI
extension WalletEngine: WalletEngineDriving {}
#endif
