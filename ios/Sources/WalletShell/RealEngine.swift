import Foundation

// The generated UniFFI `WalletEngine` (ios/Generated/wallet_core.swift, built into
// WalletCore.xcframework) already exposes `handleEventJson(eventJson:)`, so it conforms with an
// empty extension. Credential ingestion is driven through issuance events, not this shell contract.
// Guarded so the package still builds on hosts without the xcframework linked.
#if canImport(wallet_coreFFI)
import wallet_coreFFI
extension WalletEngine: WalletEngineDriving {}
#endif
