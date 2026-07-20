import Foundation

// The generated UniFFI `WalletEngine` (ios/Generated/wallet_core.swift, built into
// WalletCore.xcframework) already exposes `handleEventJson(eventJson:)`, so it conforms with an
// empty extension. Credential ingestion is driven through issuance events, not this shell contract.
// Guarded so the package still builds on hosts without the xcframework linked.
#if canImport(wallet_coreFFI)
    import wallet_coreFFI
    extension FfiDurableCheckpoint: CustomStringConvertible, CustomDebugStringConvertible {
        public var description: String { "FfiDurableCheckpoint(redacted)" }
        public var debugDescription: String { description }
    }

    extension WalletEngine: WalletEngineDriving, DurableWalletEngineDriving {
        public func prepareForDurableRestore(environment: CoreDurableEnvironment) throws {
            try prepareDurableEnvironment(
                clockEpoch: environment.clockEpoch,
                signedTrustList: environment.signedTrustList,
                operatorPublicKey: environment.operatorPublicKey,
                devicePublicKey: environment.devicePublicKey,
                wuaJwt: environment.wuaJwt,
                wuaProviderPublicKey: environment.wuaProviderPublicKey)
        }

        public func makeDurableCheckpoint(generation: UInt64) throws -> CoreDurableCheckpoint {
            let checkpoint = try exportDurableCheckpoint(generation: generation)
            return CoreDurableCheckpoint(
                generation: checkpoint.generation,
                bytes: checkpoint.bytes)
        }

        public func restoreDurableCheckpointRecord(_ checkpoint: CoreDurableCheckpoint) throws {
            try restoreDurableCheckpoint(
                checkpoint: FfiDurableCheckpoint(
                    generation: checkpoint.generation,
                    bytes: checkpoint.bytes))
        }
    }
#endif
