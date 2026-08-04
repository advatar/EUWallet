import AppIntents

/// App Intents backing the Control Center controls and Siri/Shortcuts phrases. Each only opens the
/// app to a screen (via the pending-action store) — none reads or exposes credential data.
///
/// A Control's button or a Siri phrase runs the intent; `openAppWhenRun` foregrounds the app, and
/// the app consumes the pending action when it becomes active (see `ContentView`).

@available(iOS 16.0, *)
private func requestOpen(_ link: WalletDeepLink) {
    WalletPendingAction.set(link)
}

@available(iOS 16.0, *)
public struct ScanIntent: AppIntent {
    public static var title: LocalizedStringResource = "Scan a QR code"
    public static var description = IntentDescription("Open the wallet to scan a QR code.")
    public static var openAppWhenRun = true
    public init() {}
    public func perform() async throws -> some IntentResult {
        requestOpen(.scan)
        return .result()
    }
}

@available(iOS 16.0, *)
public struct PresentIntent: AppIntent {
    public static var title: LocalizedStringResource = "Show a document"
    public static var description = IntentDescription("Open the wallet to share a document.")
    public static var openAppWhenRun = true
    public init() {}
    public func perform() async throws -> some IntentResult {
        requestOpen(.present)
        return .result()
    }
}

@available(iOS 16.0, *)
public struct AddFromPassportIntent: AppIntent {
    public static var title: LocalizedStringResource = "Add from passport"
    public static var description = IntentDescription("Open the wallet to add a PID from a passport chip.")
    public static var openAppWhenRun = true
    public init() {}
    public func perform() async throws -> some IntentResult {
        requestOpen(.passport)
        return .result()
    }
}

@available(iOS 16.0, *)
public struct AddWebEvidenceIntent: AppIntent {
    public static var title: LocalizedStringResource = "Add web evidence"
    public static var description = IntentDescription("Open the wallet to capture TLSNotary web evidence.")
    public static var openAppWhenRun = true
    public init() {}
    public func perform() async throws -> some IntentResult {
        requestOpen(.webEvidence)
        return .result()
    }
}

@available(iOS 16.0, *)
public struct OpenWalletIntent: AppIntent {
    public static var title: LocalizedStringResource = "Open my wallet"
    public static var description = IntentDescription("Open the EU Wallet.")
    public static var openAppWhenRun = true
    public init() {}
    public func perform() async throws -> some IntentResult {
        requestOpen(.home)
        return .result()
    }
}

@available(iOS 16.0, *)
public struct OpenActivityIntent: AppIntent {
    public static var title: LocalizedStringResource = "Show wallet activity"
    public static var description = IntentDescription("Open the wallet's activity history.")
    public static var openAppWhenRun = true
    public init() {}
    public func perform() async throws -> some IntentResult {
        requestOpen(.activity)
        return .result()
    }
}

@available(iOS 16.0, *)
public struct OpenCatalogueIntent: AppIntent {
    public static var title: LocalizedStringResource = "Show document types"
    public static var description = IntentDescription("Open the wallet's document catalogue.")
    public static var openAppWhenRun = true
    public init() {}
    public func perform() async throws -> some IntentResult {
        requestOpen(.catalogue)
        return .result()
    }
}

@available(iOS 16.0, *)
public struct ManageAgentsIntent: AppIntent {
    public static var title: LocalizedStringResource = "Manage my agents"
    public static var description = IntentDescription("Open the wallet's delegated-agent management.")
    public static var openAppWhenRun = true
    public init() {}
    public func perform() async throws -> some IntentResult {
        requestOpen(.agents)
        return .result()
    }
}

@available(iOS 16.0, *)
public struct OpenSettingsIntent: AppIntent {
    public static var title: LocalizedStringResource = "Open wallet settings"
    public static var description = IntentDescription("Open the wallet's settings.")
    public static var openAppWhenRun = true
    public init() {}
    public func perform() async throws -> some IntentResult {
        requestOpen(.settings)
        return .result()
    }
}
