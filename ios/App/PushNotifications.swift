import UIKit
import UserNotifications

/// Registers for Apple Push Notifications and uploads the device token to VCIssuer so it can push
/// status updates (e.g. "your document is ready"). Best-effort: authorization + registration may be
/// unavailable on the Simulator or without a provisioning profile; failures are non-fatal.
final class AppDelegate: NSObject, UIApplicationDelegate, UNUserNotificationCenterDelegate {
    private let issuerBaseURL = URL(string: "https://vcissuer.advatar.systems")!
    private static let installationKey = "push.installationId"

    func application(
        _ application: UIApplication,
        didFinishLaunchingWithOptions _: [UIApplication.LaunchOptionsKey: Any]? = nil
    ) -> Bool {
        UNUserNotificationCenter.current().delegate = self
        UNUserNotificationCenter.current().requestAuthorization(options: [.alert, .sound, .badge]) {
            granted, _ in
            guard granted else { return }
            DispatchQueue.main.async { application.registerForRemoteNotifications() }
        }
        return true
    }

    func application(
        _: UIApplication,
        didRegisterForRemoteNotificationsWithDeviceToken deviceToken: Data
    ) {
        let token = deviceToken.map { String(format: "%02x", $0) }.joined()
        Task { await registerToken(token) }
    }

    func application(
        _: UIApplication,
        didFailToRegisterForRemoteNotificationsWithError error: Error
    ) {
        NSLog("Remote notification registration failed: \(error.localizedDescription)")
    }

    /// Show banners while the app is in the foreground.
    func userNotificationCenter(
        _: UNUserNotificationCenter,
        willPresent _: UNNotification,
        withCompletionHandler completionHandler: @escaping (UNNotificationPresentationOptions) -> Void
    ) {
        completionHandler([.banner, .sound])
    }

    private func installationId() -> String {
        if let existing = UserDefaults.standard.string(forKey: Self.installationKey) {
            return existing
        }
        let id = UUID().uuidString
        UserDefaults.standard.set(id, forKey: Self.installationKey)
        return id
    }

    private func registerToken(_ token: String) async {
        var request = URLRequest(
            url: issuerBaseURL.appendingPathComponent("v1/notifications/register"))
        request.httpMethod = "POST"
        request.setValue("application/json", forHTTPHeaderField: "Content-Type")
        request.httpBody = try? JSONSerialization.data(withJSONObject: [
            "installation_id": installationId(),
            "device_token": token,
        ])
        _ = try? await URLSession.shared.data(for: request)
    }
}
