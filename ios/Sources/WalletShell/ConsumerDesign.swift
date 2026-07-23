#if canImport(SwiftUI)
import SwiftUI
#if canImport(UIKit)
import UIKit
#endif

public enum CredentialOfferEntryMode: Equatable, Sendable {
    case qrCode
    case verifiedLink
}

/// A holder does not choose an arbitrary credential type. Issuance starts from an offer whose
/// issuer, configuration and format are subsequently authenticated by the core.
public enum ConsumerIssuanceEntryPolicy {
    public static let supportedModes: [CredentialOfferEntryMode] = [.qrCode, .verifiedLink]
    public static let supportsArbitraryCredentialTypeSelection = false
    public static let addActionTitle = "Scan a QR code"
}

/// Visual tokens from the approved Add & Prove prototype. These are presentation-only: trusted
/// names, claims, retention and decisions continue to come exclusively from ScreenDescription.
public enum ConsumerDesign {
    public static let minimumTouchTarget: CGFloat = 44
    public static let primaryActionHeight: CGFloat = 50
    public static let actionCornerRadius: CGFloat = 14
    public static let surfaceCornerRadius: CGFloat = 16
    #if canImport(UIKit)
    public static let brand = Color(uiColor: UIColor { traits in
        traits.userInterfaceStyle == .dark
            ? UIColor(red: 126 / 255, green: 151 / 255, blue: 1, alpha: 1)
            : UIColor(red: 30 / 255, green: 58 / 255, blue: 192 / 255, alpha: 1)
    })
    public static let brandInk = Color(uiColor: UIColor { traits in
        traits.userInterfaceStyle == .dark
            ? UIColor(red: 201 / 255, green: 211 / 255, blue: 1, alpha: 1)
            : UIColor(red: 21 / 255, green: 36 / 255, blue: 121 / 255, alpha: 1)
    })
    public static let paper = Color(uiColor: .systemGroupedBackground)
    public static let surface = Color(uiColor: .secondarySystemGroupedBackground)
    public static let surfaceRaised = Color(uiColor: .tertiarySystemGroupedBackground)
    public static let line = Color(uiColor: .separator)
    #else
    public static let brand = Color(red: 30 / 255, green: 58 / 255, blue: 192 / 255)
    public static let brandInk = Color(red: 21 / 255, green: 36 / 255, blue: 121 / 255)
    public static let paper = Color(red: 238 / 255, green: 241 / 255, blue: 249 / 255)
    public static let surface = Color.white
    public static let surfaceRaised = Color(red: 241 / 255, green: 244 / 255, blue: 252 / 255)
    public static let line = Color(red: 214 / 255, green: 220 / 255, blue: 238 / 255)
    #endif
    public static let ink = Color.primary
    public static let mutedInk = Color.secondary
    public static let good = Color(red: 12 / 255, green: 110 / 255, blue: 70 / 255)
    public static let goodBackground = Color(red: 221 / 255, green: 241 / 255, blue: 231 / 255)
    public static let warning = Color(red: 126 / 255, green: 82 / 255, blue: 0)
    public static let warningBackground = Color(red: 250 / 255, green: 236 / 255, blue: 207 / 255)
    public static let critical = Color(red: 166 / 255, green: 42 / 255, blue: 27 / 255)
    public static let criticalBackground = Color(red: 250 / 255, green: 223 / 255, blue: 218 / 255)
}

public struct ConsumerPageModifier: ViewModifier {
    public func body(content: Content) -> some View {
        content
            .tint(ConsumerDesign.brand)
            .background(ConsumerDesign.paper.ignoresSafeArea())
    }
}

public extension View {
    func consumerPage() -> some View { modifier(ConsumerPageModifier()) }

    func consumerSurface(radius: CGFloat = 16) -> some View {
        padding(16)
            .background(ConsumerDesign.surface, in: RoundedRectangle(cornerRadius: radius, style: .continuous))
            .overlay {
                RoundedRectangle(cornerRadius: radius, style: .continuous)
                    .stroke(ConsumerDesign.line, lineWidth: 1)
            }
    }
}

public struct ConsumerPrimaryButtonStyle: ButtonStyle {
    public func makeBody(configuration: Configuration) -> some View {
        configuration.label
            .font(.headline)
            .foregroundStyle(.white)
            .frame(maxWidth: .infinity, minHeight: ConsumerDesign.primaryActionHeight)
            .padding(.horizontal, 16)
            .background(
                ConsumerDesign.brand.opacity(configuration.isPressed ? 0.78 : 1),
                in: RoundedRectangle(cornerRadius: ConsumerDesign.actionCornerRadius, style: .continuous))
            .scaleEffect(configuration.isPressed ? 0.99 : 1)
    }
}

public struct ConsumerSecondaryButtonStyle: ButtonStyle {
    public func makeBody(configuration: Configuration) -> some View {
        configuration.label
            .font(.headline)
            .foregroundStyle(ConsumerDesign.brand)
            .frame(maxWidth: .infinity, minHeight: ConsumerDesign.primaryActionHeight)
            .padding(.horizontal, 16)
            .background(
                ConsumerDesign.surfaceRaised.opacity(configuration.isPressed ? 0.72 : 1),
                in: RoundedRectangle(cornerRadius: ConsumerDesign.actionCornerRadius, style: .continuous))
    }
}

public struct ConsumerStatusOrb: View {
    let systemImage: String
    let tint: Color
    let background: Color

    public init(systemImage: String, tint: Color = ConsumerDesign.brand, background: Color? = nil) {
        self.systemImage = systemImage
        self.tint = tint
        self.background = background ?? ConsumerDesign.brand.opacity(0.1)
    }

    public var body: some View {
        Image(systemName: systemImage)
            .font(.system(size: 30, weight: .semibold))
            .foregroundStyle(tint)
            .frame(width: 76, height: 76)
            .background(background, in: Circle())
            .accessibilityHidden(true)
    }
}
#endif
