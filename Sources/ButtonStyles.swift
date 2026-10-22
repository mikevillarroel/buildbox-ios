import SwiftUI

// Shared button style with strong press feedback
struct PressableBlueButtonStyle: ButtonStyle {
    @Environment(\.isEnabled) private var isEnabled
    
    func makeBody(configuration: Configuration) -> some View {
        configuration.label
            .frame(maxWidth: .infinity)
            .padding(.vertical, 14)
            .background(isEnabled ? (configuration.isPressed ? Color.blue.opacity(0.5) : Color.blue) : Color.gray.opacity(0.4))
            .foregroundColor(isEnabled ? .white : .white.opacity(0.6))
            .font(.headline)
            .cornerRadius(12)
            .scaleEffect(configuration.isPressed && isEnabled ? 0.90 : 1.0)
            .opacity(configuration.isPressed && isEnabled ? 0.6 : 1.0)
            .animation(.easeInOut(duration: 0.1), value: configuration.isPressed)
    }
}

// Red destructive variant
struct PressableRedButtonStyle: ButtonStyle {
    func makeBody(configuration: Configuration) -> some View {
        configuration.label
            .frame(maxWidth: .infinity)
            .padding(.vertical, 14)
            .background(configuration.isPressed ? Color.red.opacity(0.5) : Color.red)
            .foregroundColor(.white)
            .font(.headline)
            .cornerRadius(12)
            .scaleEffect(configuration.isPressed ? 0.94 : 1.0)
            .opacity(configuration.isPressed ? 0.7 : 1.0)
            .animation(.easeInOut(duration: 0.08), value: configuration.isPressed)
    }
}

// Small blue variant (compact, for Copy Log) — green is reserved for
// Install buttons only (Miguel's color rule, 2026-10-21)
struct PressableSmallBlueButtonStyle: ButtonStyle {
    func makeBody(configuration: Configuration) -> some View {
        configuration.label
            .padding(.horizontal, 20)
            .padding(.vertical, 8)
            .background(configuration.isPressed ? Color.blue.opacity(0.5) : Color.blue)
            .foregroundColor(.white)
            .font(.subheadline)
            .cornerRadius(10)
            .scaleEffect(configuration.isPressed ? 0.94 : 1.0)
            .opacity(configuration.isPressed ? 0.7 : 1.0)
            .animation(.easeInOut(duration: 0.08), value: configuration.isPressed)
    }
}

// Small red variant (compact, for Clear)
struct PressableSmallRedButtonStyle: ButtonStyle {
    func makeBody(configuration: Configuration) -> some View {
        configuration.label
            .padding(.horizontal, 20)
            .padding(.vertical, 8)
            .background(configuration.isPressed ? Color.red.opacity(0.5) : Color.red)
            .foregroundColor(.white)
            .font(.subheadline)
            .cornerRadius(10)
            .scaleEffect(configuration.isPressed ? 0.94 : 1.0)
            .opacity(configuration.isPressed ? 0.7 : 1.0)
            .animation(.easeInOut(duration: 0.08), value: configuration.isPressed)
    }
}

// Green variant — Miguel's rule (2026-10-21): Install buttons are GREEN
// everywhere in the app (same green as the Cash App donate button).
struct PressableGreenButtonStyle: ButtonStyle {
    @Environment(\.isEnabled) private var isEnabled
    private let green = Color(red: 0.0, green: 0.84, blue: 0.2)

    func makeBody(configuration: Configuration) -> some View {
        configuration.label
            .frame(maxWidth: .infinity)
            .padding(.vertical, 14)
            .background(isEnabled ? (configuration.isPressed ? green.opacity(0.5) : green) : Color.gray.opacity(0.4))
            .foregroundColor(isEnabled ? .white : .white.opacity(0.6))
            .font(.headline)
            .cornerRadius(12)
            .scaleEffect(configuration.isPressed && isEnabled ? 0.90 : 1.0)
            .opacity(configuration.isPressed && isEnabled ? 0.6 : 1.0)
            .animation(.easeInOut(duration: 0.1), value: configuration.isPressed)
    }
}
