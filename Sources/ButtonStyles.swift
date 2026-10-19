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

// Small green variant (compact, for Copy Log)
struct PressableSmallGreenButtonStyle: ButtonStyle {
    func makeBody(configuration: Configuration) -> some View {
        configuration.label
            .padding(.horizontal, 20)
            .padding(.vertical, 8)
            .background(configuration.isPressed ? Color.green.opacity(0.5) : Color.green)
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
