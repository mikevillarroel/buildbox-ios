// iPhone Compiler+Signer App
// Compiles Swift source on GitHub, signs on-device, installs
//
// Workflow:
// 1. User writes/pastes Swift source (or imports .zip)
// 2. App sends source to server → server compiles → returns unsigned IPA
// 3. App signs IPA on-device with user's certificate (like ESign)
// 4. App installs the signed IPA

import SwiftUI

@main
struct CompilerApp: App {
    var body: some Scene {
        WindowGroup {
            ContentView()
        }
    }
}

struct ContentView: View {
    @State private var selectedTab = 0
    @State private var pendingSignIpa: URL? = nil
    @State private var showSplash = true

    var body: some View {
        TabView(selection: $selectedTab) {
            CompileView(selectedTab: $selectedTab, pendingSignIpa: $pendingSignIpa)
                .tabItem {
                    Label("Compile", systemImage: "hammer")
                }
                .tag(0)
            SignView(pendingSignIpa: $pendingSignIpa)
                .tabItem {
                    Label("Sign", systemImage: "signature")
                }
                .tag(1)
            LibraryView(pendingSignIpa: $pendingSignIpa, selectedTab: $selectedTab)
                .tabItem {
                    Label("Library", systemImage: "books.vertical")
                }
                .tag(2)
            AboutView()
                .tabItem {
                    Label("About", systemImage: "heart.fill")
                }
                .tag(3)
        }
        .preferredColorScheme(.dark)
        .fullScreenCover(isPresented: $showSplash) {
            SplashView { showSplash = false }
        }
        // "Open in BuildBox" / share-sheet imports (Info.extra.plist
        // declares .ipa documents): the IPA lands in the Sign tab,
        // inspected and ready to sign.
        .onOpenURL { url in
            handleIncomingIPA(url)
        }
    }

    private func handleIncomingIPA(_ url: URL) {
        guard url.pathExtension.lowercased() == "ipa" else { return }
        let scoped = url.startAccessingSecurityScopedResource()
        defer { if scoped { url.stopAccessingSecurityScopedResource() } }
        let docs = FileManager.default.urls(for: .documentDirectory, in: .userDomainMask).first!
        let dest = docs.appendingPathComponent("shared-\(url.lastPathComponent)")
        try? FileManager.default.removeItem(at: dest)
        if (try? FileManager.default.copyItem(at: url, to: dest)) != nil {
            pendingSignIpa = dest
            selectedTab = 1
            showSplash = false
        }
    }
}

// Launch splash (Miguel's design, 2026-10-21): the "How it works" guide
// lives here instead of the About tab — shown when the app opens, with a
// big blue Continue button, in the same card language as his other apps.
struct SplashView: View {
    let onContinue: () -> Void

    var body: some View {
        ZStack {
            Color.black.ignoresSafeArea()
            ScrollView {
                VStack(spacing: 14) {
                    VStack(spacing: 0) {
                        if let ui = UIImage(named: "BuildBoxIcon") {
                            Image(uiImage: ui)
                                .resizable()
                                .frame(width: 104, height: 104)
                                .cornerRadius(24)
                        }
                        Text("BuildBox")
                            .font(.system(size: 36, weight: .bold))
                            .padding(.top, 14)
                        Text("v2.0.0")
                            .font(.subheadline)
                            .foregroundColor(.secondary)
                            .padding(.top, 4)
                        Text("Compile on GitHub, sign on-device with your certificate, install.")
                            .multilineTextAlignment(.center)
                            .foregroundColor(.secondary)
                            .padding(.top, 12)
                    }
                    .frame(maxWidth: .infinity)
                    .padding(24)
                    .background(Color(.secondarySystemBackground))
                    .cornerRadius(26)

                    VStack(alignment: .leading, spacing: 10) {
                        Text("How it works")
                            .font(.title3)
                            .fontWeight(.bold)
                        Text("1. Write or import Swift source in the Compile tab")
                        Text("2. GitHub compiles it to an unsigned IPA")
                        Text("3. Import your certificate in the Sign tab (one time only)")
                        Text("4. Sign the IPA on-device in the Sign tab")
                        Text("5. Install directly on your iPhone")
                    }
                    .frame(maxWidth: .infinity, alignment: .leading)
                    .padding(24)
                    .background(Color(.secondarySystemBackground))
                    .cornerRadius(26)

                    Button("Continue") { onContinue() }
                        .buttonStyle(PressableBlueButtonStyle())
                        .padding(.top, 4)
                }
                .padding(14)
            }
        }
        .preferredColorScheme(.dark)
    }
}
