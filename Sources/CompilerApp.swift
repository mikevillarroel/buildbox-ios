// iPhone Compiler+Signer App
// Compiles Swift source on a Linux server, signs on-device, installs
//
// Workflow:
// 1. User writes/pastes Swift source (or imports .zip)
// 2. App sends source to server → server compiles → returns unsigned IPA
// 3. App signs IPA on-device with user's certificate (like ESign)
// 4. App installs the signed IPA
//
// Status: UI in progress. Server compiler backend pending (xtool work).

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
            CertificateView()
                .tabItem {
                    Label("Certificate", systemImage: "key.fill")
                }
                .tag(2)
            AboutView()
                .tabItem {
                    Label("About", systemImage: "info.circle")
                }
                .tag(3)
        }
    }
}
