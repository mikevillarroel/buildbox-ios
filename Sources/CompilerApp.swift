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

// Remote update manifest (version.json in the buildbox-ios repo,
// Miguel's idea 2026-10-22): the app checks it at launch; if a newer
// version exists, the splash becomes the update screen that sends the
// user to the pretty download page instead of raw GitHub.
struct UpdateManifest: Decodable {
    let latest_version: String
    let notes: [String]
    let page_url: String
}

// Launch splash (Miguel's design, 2026-10-21): the "How it works" guide
// lives here instead of the About tab — shown when the app opens, with a
// big blue Continue button, in the same card language as his other apps.
// When the manifest announces a newer version (and the user hasn't
// dismissed that version), the guide card is replaced by the update
// card: big blue Update (opens the download page) + Dismiss (enters
// the app and silences this version for good).
struct SplashView: View {
    let onContinue: () -> Void

    @State private var update: UpdateManifest? = nil
    @AppStorage("dismissedUpdateVersion") private var dismissedUpdateVersion = ""

    private var currentVersion: String {
        Bundle.main.object(forInfoDictionaryKey: "CFBundleShortVersionString") as? String ?? "0"
    }

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
                        Text("v2.0.1")
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

                    if let u = update {
                        VStack(alignment: .leading, spacing: 10) {
                            Text("🚀 A new version is available")
                                .font(.title3)
                                .fontWeight(.bold)
                            Text("BuildBox \(u.latest_version)")
                                .font(.title3)
                                .fontWeight(.bold)
                                .foregroundColor(Color(red: 0.04, green: 0.52, blue: 1.0))
                            ForEach(u.notes, id: \.self) { note in
                                HStack(alignment: .top, spacing: 8) {
                                    Text("•")
                                        .fontWeight(.bold)
                                        .foregroundColor(Color(red: 0.04, green: 0.52, blue: 1.0))
                                    Text(note)
                                }
                            }
                        }
                        .frame(maxWidth: .infinity, alignment: .leading)
                        .padding(24)
                        .background(Color(.secondarySystemBackground))
                        .cornerRadius(26)

                        Button("Update") {
                            if let url = URL(string: u.page_url) {
                                UIApplication.shared.open(url)
                            }
                        }
                        .buttonStyle(PressableBlueButtonStyle())
                        .padding(.top, 4)

                        Button("Dismiss") {
                            dismissedUpdateVersion = u.latest_version
                            onContinue()
                        }
                        .foregroundColor(.secondary)
                    } else {
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
                }
                .padding(14)
            }
        }
        .preferredColorScheme(.dark)
        .task { await checkForUpdate() }
    }

    // Silent launch check: any failure (offline, bad JSON) just leaves
    // the normal splash in place.
    private func checkForUpdate() async {
        guard let url = URL(string: "https://raw.githubusercontent.com/mikevillarroel/buildbox-ios/main/version.json") else { return }
        var req = URLRequest(url: url)
        req.timeoutInterval = 5
        req.cachePolicy = .reloadIgnoringLocalCacheData
        guard let (data, _) = try? await URLSession.shared.data(for: req),
              let m = try? JSONDecoder().decode(UpdateManifest.self, from: data) else { return }
        if isVersion(m.latest_version, newerThan: currentVersion),
           dismissedUpdateVersion != m.latest_version {
            update = m
        }
    }

    private func isVersion(_ a: String, newerThan b: String) -> Bool {
        let pa = a.split(separator: ".").map { Int($0) ?? 0 }
        let pb = b.split(separator: ".").map { Int($0) ?? 0 }
        for i in 0..<max(pa.count, pb.count) {
            let x = i < pa.count ? pa[i] : 0
            let y = i < pb.count ? pb[i] : 0
            if x != y { return x > y }
        }
        return false
    }
}
