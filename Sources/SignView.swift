import SwiftUI
import UIKit

struct SignView: View {
    // IPA handed over from the Compile tab's "Continue to Sign" button.
    // Set by CompileView, consumed once in onAppear, then cleared.
    @Binding var pendingSignIpa: URL?

    @AppStorage("hasCertificate") private var hasCertificate = false
    @AppStorage("certP12Name") private var certP12Name = ""
    
    @State private var ipaURL: URL?
    
    @State private var appName = "MyApp"
    @State private var bundleID = "com.myapp.app"
    @State private var version = "1.0.0"
    @State private var packageName = ""
    
    @State private var isSigning = false
    @State private var signStatus = ""
    @State private var signLog = ""
    @State private var signedIPAURL: URL?
    @State private var importedIsSigned = false
    @State private var signStartedAt: Date?
    @State private var signHeartbeat: Timer?
    @State private var lastSignPhase = ""
    @State private var showingShare = false
    @State private var isInstalling = false
    @State private var dotsTimer: Timer?
    @State private var showingIPAImporter = false
    @State private var injectDylibURLs: [URL] = []
    @State private var showingDylibImporter = false
    @State private var showingClearConfirm = false
    @State private var showingClearIpaConfirm = false
    @State private var importedIconData: Data?
    @State private var dylibToRemove: URL?
    @State private var showingDylibRemoveConfirm = false
    @FocusState private var focusedField: Field?
    
    enum Field {
        case appName, bundleID, version, packageName
    }
    
    var body: some View {
        NavigationView {
            Form {
                // Header (mirrors Compile tab exactly: icon + title)
                Section {
                    VStack(spacing: 20) {
                        Image(systemName: "signature")
                            .font(.system(size: 60))
                            .foregroundColor(.secondary)
                        Text("Sign")
                            .font(.title2)
                            .fontWeight(.bold)
                    }
                    .frame(maxWidth: .infinity)
                    .padding(.vertical, 6)
                }
                .listRowBackground(Color.clear)

                // Import IPA
                Section {
                    Button("Import IPA") {
                        showingIPAImporter = true
                    }
                    .buttonStyle(PressableBlueButtonStyle())
                    if let url = ipaURL {
                        Text(url.lastPathComponent)
                            .font(.caption)
                            .foregroundColor(.secondary)
                    }
                    if let iconData = importedIconData, let uiIcon = UIImage(data: iconData) {
                        HStack(spacing: 10) {
                            Image(uiImage: uiIcon)
                                .resizable()
                                .frame(width: 44, height: 44)
                                .clipShape(RoundedRectangle(cornerRadius: 10))
                            VStack(alignment: .leading, spacing: 2) {
                                Text(appName.isEmpty ? "App" : appName)
                                    .font(.subheadline)
                                Text(bundleID)
                                    .font(.caption)
                                    .foregroundColor(.secondary)
                            }
                            Spacer()
                        }
                    }
                    if ipaURL != nil {
                        Button("Clear IPA") {
                            showingClearIpaConfirm = true
                        }
                        .foregroundColor(.red)
                        .alert("Clear Imported IPA?", isPresented: $showingClearIpaConfirm) {
                            Button("Clear IPA", role: .destructive) {
                                ipaURL = nil
                                signedIPAURL = nil
                                appName = ""
                                bundleID = ""
                                version = ""
                                packageName = ""
                                importedIsSigned = false
                                importedIconData = nil
                                signStatus = ""
                                signLog += "Imported IPA cleared.\n"
                            }
                            Button("Cancel", role: .cancel) { }
                        } message: {
                            Text("Are you sure you want to clear the imported IPA?")
                        }
                    }
                }
                .sheet(isPresented: $showingIPAImporter) {
                    DocumentPicker { urls in
                        showingIPAImporter = false
                        if let url = urls.first {
                            // Copy to Documents
                            let docs = FileManager.default.urls(for: .documentDirectory, in: .userDomainMask).first!
                            let dest = docs.appendingPathComponent(url.lastPathComponent)
                            try? FileManager.default.removeItem(at: dest)
                            let finalURL: URL
                            if (try? FileManager.default.copyItem(at: url, to: dest)) != nil {
                                finalURL = dest
                            } else {
                                finalURL = url
                            }
                            ipaURL = finalURL
                            signedIPAURL = nil
                            importedIsSigned = false
                            signLog = ""
                            inspectIPA(finalURL)
                        }
                    }
                }
                
                // App Info (compact: all fields in one section)
                Section(header: Text("App Info")) {
                    HStack {
                        Text("App Name")
                            .frame(width: 86, alignment: .leading)
                        TextField("MyApp", text: $appName)
                            .foregroundColor(.secondary)
                            .focused($focusedField, equals: .appName)
                    }
                    HStack {
                        Text("Bundle ID")
                            .frame(width: 86, alignment: .leading)
                        TextField("com.myapp.app", text: $bundleID)
                            .foregroundColor(.secondary)
                            .autocapitalization(.none)
                            .focused($focusedField, equals: .bundleID)
                    }
                    HStack {
                        Text("Version")
                            .frame(width: 86, alignment: .leading)
                        TextField("1.0.0", text: $version)
                            .foregroundColor(.secondary)
                            .focused($focusedField, equals: .version)
                    }
                    HStack {
                        Text("Package")
                            .frame(width: 86, alignment: .leading)
                        TextField("MyApp_1.0.0.ipa", text: $packageName)
                            .foregroundColor(.secondary)
                            .autocapitalization(.none)
                            .focused($focusedField, equals: .packageName)
                    }
                }

                // Injection (optional dylibs woven into the app at sign time)
                Section(header: Text("Injection (optional)")) {
                    ForEach(injectDylibURLs, id: \.path) { url in
                        HStack {
                            Text(url.lastPathComponent)
                                .foregroundColor(.secondary)
                                .lineLimit(1)
                            Spacer()
                            Button("Remove", role: .destructive) {
                                dylibToRemove = url
                                showingDylibRemoveConfirm = true
                            }
                            .foregroundColor(.red)
                        }
                    }
                    Button("Add Dylib…") {
                        showingDylibImporter = true
                    }
                    if injectDylibURLs.isEmpty {
                        Text("Dylibs are copied into the app and loaded at launch — how tweaks and mods are made.")
                            .font(.caption)
                            .foregroundColor(.secondary)
                    }
                }
                .sheet(isPresented: $showingDylibImporter) {
                    DocumentPicker { urls in
                        showingDylibImporter = false
                        let docs = FileManager.default.urls(for: .documentDirectory, in: .userDomainMask).first!
                        for url in urls where url.pathExtension.lowercased() == "dylib" {
                            let dest = docs.appendingPathComponent(url.lastPathComponent)
                            try? FileManager.default.removeItem(at: dest)
                            if (try? FileManager.default.copyItem(at: url, to: dest)) != nil {
                                if !injectDylibURLs.contains(dest) { injectDylibURLs.append(dest) }
                            } else if !injectDylibURLs.contains(url) {
                                injectDylibURLs.append(url)
                            }
                        }
                    }
                }
                .alert("Remove Dylib?", isPresented: $showingDylibRemoveConfirm) {
                    Button("Yes", role: .destructive) {
                        if let url = dylibToRemove { injectDylibURLs.removeAll { $0 == url } }
                        dylibToRemove = nil
                    }
                    Button("Cancel", role: .cancel) { dylibToRemove = nil }
                } message: {
                    Text("Are you sure you want to remove \(dylibToRemove?.lastPathComponent ?? "this dylib")?")
                }

                // Certificate (integrated one-time import)
                CertificateSection()
                
                // Signature button - big blue like TendieMaker, tappable anywhere
                Section {
                    Button(action: sign) {
                        if isSigning {
                            ProgressView()
                                .progressViewStyle(CircularProgressViewStyle(tint: .white))
                        } else {
                            Text("Signature")
                                .frame(maxWidth: .infinity)
                        }
                    }
                    .buttonStyle(PressableBlueButtonStyle())
                    .disabled(ipaURL == nil || isSigning || !hasCertificate)

                    // Install App — same section, right under Signature (compact)
                    Button("Install App") {
                        // Use signed IPA if available, otherwise the imported IPA directly
                        guard let ipa = signedIPAURL ?? ipaURL else { return }
                        isInstalling = true
                        startDots()
                        // Read ACTUAL metadata from the IPA (not form fields) to ensure manifest matches
                        let meta = IPASigner.shared.readMetadata(ipaURL: ipa)
                        let realBundleID = meta.bundleID ?? bundleID
                        let realAppName = meta.appName ?? appName
                        let realVersion = meta.version ?? version
                        LocalInstaller.install(
                            ipaURL: ipa,
                            bundleID: realBundleID,
                            appName: realAppName,
                            version: realVersion,
                            progress: { msg in
                                DispatchQueue.main.async {
                                    if msg == "Installing..." {
                                        // Add without newline, dots will append
                                        self.signLog += "[BuildBox] Installing"
                                    } else {
                                        // Stop dots timer before adding new line
                                        self.dotsTimer?.invalidate()
                                        self.dotsTimer = nil
                                        // Ensure previous line ended (dots line)
                                        if !self.signLog.hasSuffix("\n") {
                                            self.signLog += "\n"
                                        }
                                        self.signLog += "[BuildBox] \(msg)\n"
                                    }
                                }
                            },
                            completion: { result in
                                DispatchQueue.main.async {
                                    self.isInstalling = false
                                    self.stopDots()
                                    switch result {
                                    case .success:
                                        self.signLog += "[BuildBox] Installer opened\n"
                                    case .failure(let error):
                                        self.signLog += "[BuildBox] Install failed: \(error.localizedDescription)\n"
                                    }
                                }
                            }
                        )
                    }
                    .buttonStyle(PressableGreenButtonStyle())
                    .disabled((signedIPAURL == nil && !importedIsSigned) || isInstalling)
                    if ipaURL != nil && signedIPAURL == nil && !importedIsSigned {
                        Text("This IPA is not signed yet — tap Signature first. Install only works with a signed IPA.")
                            .font(.caption)
                            .foregroundColor(.orange)
                    }
                }

                // Verbose signing log
                if !signLog.isEmpty {
                    Section(header: Text("Signing Log")) {
                        ScrollView {
                            Text(signLog)
                                .font(.system(.caption, design: .monospaced))
                                .frame(maxWidth: .infinity, alignment: .leading)
                        }
                        .frame(minHeight: 180, maxHeight: 320)
                    }
                }
                
                // Copy Log + Clear buttons (small, centered, no row background)
                if !signLog.isEmpty {
                    HStack {
                        Spacer()
                        Button("Copy Log") {
                            UIPasteboard.general.string = signLog
                        }
                        .buttonStyle(PressableSmallBlueButtonStyle())
                        if isSigning || isInstalling {
                            Button("Cancel") {
                                if isSigning {
                                    IPASigner.shared.cancelCurrentSign()
                                    signLog += "[BuildBox] Cancelling... (stops at the next step)\n"
                                }
                                if isInstalling {
                                    LocalInstaller.cancelActiveInstall()
                                    isInstalling = false
                                    stopDots()
                                    signLog += "[BuildBox] Install cancelled by user\n"
                                }
                            }
                            .buttonStyle(PressableSmallRedButtonStyle())
                        }
                        Button("Clear") {
                            showingClearConfirm = true
                        }
                        .buttonStyle(PressableSmallRedButtonStyle())
                        .alert("Clear Sign Form?", isPresented: $showingClearConfirm) {
                            Button("Yes", role: .destructive) {
                                // Reset IPA state (injection list included)
                                ipaURL = nil
                                signedIPAURL = nil
                                appName = ""
                                bundleID = ""
                                version = ""
                                packageName = ""
                                signStatus = ""
                                signLog = ""
                                injectDylibURLs = []
                                importedIconData = nil
                            }
                            Button("Cancel", role: .cancel) { }
                        } message: {
                            Text("Are you sure you want to clear the imported IPA, the form, the injection list and the log?")
                        }
                        Spacer()
                    }
                    .padding(.vertical, 2)
                    .listRowBackground(Color.clear)
                    .listRowInsets(EdgeInsets(top: 0, leading: 0, bottom: 0, trailing: 0))
                }
            }
            .navigationTitle("")
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItemGroup(placement: .keyboard) {
                    Spacer()
                    Button("Done") {
                        focusedField = nil
                    }
                }
            }
            .onAppear {
                if packageName.isEmpty {
                    packageName = "\(appName)_\(version).ipa"
                }
                // IPA handed over from the Compile tab's "Continue to Sign" —
                // load it once into the Sign tab, then clear the handoff
                if let pending = pendingSignIpa {
                    ipaURL = pending
                    pendingSignIpa = nil
                    inspectIPA(pending)
                }
                // Belt-and-suspenders for share-sheet imports: files
                // shared INTO BuildBox land in Documents/Inbox. If the
                // onOpenURL handoff got swallowed (cold-launch timing),
                // the IPA is still picked up here instead of vanishing
                // (Miguel's 2026-10-21 report: "abre BuildBox pero no
                // carga el IPA").
                if ipaURL == nil {
                    let inbox = docsDir.appendingPathComponent("Inbox")
                    if let files = try? FileManager.default.contentsOfDirectory(at: inbox, includingPropertiesForKeys: nil),
                       let shared = files.first(where: { $0.pathExtension.lowercased() == "ipa" }) {
                        let dest = docsDir.appendingPathComponent("shared-\(shared.lastPathComponent)")
                        try? FileManager.default.removeItem(at: dest)
                        if (try? FileManager.default.copyItem(at: shared, to: dest)) != nil {
                            try? FileManager.default.removeItem(at: shared)
                            ipaURL = dest
                            inspectIPA(dest)
                        }
                    }
                }
            }
            // If a share arrives while this tab is already on screen,
            // onAppear never re-fires — react to the handoff directly.
            .onChange(of: pendingSignIpa) { _, newValue in
                if let pending = newValue {
                    ipaURL = pending
                    pendingSignIpa = nil
                    inspectIPA(pending)
                }
            }
        }
    }
    
    private let spinnerChars = ["⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"]
    @State private var spinnerIndex = 0
    
    private func startDots() {
        dotsTimer?.invalidate()
        spinnerIndex = 0
        dotsTimer = Timer.scheduledTimer(withTimeInterval: 0.15, repeats: true) { _ in
            DispatchQueue.main.async {
                // Replace last spinner char with next one (rotating braille spinner)
                if !self.signLog.isEmpty {
                    self.signLog.removeLast()
                }
                self.signLog += self.spinnerChars[self.spinnerIndex]
                self.spinnerIndex = (self.spinnerIndex + 1) % self.spinnerChars.count
            }
        }
    }
    
    private func stopDots() {
        dotsTimer?.invalidate()
        dotsTimer = nil
        signLog += "\n"
    }
    
    /// Read an imported/handed-over IPA on a background queue: fill the
    /// name/bundle/version fields and detect whether it already carries a
    /// code signature (that detection gates the Install App button).
    private func inspectIPA(_ url: URL) {
        signStatus = "Reading IPA..."
        importedIconData = nil
        DispatchQueue.global(qos: .userInitiated).async {
            // Fast phase: metadata + icon land on the form immediately.
            let meta = IPASigner.shared.readMetadata(ipaURL: url)
            let icon = IPASigner.shared.readIconData(ipaURL: url)
            DispatchQueue.main.async {
                if let n = meta.appName { appName = n }
                if let b = meta.bundleID { bundleID = b }
                if let v = meta.version {
                    version = v
                    packageName = "\(appName)_\(v).ipa"
                }
                importedIconData = icon
                signStatus = meta.appName == nil ? "Could not read IPA metadata" : ""
            }
            // Slow phase: the signed check reads the app's whole executable
            // (hundreds of MB on big apps) — it must never hold the
            // metadata hostage, so it updates the Install gate separately.
            let signed = IPASigner.shared.isSigned(ipaURL: url)
            DispatchQueue.main.async {
                importedIsSigned = signed
            }
        }
    }

    private func sign() {
        guard let ipa = ipaURL else { return }
        guard hasCertificate else {
            signStatus = "Import a certificate first"
            return
        }
        
        // Get persisted certificate URLs
        let docs = FileManager.default.urls(for: .documentDirectory, in: .userDomainMask).first!
        let p12Name = UserDefaults.standard.string(forKey: "certP12Name") ?? ""
        let provName = UserDefaults.standard.string(forKey: "certProvisionName") ?? ""
        
        guard !p12Name.isEmpty, !provName.isEmpty else {
            signStatus = "Certificate not found — reimport it in the Certificate section above"
            return
        }
        
        let p12URL = docs.appendingPathComponent(p12Name)
        let provURL = docs.appendingPathComponent(provName)
        
        guard FileManager.default.fileExists(atPath: p12URL.path),
              FileManager.default.fileExists(atPath: provURL.path) else {
            signStatus = "Certificate files missing — reimport it in the Certificate section above"
            return
        }
        
        // Get password from stored value
        let password = UserDefaults.standard.string(forKey: "certP12Password") ?? ""
        
        isSigning = true
        signStatus = "Signing \(appName) v\(version)..."
        signLog = "[BuildBox] Starting sign for \(appName) with zsign...\n"
        startDots()
        // Heartbeat: the log must never look dead — every 20s it reports
        // the current phase and elapsed time (Miguel's no-blind-spinner rule).
        signStartedAt = Date()
        lastSignPhase = "Starting"
        signHeartbeat?.invalidate()
        signHeartbeat = Timer.scheduledTimer(withTimeInterval: 20, repeats: true) { _ in
            guard self.isSigning, let start = self.signStartedAt else { return }
            let secs = Int(Date().timeIntervalSince(start))
            self.signLog += "[BuildBox] ... still working: \(self.lastSignPhase) (\(secs)s)\n"
        }
        
        IPASigner.shared.signWithZSign(
            ipaURL: ipa,
            p12URL: p12URL,
            p12Password: password,
            provisionURL: provURL,
            appName: appName,
            bundleID: bundleID,
            version: version,
            injectDylibs: injectDylibURLs,
            progress: { msg in
                DispatchQueue.main.async {
                    self.signStatus = msg
                    self.lastSignPhase = msg
                    self.signLog += "[BuildBox] \(msg)\n"
                }
            },
            completion: { result in
                self.isSigning = false
                self.signHeartbeat?.invalidate()
                self.signHeartbeat = nil
                self.stopDots()
                switch result {
                case .success(let url):
                    // Move to Documents with package name
                    let dest = docs.appendingPathComponent(self.packageName)
                    try? FileManager.default.removeItem(at: dest)
                    try? FileManager.default.copyItem(at: url, to: dest)
                    self.signedIPAURL = dest
                    self.registerSigned(dest: dest)
                    self.signStatus = "Signed successfully!"
                    self.signLog += "[BuildBox] Signed successfully: \(dest.lastPathComponent)\n"
                    self.signLog += "[BuildBox] Saved to the Library tab — install or share it from there.\n"
                case .failure(let error):
                    self.signStatus = "Signing failed: \(error.localizedDescription)"
                    self.signLog += "[BuildBox] FAILED: \(error.localizedDescription)\n"
                }
            }
        )
    }

    // MARK: - Signed library registration

    private var docsDir: URL {
        FileManager.default.urls(for: .documentDirectory, in: .userDomainMask).first!
    }

    // After a successful sign, register the IPA in the library (its own
    // tab) so it can be installed later without re-signing.
    private func registerSigned(dest: URL) {
        let attrs = try? FileManager.default.attributesOfItem(atPath: dest.path)
        let sizeMB = (attrs?[.size] as? NSNumber).map { $0.doubleValue / 1_000_000 } ?? 0
        let entry = SignedIPAEntry(fileName: dest.lastPathComponent, appName: appName,
                                   bundleID: bundleID, version: version,
                                   date: Date().timeIntervalSince1970, sizeMB: sizeMB)
        var list = SignedLibraryStore.load().filter { $0.fileName != entry.fileName }
        list.insert(entry, at: 0)
        SignedLibraryStore.save(list)
        if let iconData = importedIconData {
            let dir = docsDir.appendingPathComponent("lib-icons")
            try? FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
            try? iconData.write(to: dir.appendingPathComponent(entry.fileName + ".png"))
        }
    }
}

struct AboutView: View {
    private func bundleImage(_ name: String) -> Image {
        // UIImage(named:) handles @2x/@3x automatically from main bundle
        if let uiImage = UIImage(named: name) {
            return Image(uiImage: uiImage)
        }
        // Fallback: try explicit path
        if let path = Bundle.main.path(forResource: name, ofType: "png"),
           let uiImage = UIImage(contentsOfFile: path) {
            return Image(uiImage: uiImage)
        }
        // Last resort: system placeholder
        return Image(systemName: "app.fill")
    }

    // About in the Layers / TendieMaker design (Miguel's rule, 2026-10-21):
    // dark cards, dev row with brand social buttons, big eye-catching
    // donate buttons. No "How it works" here — that lives on the splash.
    var body: some View {
        NavigationView {
            ZStack {
                Color.black.ignoresSafeArea()
                ScrollView {
                    VStack(spacing: 14) {
                        // Card 1: identity
                        VStack(spacing: 0) {
                            bundleImage("BuildBoxIcon")
                                .resizable()
                                .frame(width: 104, height: 104)
                                .cornerRadius(24)
                            Text("BuildBox")
                                .font(.system(size: 34, weight: .bold))
                                .padding(.top, 14)
                            Text("v2.0.0")
                                .font(.subheadline)
                                .foregroundColor(.secondary)
                                .padding(.top, 4)
                            Text("Compile on GitHub, sign on-device with your certificate, install.")
                                .font(.body)
                                .foregroundColor(.secondary)
                                .multilineTextAlignment(.center)
                                .padding(.top, 12)
                        }
                        .frame(maxWidth: .infinity)
                        .padding(24)
                        .background(Color(.secondarySystemBackground))
                        .cornerRadius(26)

                        // Card 2: people + support
                        VStack(spacing: 0) {
                            HStack(spacing: 12) {
                                bundleImage("profile-photo")
                                    .resizable()
                                    .frame(width: 56, height: 56)
                                    .clipShape(Circle())
                                VStack(alignment: .leading, spacing: 2) {
                                    Text("Miguel Villarroel")
                                        .font(.headline)
                                    Text("Developer")
                                        .font(.caption)
                                        .foregroundColor(.secondary)
                                }
                                Spacer()
                                HStack(spacing: 8) {
                                    Link(destination: URL(string: "https://x.com/MikeBuildsApp")!) {
                                        bundleImage("x-logo")
                                            .resizable()
                                            .frame(width: 44, height: 44)
                                            .cornerRadius(11)
                                    }
                                    Link(destination: URL(string: "https://instagram.com/mikevillarroel")!) {
                                        bundleImage("instagram-logo")
                                            .resizable()
                                            .frame(width: 44, height: 44)
                                            .cornerRadius(11)
                                    }
                                    Link(destination: URL(string: "https://discord.gg/3C3fygY35E")!) {
                                        bundleImage("discord-logo")
                                            .resizable()
                                            .frame(width: 44, height: 44)
                                            .cornerRadius(11)
                                    }
                                }
                            }
                            Divider()
                                .padding(.vertical, 14)
                            HStack(spacing: 12) {
                                Text("🤖")
                                    .font(.system(size: 30))
                                    .frame(width: 56, height: 56)
                                    .background(Color(.systemGray5))
                                    .clipShape(Circle())
                                VStack(alignment: .leading, spacing: 2) {
                                    Text("MikeBorg")
                                        .font(.headline)
                                    Text("Collaborator")
                                        .font(.caption)
                                        .foregroundColor(.secondary)
                                }
                                Spacer()
                            }
                            Divider()
                                .padding(.vertical, 14)
                            Text("Support BuildBox")
                                .font(.system(size: 22, weight: .bold))
                                .frame(maxWidth: .infinity, alignment: .leading)
                            Link(destination: URL(string: "https://paypal.me/mikevillarroel")!) {
                                VStack(spacing: 2) {
                                    Text("Donate with PayPal")
                                        .font(.system(size: 20, weight: .bold))
                                        .foregroundColor(.white)
                                    Text("@mikevillarroel")
                                        .font(.subheadline)
                                        .foregroundColor(.white.opacity(0.75))
                                }
                                .frame(maxWidth: .infinity)
                                .padding(.vertical, 15)
                                .background(Color(red: 0.04, green: 0.52, blue: 1.0))
                                .cornerRadius(16)
                            }
                            .padding(.top, 14)
                            Link(destination: URL(string: "https://cash.app/$mikevillarroel")!) {
                                VStack(spacing: 2) {
                                    Text("Donate with Cash App")
                                        .font(.system(size: 20, weight: .bold))
                                        .foregroundColor(.white)
                                    Text("$mikevillarroel")
                                        .font(.subheadline)
                                        .foregroundColor(.white.opacity(0.75))
                                }
                                .frame(maxWidth: .infinity)
                                .padding(.vertical, 15)
                                .background(Color(red: 0.0, green: 0.84, blue: 0.2))
                                .cornerRadius(16)
                            }
                            .padding(.top, 12)
                        }
                        .padding(20)
                        .background(Color(.secondarySystemBackground))
                        .cornerRadius(26)
                    }
                    .padding(14)
                }
            }
            .navigationTitle("")
            .navigationBarTitleDisplayMode(.inline)
        }
    }
}