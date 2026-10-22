import SwiftUI
import UIKit
import UniformTypeIdentifiers
import Security
import UIKit

// MARK: - Share Sheet
struct ShareSheet: UIViewControllerRepresentable {
    var items: [Any]
    
    func makeUIViewController(context: Context) -> UIActivityViewController {
        UIActivityViewController(activityItems: items, applicationActivities: nil)
    }
    
    func updateUIViewController(_ uiViewController: UIActivityViewController, context: Context) {}
}

// Identifiable wrapper for share sheet item (fixes empty-on-first-present bug)
struct ShareItem: Identifiable {
    let id = UUID()
    let url: URL
}

struct DocumentPicker: UIViewControllerRepresentable {    var onPick: ([URL]) -> Void
    
    func makeUIViewController(context: Context) -> UIDocumentPickerViewController {
        let picker = UIDocumentPickerViewController(forOpeningContentTypes: [.data], asCopy: true)
        picker.delegate = context.coordinator
        picker.allowsMultipleSelection = true
        return picker
    }
    
    func updateUIViewController(_ uiViewController: UIDocumentPickerViewController, context: Context) {}
    
    func makeCoordinator() -> Coordinator {
        Coordinator(onPick: onPick)
    }
    
    class Coordinator: NSObject, UIDocumentPickerDelegate {
        var onPick: ([URL]) -> Void
        init(onPick: @escaping ([URL]) -> Void) { self.onPick = onPick }
        func documentPicker(_ controller: UIDocumentPickerViewController, didPickDocumentsAt urls: [URL]) {
            onPick(urls)
        }
    }
}

// MARK: - GitHub Keychain Storage
struct GitHubKeychain {
    static let service = "com.mikevillarroel.buildbox.github"
    
    static func saveToken(_ token: String) -> Bool {
        guard let data = token.data(using: .utf8) else { return false }
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: "github-token"
        ]
        SecItemDelete(query as CFDictionary)
        let addQuery: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: "github-token",
            kSecValueData as String: data,
            kSecAttrAccessible as String: kSecAttrAccessibleWhenUnlockedThisDeviceOnly
        ]
        return SecItemAdd(addQuery as CFDictionary, nil) == errSecSuccess
    }
    
    static func getToken() -> String? {
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: "github-token",
            kSecReturnData as String: true
        ]
        var result: AnyObject?
        guard SecItemCopyMatching(query as CFDictionary, &result) == errSecSuccess,
              let data = result as? Data else { return nil }
        return String(data: data, encoding: .utf8)
    }
    
    static func deleteToken() {
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: "github-token"
        ]
        SecItemDelete(query as CFDictionary)
    }
}

struct CompileView: View {
    @State private var sourceCode = ""
    @State private var sourceZipURL: URL?
    @State private var sourceZipName = ""
    @State private var isCompiling = false
    @State private var compileStatus = ""
    @State private var ipaURL: URL?
    @State private var showingImporter = false
    @State private var projectName = ""
    @State private var projectNameIsAuto = true
    @State private var lastAutoName = ""
    @State private var buildLog = ""
    @State private var showingLog = false
    @State private var githubConnected = false
    @State private var dotsTimer: Timer?
    private let spinnerChars = ["⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"]
    @State private var spinnerIndex = 0
    @State private var githubUsername = ""
    @State private var showingGitHubConnect = false
    @State private var githubTokenInput = ""
    @State private var shareItem: ShareItem?
    @State private var showingDisconnectConfirm = false
    @State private var showingClearLogConfirm = false
    @State private var shareURL: URL?

    // Handoff to the Sign tab: set pendingSignIpa, then flip selectedTab to Sign
    @Binding var selectedTab: Int
    @Binding var pendingSignIpa: URL?
    
    var body: some View {
        NavigationView {
            ScrollView {
            VStack(spacing: 12) {
                // Header (consistent with Sign tab style - VStack spacing 20, no extra padding)
                VStack(spacing: 20) {
                    Image(systemName: "hammer")
                        .font(.system(size: 60))
                        .foregroundColor(.secondary)
                    Text("Compile")
                        .font(.title2)
                        .fontWeight(.bold)
                }
                
                // GitHub requirement banner (first requirement)
                if !githubConnected {
                    VStack(alignment: .leading, spacing: 8) {
                        HStack {
                            Image(systemName: "exclamationmark.triangle.fill")
                                .foregroundColor(.orange)
                            Text("GitHub Required")
                                .font(.headline)
                        }
                        Text("Connect your GitHub account to compile. Your code stays in your private repos — we never see it. Uses your free Actions minutes.")
                            .font(.caption)
                            .foregroundColor(.secondary)
                        Button(action: { showingGitHubConnect = true }) {
                            Text("Connect GitHub")
                                .frame(maxWidth: .infinity)
                        }
                        .buttonStyle(PressableBlueButtonStyle())
                    }
                    .padding()
                    .background(Color.orange.opacity(0.1))
                    .cornerRadius(12)
                    .padding(.horizontal)
                    .padding(.top, 8)
                } else {
                    VStack(spacing: 8) {
                        HStack {
                            Image(systemName: "checkmark.circle.fill")
                                .foregroundColor(.green)
                            Text("GitHub: @\(githubUsername)")
                                .font(.subheadline)
                            Spacer()
                        }
                        Button("Disconnect GitHub") {
                            showingDisconnectConfirm = true
                        }
                        .buttonStyle(PressableRedButtonStyle())
                        .alert("Disconnect GitHub?", isPresented: $showingDisconnectConfirm) {
                            Button("Yes", role: .destructive) {
                                GitHubKeychain.deleteToken()
                                githubConnected = false
                                githubUsername = ""
                            }
                            Button("Cancel", role: .cancel) { }
                        } message: {
                            Text("Are you sure you want to disconnect?")
                        }
                    }
                    .padding(.horizontal)
                    .padding(.horizontal)
                    .padding(.top, 8)
                }
                
                // Project name
                HStack {
                    Text("Project:")
                        .font(.subheadline)
                        .foregroundColor(.white)
                    TextField("Input your project name", text: $projectName)
                        .textFieldStyle(.roundedBorder)
                        .font(.subheadline)
                        .onChange(of: projectName) { newValue in
                            // A manual edit wins: stop auto-filling
                            if newValue != lastAutoName { projectNameIsAuto = false }
                        }
                }
                .padding(.horizontal)
                .padding(.top, 8)
                
                // Source editor header
                HStack {
                    Text("Swift Source")
                        .font(.headline)
                    Spacer()
                    Button("Import") {
                        showingImporter = true
                    }
                    .buttonStyle(PressableBlueButtonStyle())
                    .disabled(ipaURL != nil)
                }
                .padding(.horizontal)
                .padding(.top, 8)
                
                // Code editor OR build log (build log takes over during/after build)
                if isCompiling || !buildLog.isEmpty {
                    // Show build log in the editor space
                    ScrollView {
                        Text(buildLog)
                            .font(.system(.body, design: .monospaced))
                            .frame(maxWidth: .infinity, alignment: .leading)
                            .padding(8)
                    }
                    .border(Color.gray.opacity(0.3), width: 1)
                    .cornerRadius(8)
                    .padding(.horizontal)
                    .frame(minHeight: 320)
                } else {
                    TextEditor(text: $sourceCode)
                        .font(.system(.body, design: .monospaced))
                        .onChange(of: sourceCode) { _ in
                            if let name = Self.deriveName(fromSource: sourceCode) {
                                autoFillProjectName(name)
                            }
                        }
                        .border(Color.gray.opacity(0.3), width: 1)
                        .cornerRadius(8)
                        .padding(.horizontal)
                        .frame(minHeight: 200)
                }
                
                // Status (red if failed)
                if !compileStatus.isEmpty {
                    Text(compileStatus)
                        .font(.caption)
                        .foregroundColor(compileStatus.lowercased().contains("fail") ? .red : .secondary)
                        .padding(.horizontal)
                        .padding(.top, 4)
                }
                
                // Compile button - hidden while compiling, disabled after successful compile
                if !isCompiling {
                    Button(action: compile) {
                        Text("Compile on GitHub")
                            .frame(maxWidth: .infinity)
                    }
                    .buttonStyle(PressableBlueButtonStyle())
                    .disabled((sourceCode.isEmpty && sourceZipURL == nil) || !githubConnected || ipaURL != nil || projectName.trimmingCharacters(in: .whitespaces).isEmpty)
                    .padding(.horizontal)
                }
                
                // Helper text explaining requirements
                Group {
                    if !githubConnected {
                        Text("Connect GitHub above to enable compiling")
                            .font(.caption)
                            .foregroundColor(.orange)
                    } else if projectName.trimmingCharacters(in: .whitespaces).isEmpty {
                        Text("Enter a project name to enable compiling")
                            .font(.caption)
                            .foregroundColor(.orange)
                    } else if sourceCode.isEmpty && sourceZipURL == nil {
                        Text("Add Swift source or a ZIP file to enable compiling")
                            .font(.caption)
                            .foregroundColor(.orange)
                    }
                }
                .padding(.top, 4)
                
                // Continue to sign + Share unsigned
                if ipaURL != nil {
                    Button(action: {
                        // Hand the fresh IPA to the Sign tab and jump there —
                        // signing happens in the Sign tab, not inside Compile
                        pendingSignIpa = ipaURL
                        selectedTab = 1
                    }) {
                        Text("Continue to Sign →")
                            .frame(maxWidth: .infinity)
                    }
                    .buttonStyle(PressableBlueButtonStyle())
                    .padding(.horizontal)
                    
                    Button("Share Unsigned IPA") {
                        if let url = ipaURL, FileManager.default.fileExists(atPath: url.path) {
                            shareItem = ShareItem(url: url)
                        }
                    }
                    .buttonStyle(PressableBlueButtonStyle())
                    .padding(.horizontal)
                }
                
                // Copy Log + Clear at the bottom of the page (aligned, equal width)
                if !buildLog.isEmpty || ipaURL != nil {
                    HStack(spacing: 12) {
                        if !buildLog.isEmpty {
                            Button("Copy Log") {
                                UIPasteboard.general.string = buildLog
                                compileStatus = "Log copied to clipboard"
                            }
                            .buttonStyle(PressableSmallBlueButtonStyle())
                            .frame(maxWidth: .infinity)
                        }
                        Button("Clear") {
                            showingClearLogConfirm = true
                        }
                        .buttonStyle(PressableSmallRedButtonStyle())
                        .alert("Clear Build Log?", isPresented: $showingClearLogConfirm) {
                            Button("Yes", role: .destructive) {
                                clearCompileState()
                            }
                            Button("Cancel", role: .cancel) { }
                        } message: {
                            Text("Are you sure you want to clear the build log and the compiled IPA?")
                        }
                        .frame(maxWidth: .infinity)
                    }
                    .padding(.horizontal)
                    .padding(.top, 12)
                }
                
                Spacer()
            }
            .padding()
            }
            .onAppear {
                // Check for saved GitHub token and validate
                if let token = GitHubKeychain.getToken() {
                    validateSavedToken(token)
                }
            }
            .sheet(isPresented: $showingImporter) {
                DocumentPicker { urls in
                    showingImporter = false
                    handleImport(urls)
                }
            }
            .sheet(isPresented: $showingLog) {
                NavigationView {
                    ScrollView {
                        Text(buildLog)
                            .font(.system(.caption, design: .monospaced))
                            .padding()
                    }
                    .navigationTitle("Build Log")
                    .navigationBarItems(trailing: Button("Done") { showingLog = false })
                }
            }
            .sheet(item: $shareItem) { item in
                ShareSheet(items: [item.url])
            }
            .sheet(isPresented: $showingGitHubConnect) {
                NavigationView {
                    VStack(spacing: 16) {
                        Image(systemName: "lock.shield.fill")
                            .font(.system(size: 48))
                            .foregroundColor(.blue)
                        Text("Connect GitHub")
                            .font(.title2)
                            .fontWeight(.bold)
                        VStack(alignment: .leading, spacing: 8) {
                            HStack(alignment: .top) {
                                Image(systemName: "checkmark.circle.fill")
                                    .foregroundColor(.green)
                                Text("We never see your GitHub password")
                                    .font(.subheadline)
                            }
                            HStack(alignment: .top) {
                                Image(systemName: "checkmark.circle.fill")
                                    .foregroundColor(.green)
                                Text("We never store your password — only the token")
                                    .font(.subheadline)
                            }
                            HStack(alignment: .top) {
                                Image(systemName: "checkmark.circle.fill")
                                    .foregroundColor(.green)
                                Text("Token is saved in your iPhone's Keychain (secure, on-device only)")
                                    .font(.subheadline)
                            }
                            HStack(alignment: .top) {
                                Image(systemName: "checkmark.circle.fill")
                                    .foregroundColor(.green)
                                Text("Your code goes only to your private repos")
                                    .font(.subheadline)
                            }
                        }
                        .padding(.horizontal)
                        SecureField("GitHub Personal Access Token", text: $githubTokenInput)
                            .textFieldStyle(.roundedBorder)
                            .padding(.horizontal)
                            .autocapitalization(.none)
                        VStack(alignment: .leading, spacing: 6) {
                            Text("Required permissions:")
                                .font(.subheadline)
                                .fontWeight(.semibold)
                            HStack {
                                Image(systemName: "checkmark.square.fill")
                                    .foregroundColor(.blue)
                                Text("repo")
                                    .font(.subheadline)
                                    .fontWeight(.medium)
                            }
                            HStack {
                                Image(systemName: "checkmark.square.fill")
                                    .foregroundColor(.blue)
                                Text("workflow")
                                    .font(.subheadline)
                                    .fontWeight(.medium)
                            }
                        }
                        .padding(.horizontal)
                        Text("Create one at github.com → Settings → Developer settings → Personal access tokens → Tokens (classic) → Generate new token. Give it a name, check the boxes above, then Generate. Copy the token (starts with 'ghp_') and paste it here. You'll log in with your GitHub email/password on the website — we never see it.")
                            .font(.caption2)
                            .foregroundColor(.secondary)
                            .padding(.horizontal)
                        Button(action: connectGitHub) {
                            Text("Save Token")
                                .frame(maxWidth: .infinity)
                        }
                        .buttonStyle(PressableBlueButtonStyle())
                        .disabled(githubTokenInput.isEmpty)
                        .padding(.horizontal)
                        Spacer()
                    }
                    .padding(.top, 32)
                    .navigationTitle("GitHub")
                    .navigationBarItems(trailing: Button("Cancel") { showingGitHubConnect = false })
                }
            }
        }
    }
    
    private func connectGitHub() {
        // Validate token with GitHub API before saving
        compileStatus = "Validating GitHub token..."
        guard let url = URL(string: "https://api.github.com/user") else { return }
        var request = URLRequest(url: url)
        request.setValue("Bearer \(githubTokenInput)", forHTTPHeaderField: "Authorization")
        request.setValue("application/vnd.github+json", forHTTPHeaderField: "Accept")
        
        URLSession.shared.dataTask(with: request) { data, response, error in
            DispatchQueue.main.async {
                if let httpResponse = response as? HTTPURLResponse,
                   httpResponse.statusCode == 200,
                   let data = data,
                   let json = try? JSONSerialization.jsonObject(with: data) as? [String: Any],
                   let login = json["login"] as? String {
                    // Token is valid
                    if GitHubKeychain.saveToken(self.githubTokenInput) {
                        self.githubConnected = true
                        self.githubUsername = login
                        self.githubTokenInput = ""
                        self.showingGitHubConnect = false
                        self.compileStatus = "GitHub connected as @\(login)!"
                    }
                } else {
                    // Token is invalid
                    self.compileStatus = "Invalid token. Check it and try again."
                }
            }
        }.resume()
    }
    
    // MARK: - Project name auto-fill (from the ZIP or the source itself)

    private func autoFillProjectName(_ candidate: String) {
        let clean = candidate.trimmingCharacters(in: .whitespaces)
        guard projectNameIsAuto, !clean.isEmpty else { return }
        lastAutoName = clean
        projectName = clean
    }

    /// "CycleTest-source.zip" / "CycleTest source ZIP.zip" -> "CycleTest"
    static func deriveName(fromZipName name: String) -> String {
        let base = (name as NSString).deletingPathExtension
        var tokens = base.split(whereSeparator: { $0 == " " || $0 == "-" || $0 == "_" }).map(String.init)
        let junk: Set<String> = ["zip", "source", "src"]
        while let last = tokens.last, junk.contains(last.lowercased()) {
            tokens.removeLast()
        }
        return tokens.joined(separator: " ")
    }

    /// "@main struct CycleTestApp: App" -> "CycleTest"
    static func deriveName(fromSource code: String) -> String? {
        let pattern = #"struct\s+([A-Za-z_][A-Za-z0-9_]*)\s*:\s*App"#
        guard let regex = try? NSRegularExpression(pattern: pattern),
              let match = regex.firstMatch(in: code, range: NSRange(code.startIndex..., in: code)),
              let range = Range(match.range(at: 1), in: code) else { return nil }
        var name = String(code[range])
        if name.hasSuffix("App"), name.count > 3 {
            name = String(name.dropLast(3))
        }
        return name
    }

    private func handleImport(_ urls: [URL]) {
        for url in urls {
            if url.pathExtension == "swift" {
                if let content = try? String(contentsOf: url) {
                    sourceCode += "\n// \(url.lastPathComponent)\n" + content
                }
            } else if url.pathExtension == "zip" {
                // Store ZIP for upload — GitHub Actions will unzip it
                sourceZipURL = url
                sourceZipName = url.lastPathComponent
                compileStatus = "ZIP ready: \(url.lastPathComponent)"
                autoFillProjectName(Self.deriveName(fromZipName: url.lastPathComponent))
                return
            }
        }
        if sourceZipURL == nil {
            compileStatus = "Imported \(urls.count) file(s)"
        }
    }

    private func clearCompileState() {
        // Reset everything for a new project, including the log.
        // Import button becomes enabled again after Clear.
        stopDots()
        buildLog = ""
        compileStatus = ""
        ipaURL = nil
        sourceCode = ""
        sourceZipURL = nil
        sourceZipName = ""
        projectName = ""
        projectNameIsAuto = true
        lastAutoName = ""
    }
    
    private func startDots() {
        dotsTimer?.invalidate()
        spinnerIndex = 0
        dotsTimer = Timer.scheduledTimer(withTimeInterval: 0.15, repeats: true) { _ in
            DispatchQueue.main.async {
                // Replace last spinner char with next one (rotating braille spinner)
                if !self.buildLog.isEmpty {
                    self.buildLog.removeLast()
                }
                self.buildLog += self.spinnerChars[self.spinnerIndex]
                self.spinnerIndex = (self.spinnerIndex + 1) % self.spinnerChars.count
            }
        }
    }
    
    private func stopDots() {
        dotsTimer?.invalidate()
        dotsTimer = nil
    }
    
    private func compile() {
        guard let token = GitHubKeychain.getToken() else {
            compileStatus = "GitHub not connected"
            return
        }
        isCompiling = true
        compileStatus = "Creating build repo..."
        // Don't clear the log - append so user can read previous builds
        if buildLog.isEmpty {
            buildLog = "[BuildBox] Starting build for \(projectName)...\n"
        } else {
            buildLog += "\n[BuildBox] Starting build for \(projectName)...\n"
        }
        
        let repoName = "buildbox-\(projectName.lowercased().replacingOccurrences(of: " ", with: "-"))"
        let service = GitHubService.shared
        
        // Step 1: Create repo
        service.createRepo(name: repoName, token: token) { success, fullName in
            // fullName is "owner/repo" — if nil (repo existed), construct it
            // We need the username — fetch it if needed
            let repo: String
            if let full = fullName {
                repo = full
            } else {
                // Repo already existed — construct full name from username
                repo = "\(self.githubUsername)/\(repoName)"
            }
            guard success, !repo.hasPrefix("/") else {
                self.compileStatus = "Failed to create repo"
                self.stopDots()
                self.isCompiling = false
                return
            }
            self.buildLog += "[BuildBox] Repo ready: \(repo)\n"
            self.compileStatus = "Uploading source..."
            
            // Step 2: Push source code (or ZIP)
            if let zipURL = self.sourceZipURL,
               let zipData = try? Data(contentsOf: zipURL) {
                // Upload ZIP as base64
                self.buildLog += "[BuildBox] Uploading ZIP (\(self.sourceZipName))...\n"
                service.pushFileData(repo: repo, path: "source.zip", data: zipData, token: token, message: "BuildBox: upload source ZIP") { ok in
                    guard ok else {
                        self.compileStatus = "Failed to upload ZIP"
                        self.stopDots()
                        self.isCompiling = false
                        return
                    }
                    self.pushWorkflowAndBuild(repo: repo, token: token, service: service)
                }
            } else {
                // Upload source code as text
                service.pushFile(repo: repo, path: "src/main.swift", content: self.sourceCode, token: token, message: "BuildBox: upload source") { ok in
                    guard ok else {
                        self.compileStatus = "Failed to upload source"
                        self.stopDots()
                        self.isCompiling = false
                        return
                    }
                    self.pushWorkflowAndBuild(repo: repo, token: token, service: service)
                }
            }
        }
    }
    
    private func pushWorkflowAndBuild(repo: String, token: String, service: GitHubService) {
        self.buildLog += "[BuildBox] Source uploaded\n"
        self.compileStatus = "Setting up workflow..."
        
        // Step 3: Push workflow
        service.pushFile(repo: repo, path: ".github/workflows/build-ipa.yml", content: GitHubService.buildWorkflowYAML, token: token, message: "BuildBox: add workflow") { ok in
            guard ok else {
                self.compileStatus = "Failed to setup workflow"
                self.stopDots()
                self.isCompiling = false
                return
            }
            self.buildLog += "[BuildBox] Workflow ready\n"
            self.compileStatus = "Starting build..."
            
            // Step 4: Trigger build
            service.triggerBuild(repo: repo, token: token, log: { msg in
                self.buildLog += msg + "\n"
            }) { ok in
                guard ok else {
                    self.compileStatus = "Failed to trigger build"
                    self.dotsTimer?.invalidate()
                    self.dotsTimer = nil
                    self.buildLog += "\n"
                    self.stopDots()
                    self.isCompiling = false
                    return
                }
                self.buildLog += "[BuildBox] Build triggered, waiting  "
                self.compileStatus = "Building... (this takes a few minutes)"
                
                // Animated dots (like the signer)
                self.startDots()
                
                // Step 5: Poll for completion
                self.pollBuildStatus(repo: repo, token: token, attempts: 0)
            }
        }
    }
    
    private func validateSavedToken(_ token: String) {
        guard let url = URL(string: "https://api.github.com/user") else { return }
        var request = URLRequest(url: url)
        request.setValue("Bearer \(token)", forHTTPHeaderField: "Authorization")
        request.setValue("application/vnd.github+json", forHTTPHeaderField: "Accept")
        
        URLSession.shared.dataTask(with: request) { data, response, _ in
            DispatchQueue.main.async {
                if let httpResponse = response as? HTTPURLResponse,
                   httpResponse.statusCode == 200,
                   let data = data,
                   let json = try? JSONSerialization.jsonObject(with: data) as? [String: Any],
                   let login = json["login"] as? String {
                    self.githubConnected = true
                    self.githubUsername = login
                } else {
                    // Token invalid, clear it
                    GitHubKeychain.deleteToken()
                    self.githubConnected = false
                }
            }
        }.resume()
    }
    
    private func pollBuildStatus(repo: String, token: String, attempts: Int) {
        guard attempts < 60 else { // 10 min max
            self.compileStatus = "Build timed out"
            self.stopDots()
            self.isCompiling = false
            return
        }
        
        GitHubService.shared.getBuildStatus(repo: repo, token: token) { status, conclusion, runId in
            if status == "completed" {
                if conclusion == "failure" {
                    self.stopDots()
                    self.isCompiling = false
                    self.compileStatus = "Build failed on GitHub"
                    self.buildLog += "[BuildBox] Build FAILED on GitHub Actions\n"
                    // Fetch which step failed and the detailed logs
                    if let rid = runId {
                        GitHubService.shared.getFailureLogs(repo: repo, runId: rid, token: token) { logs in
                            if let l = logs {
                                self.buildLog += "[BuildBox] \(l)\n"
                            }
                        }
                        GitHubService.shared.downloadJobLogs(repo: repo, runId: rid, token: token) { logContent in
                            if let lc = logContent, !lc.isEmpty {
                                // Show last 80 lines to avoid huge logs
                                let lines = lc.components(separatedBy: "\n")
                                let tail = lines.suffix(80).joined(separator: "\n")
                                self.buildLog += "[BuildBox] --- GitHub logs ---\n\(tail)\n"
                            }
                        }
                    }
                    return
                }
                self.buildLog += "[BuildBox] Build completed!\n"
                self.compileStatus = "Downloading IPA..."
                if let runId = runId {
                    GitHubService.shared.downloadIPA(repo: repo, runId: runId, token: token) { url in
                        self.stopDots()
                        self.isCompiling = false
                        if let url = url {
                            // Save to Documents so Sign tab can access it
                            let docs = FileManager.default.urls(for: .documentDirectory, in: .userDomainMask).first!
                            let savedURL = docs.appendingPathComponent("BuildBox-unsigned.ipa")
                            try? FileManager.default.removeItem(at: savedURL)
                            let downloadedURL: URL
                            if (try? FileManager.default.copyItem(at: url, to: savedURL)) != nil {
                                downloadedURL = savedURL
                            } else {
                                downloadedURL = url
                            }
                            // Resolve nested IPA (GitHub Actions wraps the IPA in a ZIP)
                            let resolved = IPASigner.shared.resolveNestedIPA(ipaURL: downloadedURL)
                            self.ipaURL = resolved
                            self.compileStatus = "Build complete! IPA ready."
                            self.stopDots()
                            self.buildLog += "\n[BuildBox] IPA downloaded - complete\n"
                        } else {
                            self.compileStatus = "Build done but IPA download failed"
                        }
                    }
                } else {
                    self.stopDots()
                    self.isCompiling = false
                    self.compileStatus = "Build completed"
                }
            } else {
                // Still building, check again in 10s
                DispatchQueue.main.asyncAfter(deadline: .now() + 10) {
                    self.pollBuildStatus(repo: repo, token: token, attempts: attempts + 1)
                }
            }
        }
    }
}

extension UTType {
    static var swiftSource: UTType {
        UTType(filenameExtension: "swift") ?? .sourceCode
    }
}
