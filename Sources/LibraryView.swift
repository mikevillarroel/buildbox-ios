// Library tab — every IPA the user signs lives here, in its own tab
// (Miguel, 2026-10-21: "piensa como un usuario — van a firmar de todo";
// a section inside Sign would fill up and bury the signing flow).
// Signed files sit in Documents; this view reads the registry, offers
// search, one-tap install and remove-with-confirmation.

import SwiftUI

struct LibraryView: View {
    // (The "Duplicate…" shortcut lived here until Beta 2.23 — Miguel
    // removed it as redundant: editing the Bundle ID in Sign's App Info
    // already produces a separate copy.)
    @Binding var pendingSignIpa: URL?
    @Binding var selectedTab: Int
    @State private var entries: [SignedIPAEntry] = []
    @State private var entryToRemove: SignedIPAEntry?
    @State private var showingRemoveConfirm = false
    @State private var isInstalling = false
    @State private var installLog = ""
    @State private var search = ""
    @State private var shareURL: URL?
    @State private var showingShare = false

    private var docsDir: URL {
        FileManager.default.urls(for: .documentDirectory, in: .userDomainMask).first!
    }

    private var filtered: [SignedIPAEntry] {
        search.isEmpty ? entries : entries.filter {
            $0.appName.localizedCaseInsensitiveContains(search) ||
            $0.bundleID.localizedCaseInsensitiveContains(search)
        }
    }

    var body: some View {
        NavigationView {
            Form {
                // Header (same top as Compile/Sign: icon + title)
                Section {
                    VStack(spacing: 20) {
                        Image(systemName: "books.vertical")
                            .font(.system(size: 60))
                            .foregroundColor(.secondary)
                        Text("Library")
                            .font(.title2)
                            .fontWeight(.bold)
                    }
                    .frame(maxWidth: .infinity)
                    .padding(.vertical, 6)
                }
                .listRowBackground(Color.clear)

                if entries.isEmpty {
                    Section {
                        Text("No signed IPAs yet.\n\nSign an app in the Sign tab and it will live here — ready to install anytime, without signing again.")
                            .font(.subheadline)
                            .foregroundColor(.secondary)
                    }
                } else {
                    Section(header: Text("Signed IPAs")) {
                        ForEach(filtered) { entry in
                            HStack(spacing: 10) {
                                if let icon = icon(for: entry) {
                                    Image(uiImage: icon)
                                        .resizable()
                                        .frame(width: 40, height: 40)
                                        .cornerRadius(9)
                                } else {
                                    // Placeholder tile (apps whose icon
                                    // only exists inside a compiled asset
                                    // catalog): initial letter, aligned.
                                    ZStack {
                                        RoundedRectangle(cornerRadius: 9)
                                            .fill(Color(.systemGray4))
                                        Text(String(entry.appName.prefix(1)))
                                            .font(.headline)
                                            .foregroundColor(.white)
                                    }
                                    .frame(width: 40, height: 40)
                                }
                                VStack(alignment: .leading, spacing: 2) {
                                    Text(entry.appName)
                                        .font(.subheadline)
                                        .fontWeight(.medium)
                                    Text("\(entry.version) · \(entry.bundleID)")
                                        .font(.caption2)
                                        .foregroundColor(.secondary)
                                    Text("Signed \(entry.dateString) · \(entry.sizeString)")
                                        .font(.caption2)
                                        .foregroundColor(.secondary)
                                }
                                Spacer()
                            }
                            // Actions live in the swipes now (Miguel,
                            // 2026-10-21): rows stay clean — slide LEFT for
                            // Install / Remove, slide RIGHT for Share.
                            .swipeActions(edge: .trailing, allowsFullSwipe: false) {
                                Button(role: .destructive) {
                                    entryToRemove = entry
                                    showingRemoveConfirm = true
                                } label: {
                                    Label("Remove", systemImage: "trash")
                                }
                                Button {
                                    install(entry)
                                } label: {
                                    Label("Install", systemImage: "arrow.down.circle")
                                }
                                .tint(.green)
                                .disabled(isInstalling)
                            }
                            // Share lives here in the Library (Miguel,
                            // 2026-10-21): swipe right on a row, or
                            // long-press for the full action menu.
                            .swipeActions(edge: .leading, allowsFullSwipe: false) {
                                Button {
                                    shareURL = docsDir.appendingPathComponent(entry.fileName)
                                    showingShare = true
                                } label: {
                                    Label("Share", systemImage: "square.and.arrow.up")
                                }
                                .tint(.blue)
                            }
                            .contextMenu {
                                Button {
                                    shareURL = docsDir.appendingPathComponent(entry.fileName)
                                    showingShare = true
                                } label: {
                                    Label("Share", systemImage: "square.and.arrow.up")
                                }
                                Button {
                                    install(entry)
                                } label: {
                                    Label("Install", systemImage: "arrow.down.circle")
                                }
                                Button(role: .destructive) {
                                    entryToRemove = entry
                                    showingRemoveConfirm = true
                                } label: {
                                    Label("Remove", systemImage: "trash")
                                }
                            }
                        }
                    }
                }

                if !installLog.isEmpty {
                    Section(header: Text("Installer Log")) {
                        ScrollView {
                            Text(installLog)
                                .font(.system(.caption, design: .monospaced))
                                .frame(maxWidth: .infinity, alignment: .leading)
                        }
                        .frame(maxHeight: 160)
                    }
                }
            }
            .navigationTitle("")
            .navigationBarTitleDisplayMode(.inline)
            .searchable(text: $search, prompt: "Search signed IPAs")
            .onAppear { load() }
            .sheet(isPresented: $showingShare) {
                if let url = shareURL {
                    ShareSheet(items: [url])
                }
            }
            .alert("Remove Signed IPA?", isPresented: $showingRemoveConfirm) {
                Button("Remove", role: .destructive) {
                    if let entry = entryToRemove { remove(entry) }
                    entryToRemove = nil
                }
                Button("Cancel", role: .cancel) { entryToRemove = nil }
            } message: {
                Text("This deletes the signed IPA from the library. You would have to sign it again to get it back.")
            }
        }
    }

    private func load() {
        let all = SignedLibraryStore.load()
        let alive = all.filter { FileManager.default.fileExists(atPath: docsDir.appendingPathComponent($0.fileName).path) }
        entries = alive
        if alive.count != all.count { SignedLibraryStore.save(alive) }
        // Self-heal: entries whose icon snapshot is missing (e.g. the
        // import-time read missed it) get one extracted from the stored
        // signed IPA itself — no re-signing needed.
        let iconDir = docsDir.appendingPathComponent("lib-icons")
        for entry in alive {
            let iconPath = iconDir.appendingPathComponent(entry.fileName + ".png")
            // Heal when the snapshot is missing OR undecodable — entries
            // registered before the iDOT fix hold a poisoned PNG that
            // exists but UIImage cannot read (FileBrowser Pro's case).
            let undecodable = !FileManager.default.fileExists(atPath: iconPath.path) || UIImage(contentsOfFile: iconPath.path) == nil
            if undecodable,
               let data = IPASigner.shared.readIconData(ipaURL: docsDir.appendingPathComponent(entry.fileName)) {
                try? FileManager.default.createDirectory(at: iconDir, withIntermediateDirectories: true)
                try? data.write(to: iconPath)
            }
        }
    }

    private func icon(for entry: SignedIPAEntry) -> UIImage? {
        let p = docsDir.appendingPathComponent("lib-icons").appendingPathComponent(entry.fileName + ".png")
        return UIImage(contentsOfFile: p.path)
    }

    private func remove(_ entry: SignedIPAEntry) {
        try? FileManager.default.removeItem(at: docsDir.appendingPathComponent(entry.fileName))
        try? FileManager.default.removeItem(at: docsDir.appendingPathComponent("lib-icons").appendingPathComponent(entry.fileName + ".png"))
        entries.removeAll { $0.id == entry.id }
        SignedLibraryStore.save(entries)
    }

    private func install(_ entry: SignedIPAEntry) {
        let url = docsDir.appendingPathComponent(entry.fileName)
        isInstalling = true
        installLog += "[BuildBox] Installing \(entry.appName)...\n"
        LocalInstaller.install(
            ipaURL: url,
            bundleID: entry.bundleID,
            appName: entry.appName,
            version: entry.version,
            progress: { msg in
                DispatchQueue.main.async {
                    if msg != "Installing..." {
                        self.installLog += "[BuildBox] \(msg)\n"
                    }
                }
            },
            completion: { result in
                DispatchQueue.main.async {
                    self.isInstalling = false
                    switch result {
                    case .success:
                        self.installLog += "[BuildBox] Installer opened\n"
                    case .failure(let error):
                        self.installLog += "[BuildBox] Install failed: \(error.localizedDescription)\n"
                    }
                }
            }
        )
    }
}

// One signed IPA kept in the library (Documents file + this registry entry).
struct SignedIPAEntry: Codable, Identifiable {
    var fileName: String
    var appName: String
    var bundleID: String
    var version: String
    var date: Double
    var sizeMB: Double
    var id: String { fileName }
    var dateString: String {
        let f = DateFormatter()
        f.dateStyle = .medium
        f.timeStyle = .none
        return f.string(from: Date(timeIntervalSince1970: date))
    }
    var sizeString: String { String(format: "%.0f MB", sizeMB) }
}

enum SignedLibraryStore {
    private static let key = "signedLibraryJSON"
    static func load() -> [SignedIPAEntry] {
        guard let str = UserDefaults.standard.string(forKey: key),
              let d = str.data(using: .utf8),
              let list = try? JSONDecoder().decode([SignedIPAEntry].self, from: d) else { return [] }
        return list
    }
    static func save(_ list: [SignedIPAEntry]) {
        if let d = try? JSONEncoder().encode(list), let str = String(data: d, encoding: .utf8) {
            UserDefaults.standard.set(str, forKey: key)
        }
    }
}
