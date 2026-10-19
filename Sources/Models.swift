import SwiftUI
import UniformTypeIdentifiers

// Model for a build project
struct BuildProject: Identifiable, Codable {
    var id = UUID()
    var name: String
    var sourceFiles: [String] // file names
    var createdAt = Date()
    var lastBuildAt: Date?
    var lastBuildStatus: BuildStatus = .none
    
    enum BuildStatus: String, Codable {
        case none, building, succeeded, failed
    }
    
    enum CodingKeys: String, CodingKey {
        case id, name, sourceFiles, createdAt, lastBuildAt, lastBuildStatus
    }
}

// Model for build history
struct BuildRecord: Identifiable, Codable {
    var id = UUID()
    var projectName: String
    var date = Date()
    var status: BuildProject.BuildStatus
    var log: String = ""
    var ipaPath: String?
    
    enum CodingKeys: String, CodingKey {
        case id, projectName, date, status, log, ipaPath
    }
}
