import Foundation

// MARK: - 应用数据目录(全部留在本机,不外发)

public enum SSPaths {
    public static var supportDir: URL {
        let base = FileManager.default.urls(for: .applicationSupportDirectory, in: .userDomainMask).first
            ?? URL(fileURLWithPath: NSHomeDirectory()).appendingPathComponent("Library/Application Support")
        let d = base.appendingPathComponent("SafeShield", isDirectory: true)
        try? FileManager.default.createDirectory(at: d, withIntermediateDirectories: true)
        return d
    }
    public static var settingsURL: URL { supportDir.appendingPathComponent("settings.json") }
    public static var baselineURL: URL { supportDir.appendingPathComponent("baseline.json") }
    public static var eventsURL: URL { supportDir.appendingPathComponent("events.jsonl") }
    public static var auditURL: URL { supportDir.appendingPathComponent("audit.jsonl") }
    public static var reportsURL: URL { supportDir.appendingPathComponent("reports.json") }
    public static var quarantineDir: URL {
        let d = supportDir.appendingPathComponent("quarantine", isDirectory: true)
        try? FileManager.default.createDirectory(at: d, withIntermediateDirectories: true)
        return d
    }
}

// MARK: - 处置姿态(设计 §4.1 / PRD F11)

public enum ResponsePosture: String, Codable, CaseIterable, Sendable {
    case readOnly = "只读(仅检测)"
    case confirm = "确认后处置(默认)"
    case semiAuto = "半自动(可逆动作自动,不可逆仍确认)"

    public var note: String {
        switch self {
        case .readOnly: return "任何处置都不执行,仅给出建议。"
        case .confirm: return "每个动作逐项弹窗确认;不可逆动作需二次确认。"
        case .semiAuto: return "隔离/停用启动项等可回滚动作自动执行;终止进程等不可逆动作仍需确认。"
        }
    }
    /// 该姿态下是否允许"无需确认"执行可回滚动作
    public var autoReversible: Bool { self == .semiAuto }
    public var allowsAnyAction: Bool { self != .readOnly }
}

// MARK: - 白名单:随产品发布的是"通用规则";本机学习到的条目只存用户容器

public struct Whitelists: Codable, Sendable {
    public var processes: [String]
    public var ports: [Int]
    public var ips: [String]
    public var pathPrefixes: [String]
    public var launchPrefixes: [String]
    public var suspiciousKeywords: [String]
    public var watchPaths: [String]
    public var highFreqThreshold: Int

    public static let generic = Whitelists(
        processes: ["Finder", "Dock", "WindowServer", "loginwindow", "kernel_task", "launchd",
                    "SystemUIServer", "ControlCenter", "rapportd", "mds", "mds_stores", "configd",
                    "UserEventAgent", "opendirectoryd", "distnotd", "python3", "python", "node",
                    "git", "ssh", "curl", "brew", "npm", "go", "ruby", "java"],
        ports: [22, 53, 80, 443, 587, 993, 3306, 5432, 6379, 8080],
        ips: ["127.0.0.1", "::1", "localhost"],
        pathPrefixes: ["/System/", "/Applications/", "/usr/bin/", "/usr/sbin/", "/bin/", "/sbin/",
                       "/Library/", "/opt/", "/usr/local/", "/private/var/", "@HOME@"],
        launchPrefixes: ["com.apple.", "com.google.", "com.microsoft.", "com.docker.", "com.github.",
                         "homebrew.", "org.mozilla."],
        suspiciousKeywords: ["xmrig", "minerd", "stratum", "cryptonight", "bash -i", "nc -e", "nc -c",
                             "/dev/tcp/", "curl | sh", "wget | sh", "osascript -e", "python3 -c",
                             "python -c", "rm -f /tmp/", "nohup", "tmux new -d", "screen -dm",
                             "ps aux | grep", "chmod +x"],
        watchPaths: ["/Library/LaunchDaemons", "/Library/LaunchAgents", "/private/tmp", "/tmp", "/Users/Shared"],
        highFreqThreshold: 10
    )

    /// 运行时把 @HOME@ 展开为当前用户主目录(通用规则不含任何机器专属字面量)
    public func resolvedPathPrefixes() -> [String] {
        pathPrefixes.map { $0 == "@HOME@" ? NSHomeDirectory() + "/" : $0 }
    }
}

// MARK: - 设置

public struct AppSettings: Codable, Sendable {
    public var posture: ResponsePosture = .confirm
    public var guardianEnabled: Bool = false
    public var intervalSec: Int = 60
    public var notifyEnabled: Bool = false
    public var onboardingDone: Bool = false
    public var whitelists: Whitelists = .generic
    public var consentAt: Date? = nil

    public static func load() -> AppSettings {
        if let data = try? Data(contentsOf: SSPaths.settingsURL),
           let s = try? JSONDecoder().decode(AppSettings.self, from: data) { return s }
        return AppSettings()
    }
    public func save() {
        let enc = JSONEncoder(); enc.outputFormatting = [.prettyPrinted, .sortedKeys]
        try? enc.encode(self).write(to: SSPaths.settingsURL, options: .atomic)
    }
}

// MARK: - 白名单判定(与 monitor.py 语义一致,但清单通用化)

public struct WhitelistJudge: Sendable {
    public let w: Whitelists
    public init(_ w: Whitelists) { self.w = w }

    public func process(_ cmdline: String) -> Bool {
        guard !cmdline.isEmpty else { return false }
        let low = cmdline.lowercased()
        return w.processes.contains { low.contains($0.lowercased()) }
    }
    public func port(_ p: Int) -> Bool { w.ports.contains(p) }
    public func ip(_ raw: String) -> Bool {
        let ip = raw.trimmingCharacters(in: CharacterSet(charactersIn: "[]"))
        if ip.isEmpty || ip == "::1" || ip == "localhost" { return true }
        if w.ips.contains(ip) { return true }
        if ip.hasPrefix("127.") || ip.hasPrefix("192.168.") || ip.hasPrefix("10.")
            || ip.hasPrefix("172.") || ip.hasPrefix("169.254.") || ip.hasPrefix("fe80") { return true }
        return false
    }
    public func path(_ p: String) -> Bool {
        w.resolvedPathPrefixes().contains { p.hasPrefix($0) }
    }
    public func launchLabel(_ name: String) -> Bool {
        w.launchPrefixes.contains { name.hasPrefix($0) || name.contains($0) }
    }
    public func keyword(_ cmdline: String) -> String? {
        let low = cmdline.lowercased()
        return w.suspiciousKeywords.first { low.contains($0.lowercased()) }
    }
}
