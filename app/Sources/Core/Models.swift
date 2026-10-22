import Foundation

// MARK: - 严重度 / 维度 / 结论状态

public enum Severity: String, Codable, CaseIterable, Comparable, Sendable {
    case critical, high, medium, low, info
    public var label: String {
        switch self {
        case .critical: return "严重"
        case .high: return "高危"
        case .medium: return "中危"
        case .low: return "低危"
        case .info: return "提示"
        }
    }
    public var penalty: Double {
        switch self {
        case .critical: return 1.0
        case .high: return 0.6
        case .medium: return 0.3
        case .low: return 0.1
        case .info: return 0.0
        }
    }
    private var rank: Int {
        switch self {
        case .critical: return 4
        case .high: return 3
        case .medium: return 2
        case .low: return 1
        case .info: return 0
        }
    }
    public static func < (l: Severity, r: Severity) -> Bool { l.rank < r.rank }
}

public enum Dimension: String, Codable, CaseIterable, Sendable {
    case systemConfig = "系统配置"
    case privacy = "隐私"
    case persistence = "驻留"
    case file = "文件"
    case network = "网络"
    case account = "账户"
}

/// 单项检测结论状态。unavailable 不计入评分池(设计 §7)。
public enum FindingStatus: String, Codable, Sendable {
    case pass, fail, unavailable
}

// MARK: - 检测结论

public struct Finding: Identifiable, Codable, Sendable {
    public let id: String              // 规则 id,如 sys.sip
    public let name: String
    public let dimension: Dimension
    public let status: FindingStatus
    public let severity: Severity      // status==fail 时为规则 failSeverity;pass 时为 info
    public let summary: String
    public let evidence: String        // 命令真实输出(脱敏后)
    public let remediationKind: String // deepLink / guide / action
    public let remediationTarget: String? // deepLink URL 或 guide 文本
    public let actionType: String?     // remediationKind==action 时的 ActionType rawValue
    public let weight: Double

    public var countsInScore: Bool { status != .unavailable && weight > 0 }
}

// MARK: - 体检报告

public struct ScanReport: Identifiable, Codable, Sendable {
    public let id: String
    public let startedAt: Date
    public let finishedAt: Date
    public let score: Int
    public let grade: String
    public let ruleSetVersion: String
    public let findings: [Finding]
    public let dimensionScores: [String: Int]

    public var risks: [Finding] { findings.filter { $0.status == .fail }.sorted { $0.severity > $1.severity } }
    public var passed: [Finding] { findings.filter { $0.status == .pass } }
}

// MARK: - 命令输出

public struct CommandOutput: Sendable {
    public let tool: String
    public let exitCode: Int32
    public let stdout: String
    public let stderr: String
    public var ok: Bool { exitCode == 0 }
    public init(tool: String, exitCode: Int32, stdout: String, stderr: String) {
        self.tool = tool; self.exitCode = exitCode; self.stdout = stdout; self.stderr = stderr
    }
}

// MARK: - 守护事件(设计 §4.1)

public enum EventKind: String, Codable, Sendable {
    case suspiciousProcess, tempExecution, newListenPort, highFreqConnection, suspiciousPortConnection
    case newLaunchAgent, newLaunchDaemon, newFile, fileChanged, newUserAccount, guardianStarted, guardianStopped, error
}

public struct SecurityEvent: Identifiable, Codable, Sendable {
    public let id: String
    public let time: Date
    public let kind: EventKind
    public let severity: Severity
    public let title: String
    public let detail: String
    public let target: String          // pid / ip:port / path / label
    public let suggestedAction: String? // ActionType rawValue
    public let handled: Bool

    public init(id: String = UUID().uuidString, time: Date = Date(), kind: EventKind, severity: Severity,
                title: String, detail: String, target: String, suggestedAction: String? = nil, handled: Bool = false) {
        self.id = id; self.time = time; self.kind = kind; self.severity = severity
        self.title = title; self.detail = detail; self.target = target
        self.suggestedAction = suggestedAction; self.handled = handled
    }
}

// MARK: - 工具

public enum Fmt {
    static let df: DateFormatter = {
        let f = DateFormatter(); f.dateFormat = "HH:mm"; return f
    }()
    static let dfFull: DateFormatter = {
        let f = DateFormatter(); f.dateFormat = "yyyy-MM-dd HH:mm:ss"; return f
    }()
    static let dfDay: DateFormatter = {
        let f = DateFormatter(); f.dateFormat = "MM-dd HH:mm"; return f
    }()
    public static func time(_ d: Date) -> String { df.string(from: d) }
    public static func full(_ d: Date) -> String { dfFull.string(from: d) }
    public static func day(_ d: Date) -> String { dfDay.string(from: d) }

    /// 证据脱敏:空/错误串归一为(缺省),截断超长输出
    public static func evidence(_ s: String, maxLen: Int = 220) -> String {
        let t = s.trimmingCharacters(in: .whitespacesAndNewlines)
        if t.isEmpty { return "(无输出)" }
        let low = t.lowercased()
        if low.hasPrefix("error") || low.contains("could not find") || low.contains("does not exist")
            || low.contains("permission denied") || low.contains("operation not permitted") {
            return "(缺省)"
        }
        let first = t.split(separator: "\n").prefix(3).joined(separator: " | ")
        return String(first.prefix(maxLen))
    }
}
