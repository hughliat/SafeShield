import Foundation
import AppKit

// MARK: - 处置动作(设计 §4.1 / §6.2)

public enum ActionType: String, Codable, CaseIterable, Sendable {
    case openSettings, quarantineFile, restoreFile, killProcess, blockIP, acknowledge

    public var label: String {
        switch self {
        case .openSettings: return "打开系统设置"
        case .quarantineFile: return "隔离文件/启动项"
        case .restoreFile: return "从隔离区还原"
        case .killProcess: return "终止进程"
        case .blockIP: return "封禁 IP"
        case .acknowledge: return "标记已知悉"
        }
    }
    /// 可回滚
    public var reversible: Bool { self == .quarantineFile || self == .blockIP }
    /// 不可逆,需二次确认
    public var irreversible: Bool { self == .killProcess }
    /// 需要 root 特权(特权助手),无常驻特权渠道不执行
    public var requiresPrivilege: Bool { self == .blockIP }
}

public struct SecurityAction: Identifiable, Sendable {
    public let id: String
    public let type: ActionType
    public let target: String
    public let reason: String
    public let sourceEventId: String?
    public init(type: ActionType, target: String, reason: String, sourceEventId: String? = nil) {
        self.id = UUID().uuidString; self.type = type; self.target = target
        self.reason = reason; self.sourceEventId = sourceEventId
    }
}

// MARK: - 审计日志(JSONL,全量留痕,设计 §9.1c / §10)

public struct AuditRecord: Identifiable, Codable, Sendable {
    public let id: String
    public let time: Date
    public let actionType: String
    public let target: String
    public let reason: String
    public let posture: String
    public let result: String          // executed / would_execute / blocked / failed / rolled_back
    public var rolledBackAt: Date?
    public var rollbackOf: String?
}

public enum AuditLog {
    public static func append(_ r: AuditRecord) {
        let enc = JSONEncoder(); enc.dateEncodingStrategy = .iso8601
        guard let data = try? enc.encode(r), let line = String(data: data, encoding: .utf8) else { return }
        if let h = FileHandle(forWritingAtPath: SSPaths.auditURL.path) {
            h.seekToEndOfFile(); h.write((line + "\n").data(using: .utf8)!); try? h.close()
        } else {
            FileManager.default.createFile(atPath: SSPaths.auditURL.path, contents: (line + "\n").data(using: .utf8))
        }
    }
    public static func tail(_ n: Int = 200) -> [AuditRecord] {
        guard let s = try? String(contentsOf: SSPaths.auditURL, encoding: .utf8) else { return [] }
        let dec = JSONDecoder(); dec.dateDecodingStrategy = .iso8601
        return s.split(separator: "\n").suffix(n).compactMap { try? dec.decode(AuditRecord.self, from: Data($0.utf8)) }.reversed()
    }
}

// MARK: - 隔离区(可回滚处置的落点)

public struct QuarantineEntry: Codable, Sendable {
    public let id: String
    public let originalPath: String
    public let storedPath: String
    public let time: Date
    public let mode: Int
}

public enum QuarantineStore {
    public static var indexURL: URL { SSPaths.supportDir.appendingPathComponent("quarantine-index.json") }
    public static func load() -> [QuarantineEntry] {
        guard let d = try? Data(contentsOf: indexURL) else { return [] }
        let dec = JSONDecoder(); dec.dateDecodingStrategy = .iso8601
        return (try? dec.decode([QuarantineEntry].self, from: d)) ?? []
    }
    public static func save(_ list: [QuarantineEntry]) {
        let enc = JSONEncoder(); enc.dateEncodingStrategy = .iso8601; enc.outputFormatting = [.prettyPrinted]
        try? enc.encode(list).write(to: indexURL, options: .atomic)
    }
}

// MARK: - 处置执行器:窄白名单,与只读 ProcessRunner 分离

public enum ActionExecutor {
    public static let allowed: Set<String> = ["/bin/kill"]
    public static func run(_ tool: String, _ args: [String]) async -> CommandOutput {
        guard allowed.contains(tool) else {
            return CommandOutput(tool: tool, exitCode: 126, stdout: "", stderr: "not whitelisted")
        }
        for a in args where a.contains(";") || a.contains("|") || a.contains("&") || a.contains("\n") {
            return CommandOutput(tool: tool, exitCode: 126, stdout: "", stderr: "invalid argument \(a)")
        }
        let p = Process(); p.executableURL = URL(fileURLWithPath: tool); p.arguments = args
        let errBuf = NSMutableData()
        let errPipe = Pipe()
        errPipe.fileHandleForReading.readabilityHandler = { h in
            let d = h.availableData
            if !d.isEmpty { errBuf.append(d) }
        }
        p.standardError = errPipe; p.standardOutput = Pipe()
        do { try p.run() } catch { return CommandOutput(tool: tool, exitCode: 127, stdout: "", stderr: error.localizedDescription) }
        let deadline = Date().addingTimeInterval(10)
        while p.isRunning && Date() < deadline { try? await Task.sleep(nanoseconds: 50_000_000) }
        if p.isRunning { p.terminate() }
        try? await Task.sleep(nanoseconds: 100_000_000)
        errPipe.fileHandleForReading.readabilityHandler = nil
        let se = String(data: errBuf as Data, encoding: .utf8) ?? ""
        return CommandOutput(tool: tool, exitCode: p.terminationStatus, stdout: "", stderr: se)
    }
}

// MARK: - 策略:姿态门控 + 白名单拒绝 + 特权门控(设计 §6.2 ActionPolicy)

public struct ActionDecision: Sendable {
    public let allowed: Bool
    public let needsConfirm: Bool
    public let needsSecondConfirm: Bool
    public let blockedReason: String?
}

public enum ActionPolicy {
    public static func decide(_ a: SecurityAction, posture: ResponsePosture, judge: WhitelistJudge,
                              privilegedHelperInstalled: Bool = false) -> ActionDecision {
        if !posture.allowsAnyAction {
            return ActionDecision(allowed: false, needsConfirm: true, needsSecondConfirm: false,
                                  blockedReason: "当前姿态为「\(posture.rawValue)」,仅检测不处置。")
        }
        if a.type.requiresPrivilege && !privilegedHelperInstalled {
            return ActionDecision(allowed: false, needsConfirm: true, needsSecondConfirm: false,
                                  blockedReason: "「\(a.type.label)」需要 root 特权助手;当前渠道未安装,仅记录建议不执行。")
        }
        // 白名单目标一律拒绝处置(企业合规软件/系统组件保护)
        switch a.type {
        case .killProcess:
            if judge.process(a.target) {
                return ActionDecision(allowed: false, needsConfirm: true, needsSecondConfirm: false,
                                      blockedReason: "目标进程命中白名单,拒绝终止。")
            }
        case .quarantineFile:
            if judge.path(a.target) {
                return ActionDecision(allowed: false, needsConfirm: true, needsSecondConfirm: false,
                                      blockedReason: "目标路径命中白名单,拒绝隔离。")
            }
        case .blockIP:
            if judge.ip(a.target) {
                return ActionDecision(allowed: false, needsConfirm: true, needsSecondConfirm: false,
                                      blockedReason: "目标 IP 命中白名单/私有段,拒绝封禁。")
            }
        default: break
        }
        let needsConfirm = !(posture.autoReversible && a.type.reversible)
        return ActionDecision(allowed: true, needsConfirm: needsConfirm,
                              needsSecondConfirm: a.type.irreversible, blockedReason: nil)
    }
}

// MARK: - 协调器:确认 → 执行 → 审计 → 回滚(设计 §6.2)

@MainActor
public final class ResponseCoordinator: ObservableObject {
    @Published public private(set) var audit: [AuditRecord] = AuditLog.tail()
    @Published public private(set) var quarantine: [QuarantineEntry] = QuarantineStore.load()

    public init() {}

    @discardableResult
    public func execute(_ a: SecurityAction, posture: ResponsePosture, judge: WhitelistJudge,
                        confirmed: Bool) async -> AuditRecord {
        let decision = ActionPolicy.decide(a, posture: posture, judge: judge)
        func record(_ result: String) -> AuditRecord {
            let r = AuditRecord(id: a.id, time: Date(), actionType: a.type.rawValue, target: a.target,
                                reason: a.reason, posture: posture.rawValue, result: result,
                                rolledBackAt: nil, rollbackOf: nil)
            AuditLog.append(r)
            audit.insert(r, at: 0)
            return r
        }
        guard decision.allowed else { return record("blocked: \(decision.blockedReason ?? "-")") }
        if decision.needsConfirm && !confirmed { return record("would_execute (awaiting confirm)") }

        switch a.type {
        case .openSettings:
            if let u = URL(string: a.target) { NSWorkspace.shared.open(u) }
            return record("executed")
        case .quarantineFile:
            return quarantineFile(a, record: record)
        case .restoreFile:
            return restore(a.target, record: record)
        case .killProcess:
            let out = await ActionExecutor.run("/bin/kill", ["-9", a.target])
            return record(out.ok ? "executed" : "failed: \(out.stderr)")
        case .blockIP:
            // 无常驻特权:只记录建议,绝不尝试 pfctl
            return record("would_execute (requires privileged helper)")
        case .acknowledge:
            return record("executed")
        }
    }

    private func quarantineFile(_ a: SecurityAction, record: (String) -> AuditRecord) -> AuditRecord {
        let fm = FileManager.default
        let src = a.target
        guard fm.fileExists(atPath: src) else { return record("failed: 文件不存在") }
        let attrs = (try? fm.attributesOfItem(atPath: src)) ?? [:]
        let mode = (attrs[.posixPermissions] as? NSNumber)?.intValue ?? 0o644
        let ts = Fmt.full(Date()).replacingOccurrences(of: " ", with: "_").replacingOccurrences(of: ":", with: "")
        let dst = SSPaths.quarantineDir.appendingPathComponent("\(ts)_\((src as NSString).lastPathComponent)").path
        do {
            try fm.moveItem(atPath: src, toPath: dst)
            try? fm.setAttributes([.posixPermissions: 0], ofItemAtPath: dst)
            var list = quarantine
            let entry = QuarantineEntry(id: a.id, originalPath: src, storedPath: dst, time: Date(), mode: mode)
            list.append(entry); quarantine = list; QuarantineStore.save(list)
            return record("executed (quarantined → \(dst))")
        } catch {
            return record("failed: \(error.localizedDescription)")
        }
    }

    private func restore(_ entryId: String, record: (String) -> AuditRecord) -> AuditRecord {
        guard let idx = quarantine.firstIndex(where: { $0.id == entryId }) else {
            return record("failed: 隔离记录不存在")
        }
        let e = quarantine[idx]
        let fm = FileManager.default
        do {
            try? fm.setAttributes([.posixPermissions: e.mode], ofItemAtPath: e.storedPath)
            try fm.moveItem(atPath: e.storedPath, toPath: e.originalPath)
            quarantine.remove(at: idx); QuarantineStore.save(quarantine)
            var r = record("executed (restored → \(e.originalPath))")
            r.rolledBackAt = Date(); r.rollbackOf = entryId
            return r
        } catch {
            return record("failed: \(error.localizedDescription)")
        }
    }

    public func rollback(_ auditId: String) async -> AuditRecord? {
        guard let rec = audit.first(where: { $0.id == auditId }), rec.actionType == ActionType.quarantineFile.rawValue,
              rec.result.hasPrefix("executed") else { return nil }
        let r = await restore(rec.id, record: { _ in
            let nr = AuditRecord(id: UUID().uuidString, time: Date(), actionType: ActionType.restoreFile.rawValue,
                                 target: rec.target, reason: "回滚 \(rec.id)", posture: "rollback",
                                 result: "executed", rolledBackAt: Date(), rollbackOf: rec.id)
            AuditLog.append(nr); audit.insert(nr, at: 0); return nr
        })
        return r
    }
}
