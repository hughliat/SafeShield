//
//  SafeShieldMVP.swift
//  安全盾 SafeShield · MVP 真实 Demo（体检最小闭环）
//
//  对应《03-安全盾SafeShield-开发设计.md》MVP 范围（V2/V3/V4/V6/V7 的精简真实版）：
//   - SystemConfigDetector 全 7 项 + 账户自动登录，全部**真读本机状态**（只读，不修改系统）
//   - ProcessRunner 白名单命令执行（Process 直调二进制，不经 shell，杜绝注入）§9.1
//   - RuleEngine 按文档评分公式 §7：S = 100 × (1 − Σ(w·p_sev)/Σw)
//   - RemediationRouter 深链跳转系统设置 §6/PRD F2
//   - SwiftUI 仪表盘：评分环 + 风险列表 + 去修复
//
//  编译（无完整 Xcode，用 CommandLineTools 的 swiftc）：
//    swiftc -O -o SafeShieldMVP SafeShieldMVP.swift
//  运行：
//    ./SafeShieldMVP
//
import SwiftUI
import AppKit

// MARK: - 领域模型（对应设计 §4）

enum Severity: Int, Comparable, CaseIterable {
    case info = 0, low = 1, medium = 2, high = 3, critical = 4
    static func < (l: Severity, r: Severity) -> Bool { l.rawValue < r.rawValue }
    var label: String {
        switch self {
        case .info: return "提示"; case .low: return "低危"; case .medium: return "中危"
        case .high: return "高危"; case .critical: return "严重"
        }
    }
    var color: Color {
        switch self {
        case .info: return .secondary; case .low: return .blue; case .medium: return .yellow
        case .high: return .orange; case .critical: return .red
        }
    }
    /// 评分惩罚系数 p（设计 §7）
    var penalty: Double {
        switch self {
        case .critical: return 1.0; case .high: return 0.6; case .medium: return 0.3
        case .low: return 0.1; case .info: return 0
        }
    }
}

enum FindingStatus: String { case passed = "通过", risk = "风险", unavailable = "未检测" }

struct Finding: Identifiable {
    let id = UUID()
    let ruleID: String
    let dimension: String
    let title: String
    let detail: String
    let severity: Severity          // 仅当 status == .risk 时有意义
    let status: FindingStatus
    let evidence: String            // 真实命令输出（脱敏：仅状态值）
    let remediationURL: String?     // 深链；nil 表示需人工引导
    let manualGuide: String?
}

// MARK: - ProcessRunner（白名单命令执行，设计 §9.1）

actor ProcessRunner {
    static let shared = ProcessRunner()
    /// 仅允许白名单内只读命令；参数固定，不接受用户输入拼接
    private static let allowed: Set<String> = [
        "/usr/bin/csrutil", "/usr/bin/fdesetup", "/usr/sbin/spctl",
        "/usr/libexec/ApplicationFirewall/socketfilterfw",
        "/usr/bin/defaults", "/usr/bin/sw_vers"
    ]
    /// 直调二进制，不经过 shell，从根本上消除命令注入面
    func run(_ tool: String, _ args: [String]) -> String {
        guard Self.allowed.contains(tool) else { return "" }
        let p = Process()
        p.executableURL = URL(fileURLWithPath: tool)
        p.arguments = args
        let out = Pipe(), err = Pipe()
        p.standardOutput = out; p.standardError = err
        do { try p.run(); p.waitUntilExit() } catch { return "" }
        let data = out.fileHandleForReading.readDataToEndOfFile()
        let e = err.fileHandleForReading.readDataToEndOfFile()
        let s = String(data: data, encoding: .utf8)?.trimmingCharacters(in: .whitespacesAndNewlines) ?? ""
        let es = String(data: e, encoding: .utf8)?.trimmingCharacters(in: .whitespacesAndNewlines) ?? ""
        return s.isEmpty ? es : s
    }
}

// MARK: - SystemConfigDetector（真实检测，设计 §V4 / PRD F2 + F7-3）

struct SystemConfigDetector {
    /// 已知最新大版本（离线补丁表 latestPatchTable 的精简版，设计 §7 离线版本比对）
    static let knownLatestMajor = 27

    /// 把 defaults 的"键不存在"报错规范化为 (缺省)，避免把报错原文当证据展示
    static func norm(_ s: String) -> String {
        let t = s.trimmingCharacters(in: .whitespacesAndNewlines)
        if t.isEmpty || t.hasPrefix("Error") || t.contains("Could not find") || t.contains("Does Not Exist") {
            return "(缺省)"
        }
        return t
    }

    static func detect() async -> [Finding] {
        let pr = ProcessRunner.shared
        var f: [Finding] = []

        // F2-1 SIP
        let sip = await pr.run("/usr/bin/csrutil", ["status"])
        let sipOn = sip.lowercased().contains("enabled") && !sip.lowercased().contains("disabled")
        f.append(Finding(ruleID: "SYS-SIP-001", dimension: "系统配置",
            title: "SIP 系统完整性保护", detail: sipOn ? "系统关键区域受保护。" : "SIP 被关闭，系统完整性失去保护。",
            severity: sipOn ? .info : .critical, status: sipOn ? .passed : .risk,
            evidence: sip, remediationURL: nil,
            manualGuide: sipOn ? nil : "需进入恢复模式执行 csrutil enable 重新开启。"))

        // F2-2 FileVault
        let fv = await pr.run("/usr/bin/fdesetup", ["status"])
        let fvOn = fv.contains("On")
        f.append(Finding(ruleID: "SYS-FILEVAULT-001", dimension: "系统配置",
            title: "FileVault 全盘加密", detail: fvOn ? "磁盘已加密，设备丢失时数据受保护。" : "磁盘未加密，设备丢失时数据可被直接读取。",
            severity: fvOn ? .info : .critical, status: fvOn ? .passed : .risk,
            evidence: fv, remediationURL: "x-apple.systempreferences:com.apple.preference.security?FDE", manualGuide: nil))

        // F2-3 Gatekeeper
        let gk = await pr.run("/usr/sbin/spctl", ["--status"])
        let gkOn = gk.contains("enabled") && !gk.contains("disabled")
        f.append(Finding(ruleID: "SYS-GATEKEEPER-001", dimension: "系统配置",
            title: "Gatekeeper / 公证策略", detail: gkOn ? "仅允许经公证的应用运行。" : "已设为允许任何来源，恶意软件易潜入。",
            severity: gkOn ? .info : .high, status: gkOn ? .passed : .risk,
            evidence: gk, remediationURL: "x-apple.systempreferences:com.apple.preference.security?General", manualGuide: nil))

        // F2-4 防火墙
        let fw = await pr.run("/usr/libexec/ApplicationFirewall/socketfilterfw", ["--getglobalstate"])
        let fwOn = fw.lowercased().contains("enabled") && !fw.lowercased().contains("not enabled")
        f.append(Finding(ruleID: "SYS-FIREWALL-001", dimension: "系统配置",
            title: "应用防火墙", detail: fwOn ? "入站连接受防火墙管控。" : "防火墙关闭，入站连接不受限制。",
            severity: fwOn ? .info : .medium, status: fwOn ? .passed : .risk,
            evidence: fw, remediationURL: "x-apple.systempreferences:com.apple.preference.security?Firewall", manualGuide: nil))

        // F2-5 自动更新（AutomaticDownload / AutomaticCheckEnabled，缺失视为系统默认开启检查）
        let auD = await pr.run("/usr/bin/defaults", ["read", "/Library/Preferences/com.apple.SoftwareUpdate", "AutomaticDownload"])
        let auC = await pr.run("/usr/bin/defaults", ["read", "/Library/Preferences/com.apple.SoftwareUpdate", "AutomaticCheckEnabled"])
        let auOn = auD == "1" || auC == "1"
        f.append(Finding(ruleID: "SYS-AUTOUPDATE-001", dimension: "系统配置",
            title: "系统自动更新", detail: auOn ? "安全更新将自动下载/检查。" : "未开启自动更新，可能错过安全补丁。",
            severity: auOn ? .info : .medium, status: auOn ? .passed : .risk,
            evidence: "AutomaticDownload=\(norm(auD)) AutomaticCheckEnabled=\(norm(auC))",
            remediationURL: "x-apple.systempreferences:com.apple.preferences.softwareupdate", manualGuide: nil))

        // F2-6 版本落后（离线比对 knownLatestMajor）
        let ver = await pr.run("/usr/bin/sw_vers", ["-productVersion"])
        let major = Int(ver.split(separator: ".").first.map(String.init) ?? "0") ?? 0
        let lag = knownLatestMajor - major
        let verOK = lag <= 0
        f.append(Finding(ruleID: "SYS-OSVER-001", dimension: "系统配置",
            title: "系统版本落后程度", detail: verOK ? "处于已知最新大版本。" : "落后已知最新大版本 \(lag) 代，建议升级。",
            severity: verOK ? .info : .medium, status: verOK ? .passed : .risk,
            evidence: "productVersion=\(ver) knownLatestMajor=\(knownLatestMajor)",
            remediationURL: "x-apple.systempreferences:com.apple.preferences.softwareupdate", manualGuide: nil))

        // F2-7 锁屏密码（askForPassword 缺省视为系统默认开启）
        let sl = await pr.run("/usr/bin/defaults", ["-currentHost", "read", "com.apple.screensaver", "askForPassword"])
        let slN = norm(sl)
        let slOn = slN != "0"
        f.append(Finding(ruleID: "SYS-SCREENLOCK-001", dimension: "系统配置",
            title: "屏幕锁定密码", detail: slOn ? "唤醒/屏保后需要密码（或系统默认开启）。" : "唤醒后不需要密码，物理接触即可进入桌面。",
            severity: slOn ? .info : .medium, status: slOn ? .passed : .risk,
            evidence: "askForPassword=\(slN == "(缺省)" ? "(缺省, 系统默认 on)" : slN)",
            remediationURL: "x-apple.systempreferences:com.apple.preference.security?General", manualGuide: nil))

        // F7-3 自动登录（账户维度）
        let al = await pr.run("/usr/bin/defaults", ["read", "/Library/Preferences/com.apple.loginwindow", "autoLoginUser"])
        let alOn = !al.isEmpty && !al.lowercased().contains("error") && !al.contains("Does Not Exist")
        f.append(Finding(ruleID: "ACC-AUTOLOGIN-001", dimension: "账户",
            title: "自动登录", detail: alOn ? "开机无需密码即进入桌面（autoLoginUser=\(al)），物理接触即可访问全部数据。" : "未开启自动登录，开机需输入密码。",
            severity: alOn ? .medium : .info, status: alOn ? .risk : .passed,
            evidence: alOn ? "autoLoginUser=\(al)" : "autoLoginUser=(未设置)",
            remediationURL: "x-apple.systempreferences:com.apple.UsersGroups", manualGuide: nil))

        return f
    }
}

// MARK: - RuleEngine 评分（设计 §7）

enum RuleEngine {
    /// S = 100 × (1 − Σ(w·p_sev)/Σw)，w 统一取 1；unavailable 剔除
    static func score(_ findings: [Finding]) -> Int {
        let pool = findings.filter { $0.status != .unavailable }
        guard !pool.isEmpty else { return 100 }
        let sumP = pool.reduce(0.0) { $0 + ($1.status == .risk ? $1.severity.penalty : 0) }
        let s = 100.0 * (1.0 - sumP / Double(pool.count))
        return Int(s.rounded())
    }
}

// MARK: - RemediationRouter（深链跳转，设计 §6）

enum RemediationRouter {
    static func open(_ target: String?) {
        guard let t = target, let url = URL(string: t) else { return }
        NSWorkspace.shared.open(url)
    }
}

// MARK: - ViewModel

@MainActor
final class ScanViewModel: ObservableObject {
    @Published var findings: [Finding] = []
    @Published var scanning = false
    @Published var score: Int = 0
    @Published var scannedAt: String = ""

    func run() async {
        scanning = true
        let f = await SystemConfigDetector.detect()
        findings = f.sorted { lhs, rhs in
            let lv = lhs.status == .risk ? lhs.severity.rawValue : -1
            let rv = rhs.status == .risk ? rhs.severity.rawValue : -1
            return lv > rv
        }
        score = RuleEngine.score(f)
        scannedAt = Date().formatted(date: .omitted, time: .shortened)
        scanning = false
    }
}

// MARK: - UI

struct ScoreRing: View {
    let value: Int
    var body: some View {
        ZStack {
            Circle().stroke(Color.gray.opacity(0.2), lineWidth: 12)
            Circle().trim(from: 0, to: CGFloat(value) / 100)
                .stroke(ringColor, style: StrokeStyle(lineWidth: 12, lineCap: .round))
                .rotationEffect(.degrees(-90))
            VStack(spacing: 2) {
                Text("\(value)").font(.system(size: 40, weight: .heavy, design: .rounded))
                Text(scoreLabel).font(.caption).foregroundStyle(.secondary)
            }
        }
        .frame(width: 140, height: 140)
    }
    var ringColor: Color { value >= 85 ? .green : value >= 70 ? .yellow : .orange }
    var scoreLabel: String { value >= 85 ? "良好" : value >= 70 ? "中危" : "需关注" }
}

struct FindingRow: View {
    let f: Finding
    var body: some View {
        HStack(alignment: .top, spacing: 12) {
            Image(systemName: f.status == .passed ? "checkmark.circle.fill" : "exclamationmark.triangle.fill")
                .foregroundStyle(f.status == .passed ? .green : f.severity.color)
                .font(.title3)
            VStack(alignment: .leading, spacing: 4) {
                HStack(spacing: 8) {
                    Text(f.title).font(.headline)
                    Text(f.status == .passed ? "通过" : f.severity.label)
                        .font(.caption2.bold())
                        .padding(.horizontal, 7).padding(.vertical, 2)
                        .background((f.status == .passed ? Color.green : f.severity.color).opacity(0.18), in: Capsule())
                        .foregroundStyle(f.status == .passed ? .green : f.severity.color)
                    Text(f.dimension).font(.caption2).foregroundStyle(.secondary)
                        .padding(.horizontal, 7).padding(.vertical, 2)
                        .background(Color.gray.opacity(0.15), in: Capsule())
                }
                Text(f.detail).font(.subheadline).foregroundStyle(.secondary)
                Text(f.evidence).font(.system(.caption, design: .monospaced))
                    .foregroundStyle(.secondary).padding(6)
                    .frame(maxWidth: .infinity, alignment: .leading)
                    .background(Color.gray.opacity(0.1), in: RoundedRectangle(cornerRadius: 6))
                if let g = f.manualGuide {
                    Text("修复引导：\(g)").font(.caption).foregroundStyle(.orange)
                }
            }
            Spacer()
            if f.status == .risk {
                Button("去修复") { RemediationRouter.open(f.remediationURL) }
                    .buttonStyle(.bordered)
            }
        }
        .padding(.vertical, 6)
    }
}

struct ContentView: View {
    @StateObject private var vm = ScanViewModel()
    var body: some View {
        VStack(spacing: 0) {
            HStack(spacing: 24) {
                ScoreRing(value: vm.score)
                VStack(alignment: .leading, spacing: 6) {
                    Text("安全盾 SafeShield").font(.title.bold())
                    Text("MVP 真实 Demo · 体检最小闭环").font(.subheadline).foregroundStyle(.secondary)
                    Text("最近体检：\(vm.scannedAt.isEmpty ? "—" : vm.scannedAt) · 规则库 v1 · 只读检测")
                        .font(.caption).foregroundStyle(.secondary)
                    HStack {
                        let risks = vm.findings.filter { $0.status == .risk }
                        Text("风险 \(risks.count) 项 · 通过 \(vm.findings.count - risks.count) 项")
                            .font(.callout)
                        Spacer()
                        Button(vm.scanning ? "体检中…" : "重新体检") {
                            Task { await vm.run() }
                        }
                        .buttonStyle(.borderedProminent)
                        .disabled(vm.scanning)
                    }
                }
                Spacer()
            }
            .padding(20)

            Divider()

            ScrollView {
                LazyVStack(spacing: 4) {
                    ForEach(vm.findings) { FindingRow(f: $0) }
                }
                .padding(20)
            }
        }
        .frame(minWidth: 720, minHeight: 620)
        .task { await vm.run() }
    }
}

@main
struct SafeShieldMVPApp: App {
    var body: some Scene {
        WindowGroup("安全盾 SafeShield · MVP 真实 Demo") {
            ContentView()
        }
        .defaultSize(width: 820, height: 700)
    }
}
