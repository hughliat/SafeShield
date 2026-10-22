import Foundation

// MARK: - 快照检测器协议(设计 §5)

public struct DetectContext: Sendable {
    public let rules: RuleSet
    public let judge: WhitelistJudge
    public let pr: ProcessRunner
    public init(rules: RuleSet, judge: WhitelistJudge, pr: ProcessRunner) {
        self.rules = rules; self.judge = judge; self.pr = pr
    }
    public func rule(_ id: String) -> Rule? { rules.rules[id] }

    public func finding(_ id: String, _ status: FindingStatus, _ summary: String, _ evidence: String,
                        overrideSeverity: Severity? = nil) -> Finding {
        let r = rules.rules[id]
        let sev = overrideSeverity ?? (status == .fail ? (r?.failSeverity ?? .medium) : .info)
        return Finding(id: id,
                       name: r?.name ?? id,
                       dimension: r?.dimension ?? .systemConfig,
                       status: status,
                       severity: sev,
                       summary: summary,
                       evidence: evidence,
                       remediationKind: r?.remediationKind ?? "guide",
                       remediationTarget: r?.remediationTarget,
                       actionType: r?.actionType,
                       weight: r?.weight ?? 1.0)
    }
}

public protocol Detector: Sendable {
    var id: String { get }
    var title: String { get }
    func detect(ctx: DetectContext) async -> [Finding]
}

// MARK: - 1 系统配置

public struct SystemConfigDetector: Detector {
    public let id = "systemConfig"; public let title = "系统配置"
    public init() {}
    public func detect(ctx: DetectContext) async -> [Finding] {
        var out: [Finding] = []
        let pr = ctx.pr

        let sip = await pr.run("/usr/bin/csrutil", ["status"])
        let sipOn = sip.stdout.lowercased().contains("enabled")
        out.append(ctx.finding("sys.sip", sipOn ? .pass : .fail,
                               sipOn ? "系统关键区域受保护。" : "SIP 未启用,系统组件可被篡改。",
                               Fmt.evidence(sip.stdout + sip.stderr)))

        let fv = await pr.run("/usr/bin/fdesetup", ["status"])
        let fvOn = fv.stdout.contains("On")
        out.append(ctx.finding("sys.filevault", fvOn ? .pass : .fail,
                               fvOn ? "磁盘已加密,设备丢失时数据受保护。" : "磁盘未加密,丢失即泄露。",
                               Fmt.evidence(fv.stdout + fv.stderr)))

        let gk = await pr.run("/usr/sbin/spctl", ["--status"])
        let gkOn = gk.stdout.contains("enabled")
        out.append(ctx.finding("sys.gatekeeper", gkOn ? .pass : .fail,
                               gkOn ? "仅允许经公证的应用运行。" : "公证策略被关闭,可运行任意来源应用。",
                               Fmt.evidence(gk.stdout + gk.stderr)))

        let fw = await pr.run("/usr/libexec/ApplicationFirewall/socketfilterfw", ["--getglobalstate"])
        let fwOn = fw.stdout.lowercased().contains("enabled")
        out.append(ctx.finding("sys.firewall", fwOn ? .pass : .fail,
                               fwOn ? "入站连接受防火墙管控。" : "应用防火墙关闭,入站连接不受管控。",
                               Fmt.evidence(fw.stdout + fw.stderr)))

        let au1 = await pr.run("/usr/bin/defaults", ["read", "/Library/Preferences/com.apple.SoftwareUpdate", "AutomaticCheckEnabled"])
        let au2 = await pr.run("/usr/bin/defaults", ["read", "/Library/Preferences/com.apple.SoftwareUpdate", "AutomaticDownload"])
        let checkOff = au1.stdout.trimmingCharacters(in: .whitespacesAndNewlines) == "0"
        let dlOff = au2.stdout.trimmingCharacters(in: .whitespacesAndNewlines) == "0"
        let auOn = !(checkOff || dlOff)
        out.append(ctx.finding("sys.autoupdate", auOn ? .pass : .fail,
                               auOn ? "安全更新将自动下载/检查。" : "自动检查或下载更新被关闭。",
                               "AutomaticCheckEnabled=\(Fmt.evidence(au1.stdout + au1.stderr)) AutomaticDownload=\(Fmt.evidence(au2.stdout + au2.stderr))"))

        let sv = await pr.run("/usr/bin/sw_vers", ["-productVersion"])
        let major = Int(sv.stdout.split(separator: ".").first.map(String.init) ?? "") ?? 0
        let latest = ctx.rules.knownLatestOSMajor
        if major == 0 {
            out.append(ctx.finding("sys.osversion", .unavailable, "无法读取系统版本。", Fmt.evidence(sv.stdout + sv.stderr)))
        } else if major < latest {
            out.append(ctx.finding("sys.osversion", .fail,
                                   "本机 macOS \(major) 落后于已知最新大版本 \(latest)(离线补丁表 \(ctx.rules.asOf))。",
                                   Fmt.evidence(sv.stdout)))
        } else {
            out.append(ctx.finding("sys.osversion", .pass, "系统版本处于已知最新大版本区间。", Fmt.evidence(sv.stdout)))
        }

        let sl = await pr.run("/usr/bin/defaults", ["read", "com.apple.screensaver", "askForPassword"])
        let slv = sl.stdout.trimmingCharacters(in: .whitespacesAndNewlines)
        if slv == "1" {
            out.append(ctx.finding("sys.screenlock", .pass, "唤醒/屏保后要求输入密码。", "askForPassword=1"))
        } else if slv == "0" {
            out.append(ctx.finding("sys.screenlock", .fail, "锁屏不要求密码,离开座位即暴露会话。", "askForPassword=0"))
        } else {
            out.append(ctx.finding("sys.screenlock", .unavailable, "未读取到锁屏策略键(系统默认值未知),不计分。", Fmt.evidence(sl.stdout + sl.stderr)))
        }

        let al = await pr.run("/usr/bin/defaults", ["read", "/Library/Preferences/com.apple.loginwindow", "autoLoginUser"])
        let alv = al.stdout.trimmingCharacters(in: .whitespacesAndNewlines)
        if alv.isEmpty || alv == "(缺省)" || al.stderr.contains("Could not find") || al.stderr.contains("Does Not Exist") {
            out.append(ctx.finding("sys.autologin", .pass, "未启用自动登录。", "autoLoginUser=(缺省)"))
        } else {
            out.append(ctx.finding("sys.autologin", .fail,
                                   "开机无需密码即进入桌面(autoLoginUser=\(alv)),物理接触即可访问全部数据。",
                                   "autoLoginUser=\(alv)"))
        }
        return out
    }
}

// MARK: - 2 隐私授权(TCC 不可读时降级为引导清单,不计分)

public struct PrivacyPermissionDetector: Detector {
    public let id = "privacy"; public let title = "隐私授权"
    public init() {}
    public func detect(ctx: DetectContext) async -> [Finding] {
        let tcc = URL(fileURLWithPath: NSHomeDirectory())
            .appendingPathComponent("Library/Application Support/com.apple.TCC/TCC.db")
        let fm = FileManager.default
        if fm.isReadableFile(atPath: tcc.path), let _ = try? Data(contentsOf: tcc, options: .alwaysMapped) {
            return [ctx.finding("priv.tcc", .pass, "已具备完全磁盘访问,可读取 TCC 授权清单。", "TCC.db readable")]
        }
        return [ctx.finding("priv.tcc", .unavailable,
                            "未授权完全磁盘访问,无法读取系统授权清单;已降级为引导:请在 系统设置 ▸ 隐私与安全性 中审查 屏幕录制/辅助功能/完全磁盘访问/自动化 的授权应用。",
                            "TCC.db not readable (expected without Full Disk Access)")]
    }
}

// MARK: - 3 驻留(启动项 / cron / 登录项)

public struct PersistenceDetector: Detector {
    public let id = "persistence"; public let title = "驻留启动项"
    public init() {}

    public static func launchDirs() -> [String] {
        ["/Library/LaunchAgents", "/Library/LaunchDaemons", NSHomeDirectory() + "/Library/LaunchAgents"]
    }

    public func detect(ctx: DetectContext) async -> [Finding] {
        var out: [Finding] = []
        let fm = FileManager.default
        var unknown: [String] = []
        for dir in Self.launchDirs() {
            guard let names = try? fm.contentsOfDirectory(atPath: dir) else { continue }
            for n in names where !n.hasPrefix(".") {
                if !ctx.judge.launchLabel(n) { unknown.append("\(dir)/\(n)") }
            }
        }
        if unknown.isEmpty {
            out.append(ctx.finding("pers.launchitems", .pass, "启动项均为系统或白名单厂商签名项。", "3 dirs scanned, 0 unknown"))
        } else {
            out.append(ctx.finding("pers.launchitems", .fail,
                                   "发现 \(unknown.count) 个非系统、非白名单的自启动项,可能是驻留后门。",
                                   Fmt.evidence(unknown.prefix(6).joined(separator: "\n"))))
        }

        let cron = await ctx.pr.run("/usr/bin/crontab", ["-l"])
        let cronOut = (cron.stdout + cron.stderr).lowercased()
        if cronOut.contains("no crontab") {
            out.append(ctx.finding("pers.cron", .pass, "当前用户无 crontab 任务。", "no crontab for user"))
        } else if cron.exitCode == 0 && !cron.stdout.trimmingCharacters(in: .whitespaces).isEmpty {
            out.append(ctx.finding("pers.cron", .fail, "存在用户 crontab 任务,需审查是否被用于持久化。", Fmt.evidence(cron.stdout)))
        } else {
            out.append(ctx.finding("pers.cron", .unavailable, "无法读取 crontab。", Fmt.evidence(cron.stdout + cron.stderr)))
        }

        let li = await ctx.pr.run("/usr/bin/osascript", ["-e",
            "tell application \"System Events\" to get the name of every login item"], timeout: 6)
        let lit = li.stdout.trimmingCharacters(in: .whitespaces)
        if li.exitCode == 0 && (lit.isEmpty || lit == "") {
            out.append(ctx.finding("pers.loginitems", .pass, "无登录自启应用。", "login items: (empty)"))
        } else if li.exitCode == 0 {
            out.append(ctx.finding("pers.loginitems", .fail, "存在登录自启应用,建议审查必要性。", Fmt.evidence(lit)))
        } else {
            out.append(ctx.finding("pers.loginitems", .unavailable, "未获自动化授权,无法枚举登录项,不计分。", Fmt.evidence(li.stderr)))
        }
        return out
    }
}

// MARK: - 4 文件完整性

public struct FileIntegrityDetector: Detector {
    public let id = "fileIntegrity"; public let title = "文件完整性"
    public init() {}
    public func detect(ctx: DetectContext) async -> [Finding] {
        var out: [Finding] = []
        let fm = FileManager.default

        // SSH 私钥权限
        let sshDir = NSHomeDirectory() + "/.ssh"
        var badKeys: [String] = []
        if let names = try? fm.contentsOfDirectory(atPath: sshDir) {
            for n in names {
                guard !n.hasSuffix(".pub"), n.hasPrefix("id_") || n.hasSuffix(".pem") || n == "identity" else { continue }
                if let attrs = try? fm.attributesOfItem(atPath: sshDir + "/" + n),
                   let num = attrs[.posixPermissions] as? NSNumber {
                    let mode = num.int16Value
                    if mode & 0o077 != 0 { badKeys.append("\(n) mode=\(String(mode, radix: 8))") }
                }
            }
        }
        if badKeys.isEmpty {
            out.append(ctx.finding("file.sshperms", .pass, "SSH 私钥权限正确(仅属主可读写)。", "~/.ssh checked, 0 loose key"))
        } else {
            out.append(ctx.finding("file.sshperms", .fail, "私钥权限过宽,同机其他用户可读。", Fmt.evidence(badKeys.joined(separator: "\n"))))
        }

        // 高危目录可写脚本
        var ww: [String] = []
        for base in ctx.judge.w.watchPaths {
            guard let names = try? fm.contentsOfDirectory(atPath: base) else { continue }
            for n in names.prefix(400) {
                let full = base + "/" + n
                var isDir: ObjCBool = false
                guard fm.fileExists(atPath: full, isDirectory: &isDir), !isDir.boolValue else { continue }
                let ext = (n as NSString).pathExtension.lowercased()
                guard ["sh", "py", "pl", "rb", "php", "js", "bash", "command", "dylib", "so", ""].contains(ext) else { continue }
                if ctx.judge.path(full) { continue }
                if let attrs = try? fm.attributesOfItem(atPath: full),
                   let num = attrs[.posixPermissions] as? NSNumber, num.int16Value & 0o002 != 0 {
                    ww.append(full)
                }
            }
        }
        if ww.isEmpty {
            out.append(ctx.finding("file.worldwritable", .pass, "共享/临时目录未发现全局可写脚本。", "watchPaths scanned, 0 world-writable script"))
        } else {
            out.append(ctx.finding("file.worldwritable", .fail, "发现全局可写脚本,可能被他人替换利用。", Fmt.evidence(ww.prefix(6).joined(separator: "\n"))))
        }

        // /etc/hosts 劫持迹象
        if let hosts = try? String(contentsOfFile: "/etc/hosts", encoding: .utf8) {
            var odd: [String] = []
            for line in hosts.split(separator: "\n") {
                let t = line.trimmingCharacters(in: .whitespaces)
                if t.isEmpty || t.hasPrefix("#") { continue }
                let parts = t.split(whereSeparator: { $0 == " " || $0 == "\t" })
                guard let ip = parts.first.map(String.init) else { continue }
                if !ip.hasPrefix("127.") && ip != "::1" && ip != "255.255.255.255"
                    && !ip.hasPrefix("224.") && !t.contains("broadcasthost") { odd.append(t) }
            }
            if odd.isEmpty {
                out.append(ctx.finding("file.hosts", .pass, "/etc/hosts 仅含回环映射。", "0 non-loopback mapping"))
            } else {
                out.append(ctx.finding("file.hosts", .fail,
                                       "/etc/hosts 含 \(odd.count) 条非回环映射(含 intentional 本地映射需人工确认)。",
                                       Fmt.evidence(odd.prefix(5).joined(separator: "\n"))))
            }
        } else {
            out.append(ctx.finding("file.hosts", .unavailable, "无法读取 /etc/hosts。", "(缺省)"))
        }
        return out
    }
}

// MARK: - 5 网络

public enum NetParse {
    public struct Conn { public let proc: String; public let pid: String; public let name: String }
    /// lsof -nP -iTCP -sTCP:<STATE> 输出解析
    public static func parse(_ stdout: String) -> [Conn] {
        var out: [Conn] = []
        for line in stdout.split(separator: "\n").dropFirst() {
            let f = line.split(whereSeparator: { $0 == " " }).map(String.init)
            guard f.count >= 9 else { continue }
            out.append(Conn(proc: f[0], pid: f[1], name: f[f.count - 1]))
        }
        return out
    }
    public static func splitHostPort(_ s: String) -> (String, Int)? {
        guard let idx = s.lastIndex(of: ":") else { return nil }
        let host = String(s[s.startIndex..<idx])
        let portStr = String(s.suffix(from: idx).dropFirst())
        let port = Int(portStr) ?? 0
        return (host, port)
    }
    public static let suspiciousPorts: Set<Int> = [22, 23, 445, 3389, 5900, 4444, 5555, 6666, 8888]
}

public struct NetworkDetector: Detector {
    public let id = "network"; public let title = "网络暴露"
    public init() {}
    public func detect(ctx: DetectContext) async -> [Finding] {
        var out: [Finding] = []
        let listen = await ctx.pr.run("/usr/sbin/lsof", ["-nP", "-iTCP", "-sTCP:LISTEN"])
        var exposed: [String] = []
        for c in NetParse.parse(listen.stdout) {
            guard let (host, port) = NetParse.splitHostPort(c.name) else { continue }
            let loopback = host == "127.0.0.1" || host == "::1" || host == "localhost" || host.hasPrefix("fe80")
            if loopback || ctx.judge.port(port) || ctx.judge.process(c.proc) { continue }
            exposed.append("\(c.proc)(pid \(c.pid)) \(host):\(port)")
        }
        if exposed.isEmpty {
            out.append(ctx.finding("net.listen", .pass, "无对外暴露的非白名单监听端口。", "LISTEN scanned, 0 exposed"))
        } else {
            out.append(ctx.finding("net.listen", .fail, "存在 \(exposed.count) 个对外监听端口,扩大攻击面。",
                                   Fmt.evidence(exposed.prefix(5).joined(separator: "\n"))))
        }

        let est = await ctx.pr.run("/usr/sbin/lsof", ["-nP", "-iTCP", "-sTCP:ESTABLISHED"])
        var susp: [String] = []
        var counter: [String: Int] = [:]
        for c in NetParse.parse(est.stdout) {
            guard let arrow = c.name.range(of: "->") else { continue }
            let remote = String(c.name[arrow.upperBound...])
            guard let (ip, port) = NetParse.splitHostPort(remote) else { continue }
            if ctx.judge.ip(ip) { continue }
            counter[ip, default: 0] += 1
            if NetParse.suspiciousPorts.contains(port) { susp.append("\(ip):\(port) by \(c.proc)") }
        }
        if susp.isEmpty {
            out.append(ctx.finding("net.suspiciousconn", .pass, "无到高危端口的公网连接。", "ESTABLISHED scanned, 0 suspicious port"))
        } else {
            out.append(ctx.finding("net.suspiciousconn", .fail, "发现到高危端口(22/23/445/3389/5900/4444…)的公网连接。",
                                   Fmt.evidence(susp.prefix(5).joined(separator: "\n"))))
        }

        let hot = counter.filter { $0.value >= ctx.judge.w.highFreqThreshold }
        if hot.isEmpty {
            out.append(ctx.finding("net.highfreq", .pass, "无单一公网 IP 的高频连接。", "threshold=\(ctx.judge.w.highFreqThreshold), 0 hit"))
        } else {
            out.append(ctx.finding("net.highfreq", .fail, "单一公网 IP 连接数超阈值,疑似 C2/数据外传。",
                                   Fmt.evidence(hot.map { "\($0.key) ×\($0.value)" }.joined(separator: "\n"))))
        }
        return out
    }
}

// MARK: - 6 账户

public struct AccountDetector: Detector {
    public let id = "account"; public let title = "账户安全"
    public init() {}
    public func detect(ctx: DetectContext) async -> [Finding] {
        var out: [Finding] = []
        let pwd = await ctx.pr.run("/usr/bin/dscl", [".", "-read", "/Users/root", "Password"])
        let pw = pwd.stdout.trimmingCharacters(in: .whitespacesAndNewlines)
        // macOS 禁用 root 时 Password 记录为 "*";启用后为 ShadowHash 或空
        if pw.hasSuffix("*") || pw.isEmpty {
            out.append(ctx.finding("acct.root", .pass, "root 账户处于禁用状态(Password=*)。", Fmt.evidence(pw.isEmpty ? "Password=(缺省)" : pw)))
        } else {
            out.append(ctx.finding("acct.root", .fail, "root 账户疑似已启用(Password 非 *)。", Fmt.evidence(pw)))
        }

        let guest = await ctx.pr.run("/usr/bin/defaults", ["read", "/Library/Preferences/com.apple.loginwindow", "GuestEnabled"])
        let gv = guest.stdout.trimmingCharacters(in: .whitespacesAndNewlines)
        if gv == "1" {
            out.append(ctx.finding("acct.guest", .fail, "访客账户开启,允许无密码进入会话。", "GuestEnabled=1"))
        } else {
            out.append(ctx.finding("acct.guest", .pass, "访客账户关闭。", "GuestEnabled=\(gv.isEmpty ? "0(缺省)" : gv)"))
        }

        let admin = await ctx.pr.run("/usr/bin/dscl", [".", "-read", "/Groups/admin", "GroupMembership"])
        let members = admin.stdout.split(whereSeparator: { $0 == " " || $0 == "\n" }).map(String.init)
            .filter { !$0.isEmpty && $0 != "GroupMembership:" }
        if members.count > 2 {
            out.append(ctx.finding("acct.admins", .fail, "管理员账户 \(members.count) 个,扩大凭据失陷影响面。", Fmt.evidence(members.joined(separator: " "))))
        } else {
            out.append(ctx.finding("acct.admins", .pass, "管理员数量合理(\(members.count))。", Fmt.evidence(members.joined(separator: " "))))
        }
        return out
    }
}

// MARK: - 注册表(设计 §5 双类型注册表之快照侧)

public struct DetectorRegistry: Sendable {
    public let snapshot: [Detector]
    public init() {
        snapshot = [SystemConfigDetector(), PrivacyPermissionDetector(), PersistenceDetector(),
                    FileIntegrityDetector(), NetworkDetector(), AccountDetector()]
    }
}
