import Foundation

// MARK: - 连续检测器(守护模式,移植自 monitor.py 的差分语义;设计 §5)

public protocol ContinuousDetector: Sendable {
    var id: String { get }
    var title: String { get }
    /// firstRun=true 时只建立基线,不产生告警(避免首跑洪水)
    func observe(ctx: DetectContext, base: inout Baseline, firstRun: Bool) async -> [SecurityEvent]
}

/// 去重键:同类同目标只告警一次,直到基线重置
func dedup(_ base: inout Baseline, _ key: String) -> Bool {
    if base.seenEventKeys.contains(key) { return true }
    base.seenEventKeys.append(key)
    return false
}

// MARK: 1 可疑进程(关键字 + 临时目录执行)

public struct ProcessWatch: ContinuousDetector {
    public let id = "processWatch"; public let title = "进程行为"
    public init() {}
    public func observe(ctx: DetectContext, base: inout Baseline, firstRun: Bool) async -> [SecurityEvent] {
        let ps = await ctx.pr.run("/bin/ps", ["aux"])
        var events: [SecurityEvent] = []
        for line in ps.stdout.split(separator: "\n").dropFirst() {
            let parts = line.split(omittingEmptySubsequences: true, whereSeparator: { $0 == " " }).map(String.init)
            guard parts.count >= 11 else { continue }
            let pid = parts[1]; let cmd = parts[10...].joined(separator: " ")
            if ctx.judge.process(cmd) { continue }
            if let kw = ctx.judge.keyword(cmd) {
                if base.handledPids.contains(pid) { continue }
                base.handledPids.append(pid)
                if firstRun { continue }
                events.append(SecurityEvent(kind: .suspiciousProcess, severity: .high,
                                            title: "可疑进程命中规则 \(kw)",
                                            detail: String(cmd.prefix(160)), target: pid,
                                            suggestedAction: "killProcess"))
            } else if !firstRun {
                for tp in ["/tmp/", "/private/tmp/", "/var/folders/"] {
                    if cmd.contains(tp) && !cmd.lowercased().contains("python") && !cmd.lowercased().contains("node") {
                        let key = "temp:\(pid)"
                        if dedup(&base, key) { break }
                        events.append(SecurityEvent(kind: .tempExecution, severity: .medium,
                                                    title: "临时目录中的可执行运行",
                                                    detail: String(cmd.prefix(160)), target: pid,
                                                    suggestedAction: "killProcess"))
                        break
                    }
                }
            }
        }
        return events
    }
}

// MARK: 2 新增监听端口

public struct PortWatch: ContinuousDetector {
    public let id = "portWatch"; public let title = "监听端口"
    public init() {}
    public func observe(ctx: DetectContext, base: inout Baseline, firstRun: Bool) async -> [SecurityEvent] {
        let out = await ctx.pr.run("/usr/sbin/lsof", ["-nP", "-iTCP", "-sTCP:LISTEN"])
        var current: [Int] = []
        var meta: [Int: (String, String, String)] = [:]
        for c in NetParse.parse(out.stdout) {
            guard let (host, port) = NetParse.splitHostPort(c.name), port > 0 else { continue }
            current.append(port)
            meta[port] = (c.proc, c.pid, host)
        }
        var events: [SecurityEvent] = []
        if !firstRun {
            let known = Set(base.ports)
            for p in Set(current) where !known.contains(p) && !ctx.judge.port(p) {
                let m = meta[p] ?? ("?", "?", "?")
                let procWhitelisted = ctx.judge.process(m.0)
                let key = "port:\(p)"
                if dedup(&base, key) { continue }
                events.append(SecurityEvent(kind: .newListenPort,
                                            severity: procWhitelisted ? .medium : .high,
                                            title: "新增监听端口 \(p)",
                                            detail: "\(m.0) pid=\(m.1) addr=\(m.2)\(procWhitelisted ? "" : "(进程不在白名单)")",
                                            target: "\(m.2):\(p)"))
            }
        }
        base.ports = Array(Set(current)).sorted()
        return events
    }
}

// MARK: 3 外连(高频 + 高危端口)

public struct ConnectionWatch: ContinuousDetector {
    public let id = "connectionWatch"; public let title = "出站连接"
    public init() {}
    public func observe(ctx: DetectContext, base: inout Baseline, firstRun: Bool) async -> [SecurityEvent] {
        let out = await ctx.pr.run("/usr/sbin/lsof", ["-nP", "-iTCP", "-sTCP:ESTABLISHED"])
        var counter: [String: Int] = [:]
        var suspPorts: [String: Set<Int>] = [:]
        for c in NetParse.parse(out.stdout) {
            guard let arrow = c.name.range(of: "->") else { continue }
            guard let (ip, port) = NetParse.splitHostPort(String(c.name[arrow.upperBound...])) else { continue }
            if ctx.judge.ip(ip) { continue }
            counter[ip, default: 0] += 1
            if NetParse.suspiciousPorts.contains(port) { suspPorts[ip, default: []].insert(port) }
        }
        var events: [SecurityEvent] = []
        guard !firstRun else { return events }
        for (ip, cnt) in counter where cnt >= ctx.judge.w.highFreqThreshold {
            let key = "freq:\(ip)"
            if dedup(&base, key) { continue }
            events.append(SecurityEvent(kind: .highFreqConnection, severity: .high,
                                        title: "高频外连 \(ip) ×\(cnt)",
                                        detail: "单一公网 IP 连接数 ≥ 阈值 \(ctx.judge.w.highFreqThreshold)",
                                        target: ip, suggestedAction: "blockIP"))
        }
        for (ip, ports) in suspPorts where (counter[ip] ?? 0) >= 3 {
            let key = "susp:\(ip)"
            if dedup(&base, key) { continue }
            events.append(SecurityEvent(kind: .suspiciousPortConnection, severity: .high,
                                        title: "到高危端口的公网连接 \(ip)",
                                        detail: "ports: \(ports.sorted().map(String.init).joined(separator: ","))",
                                        target: ip, suggestedAction: "blockIP"))
        }
        return events
    }
}

// MARK: 4 新增启动项

public struct LaunchItemWatch: ContinuousDetector {
    public let id = "launchItemWatch"; public let title = "启动项变化"
    public init() {}
    public func observe(ctx: DetectContext, base: inout Baseline, firstRun: Bool) async -> [SecurityEvent] {
        let fm = FileManager.default
        var current: [String] = []
        var events: [SecurityEvent] = []
        for dir in PersistenceDetector.launchDirs() {
            guard let names = try? fm.contentsOfDirectory(atPath: dir) else { continue }
            for n in names where !n.hasPrefix(".") {
                current.append(n)
                if ctx.judge.launchLabel(n) { continue }
                if base.launchItems.contains(n) { continue }
                if !firstRun {
                    let isDaemon = dir.hasSuffix("LaunchDaemons")
                    let key = "launch:\(n)"
                    if dedup(&base, key) { continue }
                    events.append(SecurityEvent(kind: isDaemon ? .newLaunchDaemon : .newLaunchAgent,
                                                severity: isDaemon ? .high : .medium,
                                                title: "新增 \(isDaemon ? "LaunchDaemon" : "LaunchAgent") \(n)",
                                                detail: dir, target: dir + "/" + n,
                                                suggestedAction: "quarantineFile"))
                }
            }
        }
        base.launchItems = current
        return events
    }
}

// MARK: 5 高危目录文件新增/篡改

public struct WatchPathWatch: ContinuousDetector {
    public let id = "watchPathWatch"; public let title = "高危目录文件"
    public init() {}
    public func observe(ctx: DetectContext, base: inout Baseline, firstRun: Bool) async -> [SecurityEvent] {
        let fm = FileManager.default
        var events: [SecurityEvent] = []
        var seen: [String: String] = [:]
        for basePath in ctx.judge.w.watchPaths {
            guard let names = try? fm.contentsOfDirectory(atPath: basePath) else { continue }
            for n in names.prefix(500) {
                if n.hasPrefix(".") || n.hasPrefix("com.apple") { continue }
                let full = (basePath + "/" + n as NSString).standardizingPath
                var isDir: ObjCBool = false
                guard fm.fileExists(atPath: full, isDirectory: &isDir), !isDir.boolValue else { continue }
                let ext = (n as NSString).pathExtension.lowercased()
                guard ["sh", "py", "pl", "rb", "php", "js", "bash", "command", "", "dylib", "so"].contains(ext) else { continue }
                if ctx.judge.path(full) { continue }
                guard let h = FileHash.sha256(full) else { continue }
                seen[full] = h
                if firstRun { continue }
                if let old = base.fileHashes[full] {
                    if old != h {
                        let key = "chg:\(full):\(h.prefix(8))"
                        if dedup(&base, key) { continue }
                        events.append(SecurityEvent(kind: .fileChanged, severity: .high,
                                                    title: "受监控文件被修改", detail: full,
                                                    target: full, suggestedAction: "quarantineFile"))
                    }
                } else {
                    let risky = ["/private/tmp", "/tmp", "/Users/Shared"].contains { full.hasPrefix($0) }
                    let key = "new:\(full)"
                    if dedup(&base, key) { continue }
                    events.append(SecurityEvent(kind: .newFile, severity: risky ? .medium : .low,
                                                title: "高危目录新增文件", detail: full,
                                                target: full, suggestedAction: "quarantineFile"))
                }
            }
        }
        base.fileHashes = seen
        return events
    }
}

// MARK: 6 新增系统账户

public struct AccountWatch: ContinuousDetector {
    public let id = "accountWatch"; public let title = "系统账户"
    public init() {}
    public func observe(ctx: DetectContext, base: inout Baseline, firstRun: Bool) async -> [SecurityEvent] {
        let out = await ctx.pr.run("/usr/bin/dscl", [".", "-list", "/Users"])
        let users = out.stdout.split(separator: "\n").map(String.init)
            .filter { !$0.hasPrefix("_") && !["daemon", "nobody", "root", "ubuntu"].contains($0) }
        var events: [SecurityEvent] = []
        if !firstRun && !base.users.isEmpty {
            let new = users.filter { !base.users.contains($0) }
            if !new.isEmpty {
                let key = "user:\(new.joined(separator: ","))"
                if !dedup(&base, key) {
                    events.append(SecurityEvent(kind: .newUserAccount, severity: .high,
                                                title: "新增用户账户 \(new.joined(separator: ", "))",
                                                detail: "dscl . -list /Users 差分", target: new.joined(separator: ",")))
                }
            }
        }
        base.users = users
        return events
    }
}

public struct ContinuousRegistry: Sendable {
    public let all: [ContinuousDetector]
    public init() {
        all = [ProcessWatch(), PortWatch(), ConnectionWatch(), LaunchItemWatch(), WatchPathWatch(), AccountWatch()]
    }
}
