import Foundation

// MARK: - 守护引擎:轮询循环 + 基线差分 + 事件发布(设计 §6.1)

@MainActor
public final class GuardianEngine: ObservableObject {
    @Published public private(set) var running = false
    @Published public private(set) var lastTick: Date? = nil
    @Published public private(set) var events: [SecurityEvent] = EventLog.tail()
    @Published public private(set) var tickCount = 0

    private var loop: Task<Void, Never>? = nil
    private let registry = ContinuousRegistry()
    public var onEvent: ((SecurityEvent) -> Void)? = nil

    public init() {}

    public func start(intervalSec: Int, rules: RuleSet, judge: WhitelistJudge) {
        guard !running else { return }
        running = true
        let secs = max(15, intervalSec)
        loop = Task { [weak self] in
            var first = BaselineStore.load().establishedAt == nil
            while !Task.isCancelled {
                await self?.tick(firstRun: first, rules: rules, judge: judge)
                first = false
                try? await Task.sleep(nanoseconds: UInt64(secs) * 1_000_000_000)
            }
        }
        publish(SecurityEvent(kind: .guardianStarted, severity: .info,
                              title: "守护已启动", detail: "轮询间隔 \(secs)s,六类差分检测", target: "-"))
    }

    public func stop() {
        loop?.cancel(); loop = nil
        running = false
        publish(SecurityEvent(kind: .guardianStopped, severity: .info,
                              title: "守护已停止", detail: "基线保留,下次启动继续差分", target: "-"))
    }

    public func resetBaseline() {
        BaselineStore.reset()
        events = []
        try? FileManager.default.removeItem(at: SSPaths.eventsURL)
    }

    private func tick(firstRun: Bool, rules: RuleSet, judge: WhitelistJudge) async {
        var base = BaselineStore.load()
        let ctx = DetectContext(rules: rules, judge: judge, pr: ProcessRunner.shared)
        var collected: [SecurityEvent] = []
        for d in registry.all {
            let snapshot = base
            let res = await ScanEngine.withTimeout(ScanEngine.perDetectorTimeout) {
                var b = snapshot
                let evs = await d.observe(ctx: ctx, base: &b, firstRun: firstRun)
                return (evs, b)
            }
            if let res {
                collected.append(contentsOf: res.0)
                base = res.1
            }
        }
        base.tickCount += 1
        base.establishedAt = Date()
        BaselineStore.save(base)

        for e in collected { publish(e) }
        lastTick = Date()
        tickCount = base.tickCount
    }

    private func publish(_ e: SecurityEvent) {
        EventLog.append(e)
        events.insert(e, at: 0)
        if events.count > 300 { events = Array(events.prefix(300)) }
        onEvent?(e)
    }
}

// MARK: - 可选系统通知(默认关闭;经 osascript,文本转义防注入)

public enum Notify {
    static func escape(_ s: String) -> String {
        s.replacingOccurrences(of: "\\", with: "\\\\")
         .replacingOccurrences(of: "\"", with: "\\\"")
         .replacingOccurrences(of: "\n", with: " ")
         .replacingOccurrences(of: "\r", with: " ")
    }
    public static func send(_ e: SecurityEvent) async {
        let icon = ["critical": "🔴", "high": "🟠", "medium": "🟡", "low": "🔵", "info": "ℹ️"][e.severity.rawValue] ?? "ℹ️"
        let script = "display notification \"\(escape(e.detail.prefix(180).description))\" with title \"\(escape(icon + " " + e.title))\" sound name \"Breeze\""
        _ = await ProcessRunner.shared.run("/usr/bin/osascript", ["-e", script], timeout: 5)
    }
}
