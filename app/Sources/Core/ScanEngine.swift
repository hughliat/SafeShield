import Foundation

// MARK: - 体检调度:并发 + 单项超时隔离 + 协作式取消(设计 V3)

public enum ScanEngine {
    public static let perDetectorTimeout: TimeInterval = 25

    @discardableResult
    public static func withTimeout<T: Sendable>(_ secs: TimeInterval,
                                                _ op: @escaping @Sendable () async -> T) async -> T? {
        await withTaskGroup(of: T?.self) { g in
            g.addTask { await op() }
            g.addTask {
                try? await Task.sleep(nanoseconds: UInt64(secs * 1_000_000_000))
                return nil
            }
            let first = await g.next() ?? nil
            g.cancelAll()
            return first
        }
    }

    public static func scan(registry: DetectorRegistry, rules: RuleSet, judge: WhitelistJudge,
                            progress: @escaping @Sendable (String, Bool) -> Void) async -> ScanReport {
        let started = Date()
        let pr = ProcessRunner.shared
        let ctx = DetectContext(rules: rules, judge: judge, pr: pr)
        var findings: [Finding] = []

        findings = await withTaskGroup(of: [Finding].self) { group in
            for d in registry.snapshot {
                group.addTask {
                    if Task.isCancelled { return [] }
                    let res = await withTimeout(perDetectorTimeout) { await d.detect(ctx: ctx) }
                    progress(d.title, res != nil)
                    return res ?? []
                }
            }
            var acc: [Finding] = []
            for await chunk in group { acc.append(contentsOf: chunk) }
            return acc
        }

        // 规则顺序稳定输出,保证同状态重复体检结果一致(可复现)
        let orderIndex: [String: Int] = Dictionary(uniqueKeysWithValues: rules.order.enumerated().map { ($1, $0) })
        findings.sort { (orderIndex[$0.id] ?? 999) < (orderIndex[$1.id] ?? 999) }

        let score = RuleEngine.score(findings)
        return ScanReport(id: UUID().uuidString, startedAt: started, finishedAt: Date(),
                          score: score, grade: RuleEngine.grade(score),
                          ruleSetVersion: rules.version, findings: findings,
                          dimensionScores: RuleEngine.dimensionScores(findings))
    }
}
