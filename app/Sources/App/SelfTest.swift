import Foundation

// MARK: - 处置链路自检(仅 --selftest 启动参数触发;真实执行隔离/回滚/策略门控)

@MainActor
enum SelfTest {
    struct Check: Codable { let name: String; let pass: Bool; let detail: String }

    static func run(_ state: AppState) async -> [Check] {
        var out: [Check] = []
        let judge = state.judge
        let fm = FileManager.default
        let dir = "/tmp/ss-selftest"
        try? fm.createDirectory(atPath: dir, withIntermediateDirectories: true)
        let probe = dir + "/probe.sh"
        fm.createFile(atPath: probe, contents: Data("#!/bin/sh\necho probe\n".utf8))
        try? fm.setAttributes([.posixPermissions: 0o755], ofItemAtPath: probe)

        // 1 隔离(可回滚处置)真实执行
        let a1 = SecurityAction(type: .quarantineFile, target: probe, reason: "selftest: 隔离")
        let r1 = await state.coordinator.execute(a1, posture: .confirm, judge: judge, confirmed: true)
        out.append(Check(name: "隔离执行", pass: r1.result.hasPrefix("executed") && !fm.fileExists(atPath: probe),
                         detail: r1.result))
        // 2 回滚还原
        let rb = await state.coordinator.rollback(a1.id)
        out.append(Check(name: "隔离回滚", pass: rb != nil && fm.fileExists(atPath: probe),
                         detail: rb?.result ?? "nil"))
        // 3 白名单进程拒绝终止
        let a2 = SecurityAction(type: .killProcess, target: "Finder", reason: "selftest: 白名单门控")
        let r2 = await state.coordinator.execute(a2, posture: .confirm, judge: judge, confirmed: true)
        out.append(Check(name: "白名单拒绝 kill", pass: r2.result.hasPrefix("blocked"), detail: r2.result))
        // 4 特权动作在无助手渠道不执行
        let a3 = SecurityAction(type: .blockIP, target: "8.8.8.8", reason: "selftest: 特权门控")
        let r3 = await state.coordinator.execute(a3, posture: .confirm, judge: judge, confirmed: true)
        out.append(Check(name: "blockIP 需特权助手", pass: r3.result.hasPrefix("blocked") && r3.result.contains("特权助手"),
                         detail: r3.result))
        // 5 只读姿态不处置
        let probe2 = dir + "/probe2.sh"
        fm.createFile(atPath: probe2, contents: Data("x".utf8))
        let a4 = SecurityAction(type: .quarantineFile, target: probe2, reason: "selftest: 只读姿态")
        let r4 = await state.coordinator.execute(a4, posture: .readOnly, judge: judge, confirmed: true)
        out.append(Check(name: "只读姿态阻断", pass: r4.result.hasPrefix("blocked") && fm.fileExists(atPath: probe2),
                         detail: r4.result))
        // 6 不可逆动作必须二次确认
        let d = ActionPolicy.decide(SecurityAction(type: .killProcess, target: "99999", reason: "selftest"),
                                    posture: .confirm, judge: judge)
        out.append(Check(name: "kill 需二次确认", pass: d.allowed && d.needsConfirm && d.needsSecondConfirm,
                         detail: "allowed=\(d.allowed) confirm=\(d.needsConfirm) second=\(d.needsSecondConfirm)"))
        // 7 未确认不执行
        let a5 = SecurityAction(type: .quarantineFile, target: probe2, reason: "selftest: 未确认")
        let r5 = await state.coordinator.execute(a5, posture: .confirm, judge: judge, confirmed: false)
        out.append(Check(name: "未确认不执行", pass: r5.result.contains("awaiting confirm") && fm.fileExists(atPath: probe2),
                         detail: r5.result))

        try? fm.removeItem(atPath: dir)
        let enc = JSONEncoder(); enc.outputFormatting = [.prettyPrinted]
        if let data = try? enc.encode(out) {
            try? data.write(to: SSPaths.supportDir.appendingPathComponent("selftest.json"))
        }
        return out
    }
}
