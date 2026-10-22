import Foundation

// MARK: - 报告存储(本地 JSON;无 Xcode 环境下以文件存储替代 SwiftData,见交付说明)

public enum ReportStore {
    public static func load() -> [ScanReport] {
        guard let d = try? Data(contentsOf: SSPaths.reportsURL) else { return [] }
        let dec = JSONDecoder(); dec.dateDecodingStrategy = .iso8601
        return (try? dec.decode([ScanReport].self, from: d)) ?? []
    }
    public static func save(_ list: [ScanReport]) {
        var list = list
        if list.count > 50 { list = Array(list.suffix(50)) }
        let enc = JSONEncoder(); enc.dateEncodingStrategy = .iso8601; enc.outputFormatting = [.prettyPrinted]
        try? enc.encode(list).write(to: SSPaths.reportsURL, options: .atomic)
    }
    public static func add(_ r: ScanReport) -> [ScanReport] {
        var list = load(); list.append(r); save(list); return list
    }
}

// MARK: - Markdown 导出(与页面一致,含评分口径版本)

public enum ReportExport {
    public static func markdown(_ r: ScanReport) -> String {
        var s = """
        # 安全盾 SafeShield 体检报告

        - 时间:\(Fmt.full(r.startedAt)) → \(Fmt.full(r.finishedAt))
        - 总分:**\(r.score) / 100(\(r.grade))**
        - 规则集:\(r.ruleSetVersion)
        - 风险 \(r.risks.count) 项 / 通过 \(r.passed.count) 项 / 不计分 \(r.findings.filter { $0.status == .unavailable }.count) 项

        ## 维度得分

        | 维度 | 得分 |
        |---|---|
        """
        for dim in Dimension.allCases {
            let v = r.dimensionScores[dim.rawValue] ?? -1
            s += "\n| \(dim.rawValue) | \(v < 0 ? "—" : "\(v)") |"
        }
        s += "\n\n## 风险项\n"
        if r.risks.isEmpty { s += "\n(无)\n" }
        for f in r.risks {
            s += "\n### [\(f.severity.label)] \(f.name)\n\n- \(f.summary)\n- 证据:`\(f.evidence)`\n"
        }
        s += "\n## 通过项\n"
        for f in r.passed {
            s += "\n- \(f.name):\(f.evidence)\n"
        }
        let un = r.findings.filter { $0.status == .unavailable }
        if !un.isEmpty {
            s += "\n## 不计分项(能力/授权受限)\n"
            for f in un { s += "\n- \(f.name):\(f.summary)\n" }
        }
        s += "\n---\n评分口径:S = 100 × (1 − Σ(w·p_sev)/Σw);unavailable 与 weight=0 不计入。规则集版本 \(r.ruleSetVersion)。\n"
        return s
    }
}
