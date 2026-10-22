import Foundation

// MARK: - 规则集(外置 JSON,设计 §7 / V4)

public struct Rule: Codable, Sendable {
    public let id: String
    public let name: String
    public let dimension: Dimension
    public let weight: Double
    public let failSeverity: Severity
    public let desc: String
    public let remediationKind: String
    public let remediationTarget: String?
    public let actionType: String?

    enum CodingKeys: String, CodingKey {
        case id, name, dimension, weight, failSeverity, desc, remediation
    }
    private struct Rem: Codable { let kind: String; let text: String?; let target: String?; let action: String? }

    public init(from decoder: Decoder) throws {
        let c = try decoder.container(keyedBy: CodingKeys.self)
        id = try c.decode(String.self, forKey: .id)
        name = try c.decode(String.self, forKey: .name)
        dimension = try c.decode(Dimension.self, forKey: .dimension)
        weight = try c.decodeIfPresent(Double.self, forKey: .weight) ?? 1.0
        failSeverity = try c.decode(Severity.self, forKey: .failSeverity)
        desc = try c.decode(String.self, forKey: .desc)
        let rem = try c.decodeIfPresent(Rem.self, forKey: .remediation)
        remediationKind = rem?.kind ?? "guide"
        remediationTarget = rem?.target ?? rem?.text
        actionType = rem?.action
    }
    public func encode(to encoder: Encoder) throws {
        var c = encoder.container(keyedBy: CodingKeys.self)
        try c.encode(id, forKey: .id); try c.encode(name, forKey: .name)
        try c.encode(dimension, forKey: .dimension); try c.encode(weight, forKey: .weight)
        try c.encode(failSeverity, forKey: .failSeverity); try c.encode(desc, forKey: .desc)
    }
}

public struct RuleSet: Sendable {
    public let version: String
    public let asOf: String
    public let knownLatestOSMajor: Int
    public let rules: [String: Rule]
    public let order: [String]

    public static let fallback = RuleSet(version: "v1-fallback", asOf: "builtin", knownLatestOSMajor: 27,
                                         rules: [:], order: [])

    public static func load() -> RuleSet {
        let candidates: [URL] = {
            var u: [URL] = []
            if let r = Bundle.main.resourceURL { u.append(r.appendingPathComponent("rules.default.json")) }
            u.append(URL(fileURLWithPath: FileManager.default.currentDirectoryPath)
                .appendingPathComponent("Resources/rules.default.json"))
            return u
        }()
        for url in candidates {
            if let data = try? Data(contentsOf: url),
               let rs = try? JSONDecoder().decode(RuleFile.self, from: data) {
                var dict: [String: Rule] = [:]
                for r in rs.checks { dict[r.id] = r }
                return RuleSet(version: rs.ruleSetVersion, asOf: rs.asOf,
                               knownLatestOSMajor: rs.knownLatestOSMajor,
                               rules: dict, order: rs.checks.map(\.id))
            }
        }
        return .fallback
    }

    private struct RuleFile: Codable {
        let ruleSetVersion: String
        let asOf: String
        let knownLatestOSMajor: Int
        let checks: [Rule]
    }
}

// MARK: - 评分引擎:S = 100 × (1 − Σ(w·p_sev) / Σw),unavailable 与 weight=0 不计入

public enum RuleEngine {
    public static func score(_ findings: [Finding]) -> Int {
        let pool = findings.filter(\.countsInScore)
        guard !pool.isEmpty else { return 100 }
        let totalW = pool.reduce(0.0) { $0 + $1.weight }
        let sumP = pool.reduce(0.0) { $0 + ($1.status == .fail ? $1.weight * $1.severity.penalty : 0) }
        guard totalW > 0 else { return 100 }
        return Int((100.0 * (1.0 - sumP / totalW)).rounded())
    }

    public static func dimensionScores(_ findings: [Finding]) -> [String: Int] {
        var out: [String: Int] = [:]
        for dim in Dimension.allCases {
            let sub = findings.filter { $0.dimension == dim }
            out[dim.rawValue] = sub.isEmpty ? -1 : score(sub)   // -1 = 该维度无计分项
        }
        return out
    }

    public static func grade(_ s: Int) -> String {
        switch s {
        case 90...: return "优秀"
        case 75...: return "良好"
        case 60...: return "一般"
        case 40...: return "偏弱"
        default: return "危险"
        }
    }
}
