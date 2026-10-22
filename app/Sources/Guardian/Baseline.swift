import Foundation
import CryptoKit

// MARK: - 基线(设计 §4.2)+ 基线存储(§9.1c)

public struct Baseline: Codable, Sendable {
    public var ports: [Int] = []
    public var launchItems: [String] = []
    public var fileHashes: [String: String] = [:]
    public var users: [String] = []
    public var handledPids: [String] = []
    public var seenEventKeys: [String] = []
    public var establishedAt: Date? = nil
    public var tickCount: Int = 0

    public init() {}
}

public enum BaselineStore {
    public static func load() -> Baseline {
        if let data = try? Data(contentsOf: SSPaths.baselineURL),
           let b = try? JSONDecoder().decode(Baseline.self, from: data) { return b }
        return Baseline()
    }
    public static func save(_ b: Baseline) {
        var b = b
        // 修剪,防无限增长(对应 monitor.py prune_state)
        if b.handledPids.count > 200 { b.handledPids = Array(b.handledPids.suffix(200)) }
        if b.seenEventKeys.count > 500 { b.seenEventKeys = Array(b.seenEventKeys.suffix(500)) }
        let fm = FileManager.default
        b.fileHashes = b.fileHashes.filter { fm.fileExists(atPath: $0.key) }
        let enc = JSONEncoder(); enc.outputFormatting = [.sortedKeys]
        try? enc.encode(b).write(to: SSPaths.baselineURL, options: .atomic)
    }
    public static func reset() {
        try? FileManager.default.removeItem(at: SSPaths.baselineURL)
    }
}

// MARK: - 事件日志(JSONL,追加写,UI 读尾部)

public enum EventLog {
    public static func append(_ e: SecurityEvent) {
        let enc = JSONEncoder(); enc.dateEncodingStrategy = .iso8601
        guard let data = try? enc.encode(e) else { return }
        if let line = String(data: data, encoding: .utf8) {
            if let h = FileHandle(forWritingAtPath: SSPaths.eventsURL.path) {
                h.seekToEndOfFile()
                h.write((line + "\n").data(using: .utf8)!)
                try? h.close()
            } else {
                FileManager.default.createFile(atPath: SSPaths.eventsURL.path, contents: (line + "\n").data(using: .utf8))
            }
        }
    }
    public static func tail(_ n: Int = 200) -> [SecurityEvent] {
        guard let s = try? String(contentsOf: SSPaths.eventsURL, encoding: .utf8) else { return [] }
        let dec = JSONDecoder(); dec.dateDecodingStrategy = .iso8601
        let lines = s.split(separator: "\n").suffix(n)
        var out: [SecurityEvent] = []
        for l in lines {
            if let e = try? dec.decode(SecurityEvent.self, from: Data(l.utf8)) { out.append(e) }
        }
        return out.reversed()
    }
}

// MARK: - 文件哈希(进程内计算,不读取内容外发)

public enum FileHash {
    public static func sha256(_ path: String, cap: Int = 5 * 1024 * 1024) -> String? {
        guard let h = FileHandle(forReadingAtPath: path) else { return nil }
        defer { try? h.close() }
        var hasher = SHA256()
        var total = 0
        while total < cap {
            let data = h.readData(ofLength: 65536)
            if data.isEmpty { break }
            hasher.update(data: data)
            total += data.count
        }
        return hasher.finalize().map { String(format: "%02x", $0) }.joined()
    }
}
