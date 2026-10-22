import Foundation

/// 白名单只读命令执行器(设计 §9.1)。
/// - 仅允许白名单内绝对路径;`Process.executableURL` 不做 PATH 解析,必须写真实路径。
/// - 直调 exec,不经过 shell;参数为固定数组,拒绝含 `;` `|` `&` `` ` `` `$(` 的参数。
public actor ProcessRunner {
    public static let shared = ProcessRunner()

    public static let allowed: Set<String> = [
        // 体检(系统配置)
        "/usr/bin/csrutil", "/usr/bin/fdesetup", "/usr/sbin/spctl",
        "/usr/libexec/ApplicationFirewall/socketfilterfw",
        "/usr/bin/defaults", "/usr/bin/sw_vers",
        // 守护(进程/网络/账户/驻留)
        "/bin/ps", "/usr/sbin/lsof", "/usr/bin/netstat", "/usr/bin/dscl",
        "/usr/bin/crontab", "/bin/launchctl",
        // 通知(可选,默认关闭;字符串经转义,见 Notify)
        "/usr/bin/osascript"
    ]

    public enum InfraError: Error, CustomStringConvertible {
        case notWhitelisted(String)
        case invalidArgument(String)
        public var description: String {
            switch self {
            case .notWhitelisted(let t): return "命令不在白名单: \(t)"
            case .invalidArgument(let a): return "参数被拒绝: \(a)"
            }
        }
    }

    private static let forbidden: [String] = [";", "|", "&", "`", "$(", ">", "<", "\n"]

    public func run(_ tool: String, _ args: [String], timeout: TimeInterval = 10) async -> CommandOutput {
        guard Self.allowed.contains(tool) else {
            return CommandOutput(tool: tool, exitCode: 126, stdout: "", stderr: InfraError.notWhitelisted(tool).description)
        }
        for a in args where Self.forbidden.contains(where: { a.contains($0) }) {
            return CommandOutput(tool: tool, exitCode: 126, stdout: "", stderr: InfraError.invalidArgument(a).description)
        }
        let p = Process()
        p.executableURL = URL(fileURLWithPath: tool)
        p.arguments = args
        // 经典陷阱:阻塞式 readDataToEndOfFile / waitUntilExit 会与满管道互锁。
        // 改为 readabilityHandler 异步排空 + 轮询 isRunning,超时 terminate,绝不死等。
        final class Buf: @unchecked Sendable {
            private let lock = NSLock(); private var data = Data()
            func append(_ d: Data) { lock.lock(); data.append(d); lock.unlock() }
            var value: Data { lock.lock(); defer { lock.unlock() }; return data }
        }
        let outBuf = Buf(); let errBuf = Buf()
        let outPipe = Pipe(); let errPipe = Pipe()
        outPipe.fileHandleForReading.readabilityHandler = { h in
            let d = h.availableData
            if !d.isEmpty { outBuf.append(d) }
        }
        errPipe.fileHandleForReading.readabilityHandler = { h in
            let d = h.availableData
            if !d.isEmpty { errBuf.append(d) }
        }
        p.standardOutput = outPipe; p.standardError = errPipe
        do {
            try p.run()
        } catch {
            return CommandOutput(tool: tool, exitCode: 127, stdout: "", stderr: error.localizedDescription)
        }
        let deadline = Date().addingTimeInterval(timeout)
        while p.isRunning && Date() < deadline {
            try? await Task.sleep(nanoseconds: 50_000_000)
        }
        if p.isRunning {
            p.terminate()
            try? await Task.sleep(nanoseconds: 150_000_000)
            outPipe.fileHandleForReading.readabilityHandler = nil
            errPipe.fileHandleForReading.readabilityHandler = nil
            return CommandOutput(tool: tool, exitCode: 124, stdout: "", stderr: "command timeout")
        }
        // 子进程已退出:给 handler 一点排空余量后摘除
        try? await Task.sleep(nanoseconds: 100_000_000)
        outPipe.fileHandleForReading.readabilityHandler = nil
        errPipe.fileHandleForReading.readabilityHandler = nil
        let so = String(data: outBuf.value, encoding: .utf8) ?? ""
        let se = String(data: errBuf.value, encoding: .utf8) ?? ""
        return CommandOutput(tool: tool, exitCode: p.terminationStatus, stdout: so, stderr: se)
    }
}
