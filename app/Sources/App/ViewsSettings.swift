import SwiftUI
import AppKit

// MARK: - 设置:姿态 / 守护 / 白名单 / 隐私中心

struct SettingsView: View {
    @EnvironmentObject var state: AppState
    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 20) {
                postureSection
                guardianSection
                whitelistSection
                privacySection
                aboutSection
            }
            .padding(24)
        }
    }

    private var postureSection: some View {
        card("处置姿态") {
            Picker("", selection: $state.settings.posture) {
                ForEach(ResponsePosture.allCases, id: \.self) { p in Text(p.rawValue).tag(p) }
            }
            .pickerStyle(.radioGroup)
            .labelsHidden()
            Text(state.settings.posture.note).font(.caption).foregroundColor(.secondary)
            Text("合规红线:任何姿态下,终止进程等不可逆动作都必须逐项确认;只读姿态不执行任何处置。")
                .font(.caption2).foregroundColor(.secondary)
        }
    }

    private var guardianSection: some View {
        card("守护模式") {
            Toggle("开机后手动启动守护(常驻特权助手未安装前不提供自启)", isOn: .constant(false))
                .disabled(true)
            Stepper("轮询间隔:\(state.settings.intervalSec)s", value: Binding(
                get: { state.settings.intervalSec },
                set: { state.applyGuardianInterval($0) }), in: 15...600, step: 15)
            Toggle("高危事件发送系统通知(经 osascript,默认关闭)", isOn: $state.settings.notifyEnabled)
        }
    }

    private var whitelistSection: some View {
        card("白名单(通用规则随产品发布,此处修改仅存本机)") {
            Text("进程关键字").font(.caption).foregroundColor(.secondary)
            editor(Binding(get: { state.settings.whitelists.processes.joined(separator: ", ") },
                           set: { state.settings.whitelists.processes = split($0) }))
            Text("端口").font(.caption).foregroundColor(.secondary)
            editor(Binding(get: { state.settings.whitelists.ports.map(String.init).joined(separator: ", ") },
                           set: { state.settings.whitelists.ports = split($0).compactMap(Int.init) }))
            Text("启动项标签前缀").font(.caption).foregroundColor(.secondary)
            editor(Binding(get: { state.settings.whitelists.launchPrefixes.joined(separator: ", ") },
                           set: { state.settings.whitelists.launchPrefixes = split($0) }))
            Text("可疑关键字(守护命中即告警)").font(.caption).foregroundColor(.secondary)
            editor(Binding(get: { state.settings.whitelists.suspiciousKeywords.joined(separator: ", ") },
                           set: { state.settings.whitelists.suspiciousKeywords = split($0) }))
            Text("提示:企业合规安全软件等本机既有进程,请加入进程白名单以避免误报;该清单不会随产品分发。")
                .font(.caption2).foregroundColor(.secondary)
        }
    }

    private var privacySection: some View {
        card("隐私中心") {
            VStack(alignment: .leading, spacing: 6) {
                Text("数据目录(全部留在本机,不外发):").font(.caption).foregroundColor(.secondary)
                Text(SSPaths.supportDir.path).font(.system(size: 11, design: .monospaced)).textSelection(.enabled)
                Text("不读取、不上传任何文件内容明文与口令明文;文件完整性仅计算并保存 SHA256 哈希。")
                    .font(.caption2).foregroundColor(.secondary)
                HStack(spacing: 10) {
                    Button("打开数据目录") { NSWorkspace.shared.open(SSPaths.supportDir) }.controlSize(.small)
                    Button("清空事件日志", role: .destructive) {
                        try? FileManager.default.removeItem(at: SSPaths.eventsURL)
                        state.guardian.resetBaseline()
                    }.controlSize(.small)
                    Button("清空审计日志", role: .destructive) {
                        try? FileManager.default.removeItem(at: SSPaths.auditURL)
                    }.controlSize(.small)
                }
            }
        }
    }

    private var aboutSection: some View {
        card("关于") {
            VStack(alignment: .leading, spacing: 4) {
                Text("安全盾 SafeShield · 直接分发渠道构建").font(.callout.weight(.semibold))
                Text("规则集 \(state.rules.version)(\(state.rules.asOf)) · 已知最新 macOS 大版本 \(state.rules.knownLatestOSMajor)")
                    .font(.caption).foregroundColor(.secondary)
                Text("授权同意时间:" + (state.settings.consentAt.map(Fmt.full) ?? "未记录"))
                    .font(.caption).foregroundColor(.secondary)
                Button("重新查看引导") { state.showOnboarding = true }.controlSize(.small)
            }
        }
    }

    private func card<Content: View>(_ title: String, @ViewBuilder _ content: () -> Content) -> some View {
        VStack(alignment: .leading, spacing: 10) {
            Text(title).font(.headline)
            VStack(alignment: .leading, spacing: 8) { content() }
        }
        .padding(16)
        .frame(maxWidth: .infinity, alignment: .leading)
        .background(RoundedRectangle(cornerRadius: 12).fill(Color.gray.opacity(0.06)))
    }

    private func editor(_ text: Binding<String>) -> some View {
        TextField("", text: text, axis: .vertical)
            .textFieldStyle(.roundedBorder)
            .font(.system(size: 11, design: .monospaced))
            .lineLimit(2...4)
    }

    private func split(_ s: String) -> [String] {
        s.split(whereSeparator: { $0 == "," || $0 == "，" || $0 == "\n" })
         .map { $0.trimmingCharacters(in: .whitespaces) }.filter { !$0.isEmpty }
    }
}
