import SwiftUI
import AppKit

// MARK: - 守护中心:事件时间线 + 审计 + 隔离区

struct GuardianView: View {
    @EnvironmentObject var state: AppState
    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 18) {
                header
                section("事件时间线") {
                    if state.guardian.events.isEmpty {
                        Text("暂无事件。守护启动后先建立基线(首轮不告警),随后每轮差分产生事件。")
                            .font(.callout).foregroundColor(.secondary)
                    } else {
                        ForEach(state.guardian.events) { e in EventRowView(event: e) }
                    }
                }
                section("审计日志(全量留痕)") {
                    if state.coordinator.audit.isEmpty {
                        Text("暂无处置记录。").font(.callout).foregroundColor(.secondary)
                    } else {
                        ForEach(state.coordinator.audit.prefix(30)) { r in AuditRowView(record: r) }
                    }
                }
                section("隔离区(可回滚)") {
                    if state.coordinator.quarantine.isEmpty {
                        Text("隔离区为空。").font(.callout).foregroundColor(.secondary)
                    } else {
                        ForEach(state.coordinator.quarantine, id: \.id) { q in
                            HStack {
                                VStack(alignment: .leading, spacing: 2) {
                                    Text(q.originalPath).font(.caption).textSelection(.enabled)
                                    Text("隔离于 \(Fmt.full(q.time))").font(.caption2).foregroundColor(.secondary)
                                }
                                Spacer()
                                Button("还原") { state.requestAction(.restoreFile, target: q.id, reason: "还原隔离文件 \(q.originalPath)") }
                                    .controlSize(.small)
                            }
                            .padding(8)
                            .background(RoundedRectangle(cornerRadius: 8).fill(Color.gray.opacity(0.05)))
                        }
                    }
                }
            }
            .padding(24)
        }
    }

    private var header: some View {
        HStack(spacing: 14) {
            Image(systemName: "shield.lefthalf.filled")
                .font(.title2).foregroundColor(state.guardian.running ? .green : .secondary)
            VStack(alignment: .leading, spacing: 3) {
                Text("守护中心").font(.title2.bold())
                Text(state.guardian.running
                     ? "运行中 · 第 \(state.guardian.tickCount) 轮 · 上次差分 \(state.guardian.lastTick.map(Fmt.full) ?? "-")"
                     : "已停止 · 基线保留于本机,可随时继续")
                    .font(.caption).foregroundColor(.secondary)
            }
            Spacer()
            Stepper("间隔 \(state.settings.intervalSec)s", value: Binding(
                get: { state.settings.intervalSec },
                set: { state.applyGuardianInterval($0) }), in: 15...600, step: 15)
                .controlSize(.small).fixedSize()
            Button(state.guardian.running ? "停止守护" : "启动守护") { state.toggleGuardian() }
                .controlSize(.large)
                .tint(state.guardian.running ? .orange : .green)
            Button("重置基线") { state.guardian.resetBaseline() }
                .controlSize(.small)
        }
    }

    private func section<Content: View>(_ title: String, @ViewBuilder _ content: () -> Content) -> some View {
        VStack(alignment: .leading, spacing: 10) {
            Text(title).font(.headline)
            VStack(alignment: .leading, spacing: 8) { content() }
        }
    }
}

struct AuditRowView: View {
    @EnvironmentObject var state: AppState
    let record: AuditRecord
    var body: some View {
        HStack(alignment: .top, spacing: 10) {
            Image(systemName: record.result.hasPrefix("executed") ? "checkmark.seal"
                  : (record.result.hasPrefix("blocked") ? "hand.raised" : "clock"))
                .foregroundColor(record.result.hasPrefix("executed") ? .green : .secondary)
                .frame(width: 18)
            VStack(alignment: .leading, spacing: 2) {
                HStack(spacing: 6) {
                    Text(ActionType(rawValue: record.actionType)?.label ?? record.actionType).font(.callout.weight(.semibold))
                    Text(record.result).font(.caption2).foregroundColor(.secondary)
                    Spacer()
                    Text(Fmt.full(record.time)).font(.caption2).foregroundColor(.secondary)
                }
                Text("目标:\(record.target)").font(.caption).foregroundColor(.secondary).textSelection(.enabled).lineLimit(1)
                Text("原因:\(record.reason) · 姿态:\(record.posture)").font(.caption2).foregroundColor(.secondary).lineLimit(1)
            }
            if record.actionType == ActionType.quarantineFile.rawValue && record.result.hasPrefix("executed") && record.rolledBackAt == nil {
                Button("回滚") { state.rollback(record.id) }.controlSize(.small)
            }
        }
        .padding(10)
        .background(RoundedRectangle(cornerRadius: 8).fill(Color.gray.opacity(0.05)))
    }
}
