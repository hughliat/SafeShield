import SwiftUI

// MARK: - 仪表盘

struct DashboardView: View {
    @EnvironmentObject var state: AppState
    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 20) {
                header
                dimensionRow
                guardianCard
                recentEvents
            }
            .padding(24)
        }
    }

    private var header: some View {
        HStack(alignment: .center, spacing: 24) {
            if let r = state.report {
                ScoreRing(score: r.score)
                VStack(alignment: .leading, spacing: 6) {
                    Text("安全盾 SafeShield").font(.largeTitle.bold())
                    Text("体检 + 守护 双引擎 · 默认只读 · 处置需确认").foregroundColor(.secondary)
                    Text("最近体检:\(Fmt.full(r.startedAt)) · 规则库 \(r.ruleSetVersion) · 姿态:\(state.settings.posture.rawValue)")
                        .font(.caption).foregroundColor(.secondary)
                    Text("风险 \(r.risks.count) 项 · 通过 \(r.passed.count) 项 · 不计分 \(r.findings.filter { $0.status == .unavailable }.count) 项")
                        .font(.callout.weight(.medium))
                }
                Spacer()
                Button(state.scanning ? "体检中…" : "重新体检") { state.runScan() }
                    .controlSize(.large).disabled(state.scanning)
            } else {
                ScoreRing(score: 0)
                VStack(alignment: .leading, spacing: 8) {
                    Text("安全盾 SafeShield").font(.largeTitle.bold())
                    Text("尚未体检。首次体检将读取本机真实系统状态(只读)。").foregroundColor(.secondary)
                    Button("开始首次体检") { state.runScan() }.controlSize(.large)
                }
            }
        }
    }

    private var dimensionRow: some View {
        HStack(spacing: 18) {
            ForEach(Dimension.allCases, id: \.self) { dim in
                DimRing(name: dim.rawValue, score: state.report?.dimensionScores[dim.rawValue] ?? -1)
            }
            Spacer()
        }
        .padding(14)
        .background(RoundedRectangle(cornerRadius: 12).fill(Color.gray.opacity(0.06)))
    }

    private var guardianCard: some View {
        HStack(spacing: 14) {
            Image(systemName: state.guardian.running ? "shield.lefthalf.filled" : "shield")
                .font(.title2).foregroundColor(state.guardian.running ? .green : .secondary)
            VStack(alignment: .leading, spacing: 3) {
                Text("守护模式:" + (state.guardian.running ? "运行中" : "已停止")).font(.headline)
                Text(state.guardian.running
                     ? "第 \(state.guardian.tickCount) 轮差分 · 上次 " + (state.guardian.lastTick.map(Fmt.time) ?? "-") + " · 间隔 \(state.settings.intervalSec)s"
                     : "基线差分监控(新端口/新启动项/文件篡改/异常外连/新账户)未开启")
                    .font(.caption).foregroundColor(.secondary)
            }
            Spacer()
            Button(state.guardian.running ? "停止守护" : "启动守护") { state.toggleGuardian() }
            Button("守护中心") { state.selection = .guardian }
        }
        .padding(14)
        .background(RoundedRectangle(cornerRadius: 12).fill(Color.gray.opacity(0.06)))
    }

    private var recentEvents: some View {
        VStack(alignment: .leading, spacing: 10) {
            Text("守护实时告警流").font(.headline)
            if state.guardian.events.isEmpty {
                Text("暂无事件。启动守护后,基线差分发现的异常会出现在这里。")
                    .font(.callout).foregroundColor(.secondary)
            } else {
                ForEach(state.guardian.events.prefix(5)) { e in
                    EventRowView(event: e, compact: true)
                }
            }
        }
    }
}

// MARK: - 事件行

struct EventRowView: View {
    @EnvironmentObject var state: AppState
    let event: SecurityEvent
    var compact: Bool = false
    var icon: String {
        switch event.kind {
        case .suspiciousProcess, .tempExecution: return "terminal"
        case .newListenPort: return "antenna.radiowaves.left.and.right"
        case .highFreqConnection, .suspiciousPortConnection: return "network"
        case .newLaunchAgent, .newLaunchDaemon: return "gearshape.2"
        case .newFile, .fileChanged: return "doc.badge.plus"
        case .newUserAccount: return "person.badge.key"
        case .guardianStarted, .guardianStopped: return "shield"
        case .error: return "exclamationmark.triangle"
        }
    }
    var body: some View {
        HStack(alignment: .top, spacing: 10) {
            Image(systemName: icon).foregroundColor(color).frame(width: 20)
            VStack(alignment: .leading, spacing: 3) {
                HStack(spacing: 6) {
                    Text(event.title).font(.callout.weight(.semibold))
                    SeverityBadge(sev: event.severity)
                    Spacer()
                    Text(Fmt.day(event.time)).font(.caption2).foregroundColor(.secondary)
                }
                if !compact || !event.detail.isEmpty {
                    Text(event.detail).font(.caption).foregroundColor(.secondary).lineLimit(2).textSelection(.enabled)
                }
                if !compact, let act = event.suggestedAction, let t = ActionType(rawValue: act) {
                    HStack(spacing: 8) {
                        Button(t.label) { state.requestAction(t, target: event.target, reason: event.title, sourceEventId: event.id) }
                            .controlSize(.small)
                        Text("目标:\(event.target)").font(.caption2).foregroundColor(.secondary).lineLimit(1)
                    }
                }
            }
        }
        .padding(10)
        .background(RoundedRectangle(cornerRadius: 8).fill(Color.gray.opacity(0.05)))
    }
    var color: Color {
        switch event.severity {
        case .critical, .high: return .orange
        case .medium: return .yellow
        case .low: return .blue
        case .info: return .secondary
        }
    }
}
