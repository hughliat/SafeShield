import SwiftUI

// MARK: - 体检页

struct ScanView: View {
    @EnvironmentObject var state: AppState
    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 16) {
                toolbar
                if state.scanning { progressList }
                if let r = state.report { findingsList(r) }
            }
            .padding(24)
        }
    }

    private var toolbar: some View {
        HStack(spacing: 12) {
            Text("体检").font(.title2.bold())
            Text("6 组快照检测器 · 只读 · 评分口径 \(state.rules.version)")
                .font(.caption).foregroundColor(.secondary)
            Spacer()
            Button(state.scanning ? "体检中…" : (state.report == nil ? "开始体检" : "重新体检")) { state.runScan() }
                .controlSize(.large).disabled(state.scanning)
        }
    }

    private var progressList: some View {
        VStack(alignment: .leading, spacing: 6) {
            ProgressView().controlSize(.small)
            ForEach(state.progress, id: \.0) { p in
                HStack(spacing: 6) {
                    Image(systemName: p.1 ? "checkmark.circle.fill" : "clock")
                        .foregroundColor(p.1 ? .green : .secondary).font(.caption)
                    Text(p.0).font(.caption)
                    Text(p.1 ? "完成" : "超时/进行中").font(.caption2).foregroundColor(.secondary)
                }
            }
        }
        .padding(12)
        .background(RoundedRectangle(cornerRadius: 10).fill(Color.gray.opacity(0.06)))
    }

    private func findingsList(_ r: ScanReport) -> some View {
        VStack(alignment: .leading, spacing: 12) {
            ForEach(r.risks) { f in FindingRow(finding: f) }
            ForEach(r.passed) { f in FindingRow(finding: f) }
            ForEach(r.findings.filter { $0.status == .unavailable }) { f in FindingRow(finding: f) }
        }
    }
}

struct FindingRow: View {
    @EnvironmentObject var state: AppState
    let finding: Finding
    @StateObject private var model = GuideModel()
    final class GuideModel: ObservableObject { @Published var guide: String? = nil }
    var body: some View {
        VStack(alignment: .leading, spacing: 6) {
            HStack(spacing: 8) {
                Image(systemName: finding.status == .pass ? "checkmark.circle.fill"
                      : (finding.status == .fail ? "exclamationmark.triangle.fill" : "minus.circle"))
                    .foregroundColor(finding.status == .pass ? .green : (finding.status == .fail ? .orange : .secondary))
                Text(finding.name).font(.callout.weight(.semibold))
                StatusBadge(status: finding.status)
                if finding.status == .fail { SeverityBadge(sev: finding.severity) }
                Text(finding.dimension.rawValue).font(.caption2)
                    .padding(.horizontal, 6).padding(.vertical, 1)
                    .background(Capsule().fill(Color.gray.opacity(0.12)))
                    .foregroundColor(.secondary)
                Spacer()
                remediationButton
            }
            Text(finding.summary).font(.caption).foregroundColor(.secondary)
            EvidenceBox(text: finding.evidence)
        }
        .padding(12)
        .background(RoundedRectangle(cornerRadius: 10).fill(Color.gray.opacity(0.05)))
        .alert("修复指引", isPresented: Binding(get: { model.guide != nil }, set: { if !$0 { model.guide = nil } })) {
            Button("知道了", role: .cancel) {}
        } message: {
            Text(model.guide ?? "")
        }
    }

    @ViewBuilder
    private var remediationButton: some View {
        switch finding.remediationKind {
        case "deepLink":
            Button("去修复") {
                if let t = finding.remediationTarget, let u = URL(string: t) { NSWorkspace.shared.open(u) }
            }
            .controlSize(.small)
        case "action":
            Button("处置…") {
                state.requestAction(ActionType(rawValue: finding.actionType ?? "quarantineFile") ?? .quarantineFile,
                                    target: finding.evidence, reason: finding.name)
            }
            .controlSize(.small)
        default:
            Button("查看指引") { model.guide = finding.remediationTarget ?? finding.summary }
                .controlSize(.small)
        }
    }
}
