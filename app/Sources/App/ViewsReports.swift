import SwiftUI
import AppKit

// MARK: - 报告中心:历史 + 趋势 + 详情 + 导出

struct ReportsView: View {
    @EnvironmentObject var state: AppState

    private var selected: ScanReport? {
        state.reports.first { $0.id == state.selectedReportId } ?? state.reports.last
    }

    var body: some View {
        HStack(spacing: 0) {
            listPane
            Divider()
            detailPane
        }
    }

    private var listPane: some View {
        VStack(alignment: .leading, spacing: 10) {
            Text("历史报告").font(.headline).padding(.horizontal, 14).padding(.top, 18)
            trendChart.padding(.horizontal, 14)
            ScrollView {
                VStack(spacing: 6) {
                    ForEach(state.reports.reversed()) { r in
                        Button {
                            state.selectedReportId = r.id
                        } label: {
                            HStack {
                                VStack(alignment: .leading, spacing: 2) {
                                    Text(Fmt.full(r.startedAt)).font(.caption.weight(.medium))
                                    Text("风险 \(r.risks.count) · 通过 \(r.passed.count)").font(.caption2).foregroundColor(.secondary)
                                }
                                Spacer()
                                Text("\(r.score)").font(.title3.bold())
                                    .foregroundColor(r.score >= 75 ? .green : (r.score >= 60 ? .orange : .red))
                            }
                            .padding(10)
                            .background(RoundedRectangle(cornerRadius: 8)
                                .fill(selected?.id == r.id ? Color.accentColor.opacity(0.12) : Color.gray.opacity(0.05)))
                        }
                        .buttonStyle(.plain)
                    }
                }
                .padding(.horizontal, 14).padding(.bottom, 14)
            }
        }
        .frame(width: 260)
    }

    private var trendChart: some View {
        VStack(alignment: .leading, spacing: 4) {
            Text("评分趋势").font(.caption).foregroundColor(.secondary)
            GeometryReader { geo in
                let pts = state.reports.suffix(20).map { $0.score }
                Path { p in
                    guard pts.count > 1 else { return }
                    let w = geo.size.width, h = geo.size.height
                    for (i, s) in pts.enumerated() {
                        let x = w * CGFloat(i) / CGFloat(pts.count - 1)
                        let y = h - h * CGFloat(s) / 100.0
                        if i == 0 { p.move(to: CGPoint(x: x, y: y)) } else { p.addLine(to: CGPoint(x: x, y: y)) }
                    }
                }
                .stroke(Color.green, style: StrokeStyle(lineWidth: 2, lineCap: .round))
            }
            .frame(height: 46)
            .padding(8)
            .background(RoundedRectangle(cornerRadius: 8).fill(Color.gray.opacity(0.06)))
        }
    }

    private var detailPane: some View {
        ScrollView {
            if let r = selected {
                VStack(alignment: .leading, spacing: 16) {
                    HStack(alignment: .top, spacing: 18) {
                        ScoreRing(score: r.score, size: 96, lineWidth: 9)
                        VStack(alignment: .leading, spacing: 4) {
                            Text("体检报告").font(.title3.bold())
                            Text(Fmt.full(r.startedAt) + " → " + Fmt.time(r.finishedAt)).font(.caption).foregroundColor(.secondary)
                            Text("规则集 \(r.ruleSetVersion) · 评分口径 S = 100 × (1 − Σ(w·p)/Σw)").font(.caption2).foregroundColor(.secondary)
                            HStack(spacing: 10) {
                                ForEach(Dimension.allCases, id: \.self) { d in
                                    DimRing(name: d.rawValue, score: r.dimensionScores[d.rawValue] ?? -1)
                                }
                            }
                            .padding(.top, 4)
                        }
                        Spacer()
                        Button("导出 Markdown") { export(r) }
                    }
                    ForEach(r.risks) { f in FindingRow(finding: f) }
                    ForEach(r.passed) { f in FindingRow(finding: f) }
                    ForEach(r.findings.filter { $0.status == .unavailable }) { f in FindingRow(finding: f) }
                }
                .padding(24)
            } else {
                Text("暂无报告,先在体检页跑一次。").padding(24).foregroundColor(.secondary)
            }
        }
    }

    private func export(_ r: ScanReport) {
        let panel = NSSavePanel()
        panel.nameFieldStringValue = "SafeShield-报告-\(Fmt.full(r.startedAt).replacingOccurrences(of: " ", with: "_").replacingOccurrences(of: ":", with: "")).md"
        panel.allowedContentTypes = [.plainText]
        if panel.runModal() == .OK, let url = panel.url {
            try? ReportExport.markdown(r).data(using: .utf8)?.write(to: url)
            state.toast = "已导出:\(url.path)"
        }
    }
}
