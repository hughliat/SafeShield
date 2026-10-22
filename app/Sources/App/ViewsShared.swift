import SwiftUI

// MARK: - 共享组件

struct ScoreRing: View {
    let score: Int
    var size: CGFloat = 150
    var lineWidth: CGFloat = 12
    var color: Color {
        score >= 75 ? .green : (score >= 60 ? .orange : .red)
    }
    var body: some View {
        ZStack {
            Circle().stroke(Color.gray.opacity(0.15), lineWidth: lineWidth)
            Circle()
                .trim(from: 0, to: CGFloat(max(0, min(100, score))) / 100.0)
                .stroke(color, style: StrokeStyle(lineWidth: lineWidth, lineCap: .round))
                .rotationEffect(.degrees(-90))
                .animation(.easeOut(duration: 0.6), value: score)
            VStack(spacing: 2) {
                Text("\(score)").font(.system(size: size * 0.28, weight: .heavy, design: .rounded))
                Text(RuleEngine.grade(score)).font(.caption).foregroundColor(.secondary)
            }
        }
        .frame(width: size, height: size)
    }
}

struct SeverityBadge: View {
    let sev: Severity
    var color: Color {
        switch sev {
        case .critical: return .red
        case .high: return .orange
        case .medium: return .yellow
        case .low: return .blue
        case .info: return .secondary
        }
    }
    var body: some View {
        Text(sev.label)
            .font(.caption2.weight(.semibold))
            .padding(.horizontal, 7).padding(.vertical, 2)
            .background(Capsule().fill(color.opacity(0.16)))
            .foregroundColor(color == .secondary ? .secondary : color)
    }
}

struct StatusBadge: View {
    let status: FindingStatus
    var body: some View {
        Text(status == .pass ? "通过" : (status == .fail ? "风险" : "不计分"))
            .font(.caption2.weight(.semibold))
            .padding(.horizontal, 7).padding(.vertical, 2)
            .background(Capsule().fill((status == .pass ? Color.green : (status == .fail ? Color.orange : Color.gray)).opacity(0.15)))
            .foregroundColor(status == .pass ? .green : (status == .fail ? .orange : .secondary))
    }
}

struct EvidenceBox: View {
    let text: String
    var body: some View {
        Text(text)
            .font(.system(size: 11, design: .monospaced))
            .foregroundColor(.secondary)
            .frame(maxWidth: .infinity, alignment: .leading)
            .padding(8)
            .background(RoundedRectangle(cornerRadius: 6).fill(Color.gray.opacity(0.08)))
            .textSelection(.enabled)
    }
}

struct DimRing: View {
    let name: String
    let score: Int   // -1 = 无计分项
    var body: some View {
        VStack(spacing: 4) {
            ZStack {
                Circle().stroke(Color.gray.opacity(0.15), lineWidth: 5)
                Circle().trim(from: 0, to: CGFloat(max(0, score)) / 100.0)
                    .stroke(score < 0 ? Color.gray : (score >= 75 ? Color.green : (score >= 60 ? Color.orange : Color.red)),
                            style: StrokeStyle(lineWidth: 5, lineCap: .round))
                    .rotationEffect(.degrees(-90))
                Text(score < 0 ? "—" : "\(score)").font(.system(size: 13, weight: .bold, design: .rounded))
            }
            .frame(width: 44, height: 44)
            Text(name).font(.caption2).lineLimit(1).minimumScaleFactor(0.6)
                .foregroundColor(.secondary)
        }
        .frame(width: 64)
    }
}

// MARK: - 处置确认弹窗(不可逆动作二次确认,合规红线 3)

struct ConfirmSheet: View {
    @EnvironmentObject var state: AppState
    var body: some View {
        if let p = state.pending {
            VStack(alignment: .leading, spacing: 12) {
                Label(p.decision.allowed ? "处置确认" : "无法执行", systemImage: p.decision.allowed ? "exclamationmark.shield" : "lock.shield")
                    .font(.headline)
                VStack(alignment: .leading, spacing: 6) {
                    row("动作", p.action.type.label)
                    row("目标", p.action.target)
                    row("原因", p.action.reason)
                    row("姿态", state.settings.posture.rawValue)
                    row("可回滚", p.action.type.reversible ? "是(可在审计中还原)" : "否")
                    if p.action.type.requiresPrivilege {
                        row("特权", "需要 root 特权助手;未安装时仅记录建议")
                    }
                }
                .font(.callout)
                if let br = p.decision.blockedReason {
                    Text(br).font(.callout).foregroundColor(.orange)
                        .padding(8).frame(maxWidth: .infinity, alignment: .leading)
                        .background(RoundedRectangle(cornerRadius: 6).fill(Color.orange.opacity(0.1)))
                }
                if p.decision.needsSecondConfirm {
                    Toggle(isOn: $state.secondConfirmChecked) {
                        Text("我理解「\(p.action.type.label)」不可逆,确认继续。")
                            .font(.callout)
                    }
                    .toggleStyle(.checkbox)
                }
                HStack {
                    Spacer()
                    Button("取消") { state.pending = nil }.keyboardShortcut(.cancelAction)
                    if p.decision.allowed {
                        Button(p.decision.needsSecondConfirm ? "二次确认执行" : "确认执行") { state.confirmPending() }
                            .keyboardShortcut(.defaultAction)
                            .disabled(p.decision.needsSecondConfirm && !state.secondConfirmChecked)
                            .tint(p.action.type.irreversible ? .red : .accentColor)
                    }
                }
            }
            .padding(20)
            .frame(width: 460)
        }
    }
    func row(_ k: String, _ v: String) -> some View {
        HStack(alignment: .top, spacing: 8) {
            Text(k).foregroundColor(.secondary).frame(width: 52, alignment: .leading)
            Text(v).textSelection(.enabled)
        }
    }
}

// MARK: - 引导(能力边界 / 权限原因 / 隐私承诺)

struct OnboardingView: View {
    @EnvironmentObject var state: AppState
    @StateObject private var model = PageModel()
    final class PageModel: ObservableObject { @Published var page = 0 }
    private let pages: [(String, String, String)] = [
        ("shield.lefthalf.filled", "安全盾 SafeShield",
         "体检模式负责「防患于未然」:快照式检查系统配置、隐私、驻留、文件、网络与账户。\n守护模式负责「察变于即时」:基线差分发现新端口、新启动项、文件篡改与异常外连。"),
        ("key.horizontal", "为什么需要这些权限",
         "所有检测默认只读,仅执行白名单内的系统查询命令。\n读取系统授权清单(TCC)需要「完全磁盘访问」;未授权时自动降级为引导清单,不影响其余检测。"),
        ("lock.shield", "隐私承诺与处置边界",
         "全部数据留在本机,不上传任何文件内容或口令明文。\n任何处置都必须经你逐项确认;不可逆动作需二次确认;全过程审计、可回滚尽可能回滚。")
    ]
    var body: some View {
        VStack(spacing: 18) {
            Image(systemName: pages[model.page].0).font(.system(size: 44)).foregroundColor(.accentColor)
            Text(pages[model.page].1).font(.title2.bold())
            Text(pages[model.page].2).font(.callout).foregroundColor(.secondary)
                .multilineTextAlignment(.center).frame(maxWidth: 420)
            HStack(spacing: 6) {
                ForEach(0..<pages.count, id: \.self) { i in
                    Circle().fill(i == model.page ? Color.accentColor : Color.gray.opacity(0.3)).frame(width: 7, height: 7)
                }
            }
            HStack {
                Button("跳过") { state.finishOnboarding() }
                Spacer()
                if model.page > 0 { Button("上一页") { model.page -= 1 } }
                Button(model.page == pages.count - 1 ? "开始使用" : "下一页") {
                    if model.page == pages.count - 1 { state.finishOnboarding() } else { model.page += 1 }
                }
                .keyboardShortcut(.defaultAction)
            }
        }
        .padding(28)
        .frame(width: 520, height: 340)
    }
}
