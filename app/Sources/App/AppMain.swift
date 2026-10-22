import SwiftUI
import AppKit

// MARK: - 应用入口与主窗口骨架

@main
struct SafeShieldApp: App {
    @StateObject private var state = AppState()

    var body: some Scene {
        WindowGroup("安全盾 SafeShield") {
            RootView()
                .environmentObject(state)
                .frame(minWidth: 1020, minHeight: 680)
                .sheet(isPresented: $state.showOnboarding) { OnboardingView().environmentObject(state) }
                .sheet(isPresented: Binding(get: { state.pending != nil },
                                            set: { if !$0 { state.pending = nil } })) {
                    ConfirmSheet().environmentObject(state)
                }
                .overlay(alignment: .bottom) {
                    if let t = state.toast {
                        Text(t)
                            .font(.callout)
                            .padding(.horizontal, 14).padding(.vertical, 8)
                            .background(Capsule().fill(Color.black.opacity(0.75)))
                            .foregroundColor(.white)
                            .padding(.bottom, 18)
                            .onAppear {
                                DispatchQueue.main.asyncAfter(deadline: .now() + 3.5) { state.toast = nil }
                            }
                    }
                }
                .onAppear {
                    NSApp.setActivationPolicy(.regular)
                    NSApp.activate(ignoringOtherApps: true)
                    // 仅供自动化验证/演示的启动参数(正常双击启动不受影响)
                    let args = ProcessInfo.processInfo.arguments
                    if args.contains("--skip-onboarding") { state.showOnboarding = false }
                    if let i = args.firstIndex(of: "--interval"), i + 1 < args.count, let v = Int(args[i + 1]) {
                        state.applyGuardianInterval(v)
                    }
                    if let i = args.firstIndex(of: "--page"), i + 1 < args.count {
                        let map = ["dashboard": AppState.Page.dashboard, "scan": .scan,
                                   "guardian": .guardian, "reports": .reports, "settings": .settings]
                        if let p = map[args[i + 1]] { state.selection = p }
                    }
                    if args.contains("--guardian") { state.toggleGuardian() }
                    if args.contains("--scan") { state.runScan() }
                    if args.contains("--show-confirm") {
                        let a = SecurityAction(type: .killProcess, target: "99999",
                                               reason: "演示:命中可疑关键字规则(仅界面演示,不执行)")
                        state.pending = AppState.PendingAction(
                            action: a,
                            decision: ActionPolicy.decide(a, posture: state.settings.posture, judge: state.judge))
                    }
                    if args.contains("--selftest") {
                        Task {
                            let checks = await SelfTest.run(state)
                            for c in checks {
                                FileHandle.standardOutput.write(("\(c.pass ? "PASS" : "FAIL") \(c.name) | \(c.detail)\n").data(using: .utf8)!)
                            }
                            exit(checks.allSatisfy(\.pass) ? 0 : 1)
                        }
                    }
                    if args.contains("--headless") {
                        func say(_ s: String) {
                            FileHandle.standardOutput.write((s + "\n").data(using: .utf8)!)
                        }
                        say("HEADLESS START")
                        Task {
                            let rules = state.rules, judge = state.judge
                            let reg = DetectorRegistry()
                            let rep = await ScanEngine.scan(registry: reg, rules: rules, judge: judge) { t, ok in
                                say("PROG \(t) ok=\(ok)")
                            }
                            say("SCORE \(rep.score) risks=\(rep.risks.count)")
                            for f in rep.findings where f.status != .pass {
                                say("  \(f.status.rawValue) \(f.severity.rawValue) \(f.id) \(f.evidence.prefix(60))")
                            }
                            exit(0)
                        }
                    }
                }
        }
        .windowStyle(.automatic)
    }
}

struct RootView: View {
    @EnvironmentObject var state: AppState
    var body: some View {
        NavigationSplitView {
            List(AppState.Page.allCases,
                 selection: Binding(get: { state.selection as AppState.Page? },
                                    set: { state.selection = $0 ?? .dashboard })) { p in
                Label(p.rawValue, systemImage: p.icon).tag(p)
            }
            .navigationSplitViewColumnWidth(min: 150, ideal: 170, max: 200)
            .listStyle(.sidebar)
        } detail: {
            switch state.selection {
            case .dashboard: DashboardView()
            case .scan: ScanView()
            case .guardian: GuardianView()
            case .reports: ReportsView()
            case .settings: SettingsView()
            }
        }
    }
}
