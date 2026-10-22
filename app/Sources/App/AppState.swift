import Foundation
import SwiftUI

// MARK: - 全局状态(App 环境,设计 §6 AppEnvironment)

@MainActor
public final class AppState: ObservableObject {
    public enum Page: String, CaseIterable, Identifiable {
        case dashboard = "仪表盘", scan = "体检", guardian = "守护中心", reports = "报告", settings = "设置"
        public var id: String { rawValue }
        public var icon: String {
            switch self {
            case .dashboard: return "gauge.medium"
            case .scan: return "stethoscope"
            case .guardian: return "shield.lefthalf.filled"
            case .reports: return "doc.text"
            case .settings: return "gearshape"
            }
        }
    }

    @Published public var settings: AppSettings { didSet { settings.save(); judge = WhitelistJudge(settings.whitelists) } }
    @Published public var judge: WhitelistJudge
    @Published public var rules: RuleSet
    @Published public var reports: [ScanReport]
    @Published public var report: ScanReport?
    @Published public var scanning = false
    @Published public var progress: [(String, Bool)] = []
    @Published public var selection: Page = .dashboard
    @Published public var selectedReportId: String? = nil
    @Published public var showOnboarding: Bool
    @Published public var pending: PendingAction? = nil
    @Published public var secondConfirmChecked = false
    @Published public var toast: String? = nil

    public let guardian = GuardianEngine()
    public let coordinator = ResponseCoordinator()
    private let registry = DetectorRegistry()

    public struct PendingAction: Identifiable {
        public let id = UUID()
        public let action: SecurityAction
        public let decision: ActionDecision
    }

    public init() {
        let s = AppSettings.load()
        settings = s
        judge = WhitelistJudge(s.whitelists)
        let loaded = ReportStore.load()
        rules = RuleSet.load()
        reports = loaded
        report = loaded.last
        showOnboarding = !s.onboardingDone
        guardian.onEvent = { [weak self] e in
            Task { @MainActor in
                guard let self, self.settings.notifyEnabled, e.severity >= .high else { return }
                await Notify.send(e)
            }
        }
    }

    // MARK: 体检

    public func runScan() {
        guard !scanning else { return }
        scanning = true; progress = []
        let rules = rules, judge = judge
        Task {
            let rep = await ScanEngine.scan(registry: registry, rules: rules, judge: judge) { title, ok in
                Task { @MainActor [weak self] in
                    self?.progress.append((title, ok))
                }
            }
            report = rep
            reports = ReportStore.add(rep)
            scanning = false
            toast = "体检完成:\(rep.score) 分(\(rep.grade))"
        }
    }

    // MARK: 守护

    public func toggleGuardian() {
        if guardian.running {
            guardian.stop()
            settings.guardianEnabled = false
        } else {
            guardian.start(intervalSec: settings.intervalSec, rules: rules, judge: judge)
            settings.guardianEnabled = true
        }
    }

    // MARK: 处置(确认流)

    public func requestAction(_ type: ActionType, target: String, reason: String, sourceEventId: String? = nil) {
        let a = SecurityAction(type: type, target: target, reason: reason, sourceEventId: sourceEventId)
        let d = ActionPolicy.decide(a, posture: settings.posture, judge: judge)
        if d.allowed && !d.needsConfirm {
            Task { await coordinator.execute(a, posture: settings.posture, judge: judge, confirmed: true) }
            return
        }
        secondConfirmChecked = false
        pending = PendingAction(action: a, decision: d)
    }

    public func confirmPending() {
        guard let p = pending else { return }
        if p.decision.needsSecondConfirm && !secondConfirmChecked { return }
        pending = nil
        let posture = settings.posture, judge = judge
        let a = p.action
        Task {
            let rec = await coordinator.execute(a, posture: posture, judge: judge, confirmed: true)
            toast = "处置结果:\(rec.result)"
        }
    }

    public func rollback(_ auditId: String) {
        Task {
            if let r = await coordinator.rollback(auditId) { toast = "回滚:\(r.result)" }
            else { toast = "该记录不支持回滚" }
        }
    }

    // MARK: 设置变更

    public func applyGuardianInterval(_ v: Int) {
        settings.intervalSec = v
        if guardian.running {
            guardian.stop()
            guardian.start(intervalSec: v, rules: rules, judge: judge)
        }
    }

    public func finishOnboarding() {
        settings.onboardingDone = true
        settings.consentAt = Date()
        showOnboarding = false
    }
}
