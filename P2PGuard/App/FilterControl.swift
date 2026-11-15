import SwiftUI
import NetworkExtension
import SystemExtensions

@MainActor final class FilterControl: NSObject, ObservableObject, OSSystemExtensionRequestDelegate {
    static let identifier = "org.thunderguard.firewall.extension"
    @Published private(set) var policy = GuardPolicy()
    @Published private(set) var configured = false
    @Published private(set) var busy = false
    @Published private(set) var note: String?
    private let manager = NEFilterManager.shared()
    private var pending: GuardPolicy?

    func load() async {
        guard !busy else { return }
        do {
            try await manager.loadFromPreferences()
            guard !busy else { return }
            readPreferences()
        } catch { note = error.localizedDescription }
    }

    private func readPreferences() {
        let config = manager.providerConfiguration
        let ownsConfig = config?.filterDataProviderBundleIdentifier == Self.identifier
        let active = manager.isEnabled && ownsConfig
        let saved = GuardPolicy(vendorConfiguration: ownsConfig ? config?.vendorConfiguration ?? [:] : [:])
        if configured != active { configured = active }
        if policy != saved { policy = saved }
    }

    func change(to policy: GuardPolicy) {
        guard !busy else { return }
        note = nil
        busy = true
        pending = policy
        if policy.needsFilter {
            let request = OSSystemExtensionRequest.activationRequest(forExtensionWithIdentifier: Self.identifier, queue: .main)
            request.delegate = self
            OSSystemExtensionManager.shared.submitRequest(request)
        } else {
            Task { await persist(policy) }
        }
    }

    private func persist(_ policy: GuardPolicy) async {
        defer { busy = false; pending = nil }
        do {
            try await manager.loadFromPreferences()
            let config = manager.providerConfiguration ?? NEFilterProviderConfiguration()
            if let id = config.filterDataProviderBundleIdentifier, id != Self.identifier {
                note = "现有配置属于另一个过滤器。"
                return
            }
            config.filterSockets = true
            config.filterPackets = false
            config.filterDataProviderBundleIdentifier = Self.identifier
            config.vendorConfiguration = policy.vendorConfiguration
            manager.providerConfiguration = config
            manager.localizedDescription = "TonTon P2PGuard"
            manager.isEnabled = manager.isEnabled || policy.needsFilter
            try await manager.saveToPreferences()
            try await manager.loadFromPreferences()
            readPreferences()
            note = policy.needsFilter ? "已保存，将检查受保护 App 的新连接。" : "已保存。"
        } catch { note = error.localizedDescription }
    }

    nonisolated func requestNeedsUserApproval(_ request: OSSystemExtensionRequest) {
        Task { @MainActor in note = "请在系统设置 → 登录项与扩展 → 网络扩展中允许 TonTon P2PGuard。" }
    }

    nonisolated func request(_ request: OSSystemExtensionRequest, actionForReplacingExtension existing: OSSystemExtensionProperties,
                             withExtension replacement: OSSystemExtensionProperties) -> OSSystemExtensionRequest.ReplacementAction {
        (Int(replacement.bundleVersion) ?? 0) >= (Int(existing.bundleVersion) ?? 0) ? .replace : .cancel
    }

    nonisolated func request(_ request: OSSystemExtensionRequest, didFinishWithResult result: OSSystemExtensionRequest.Result) {
        Task { @MainActor in
            if result == .willCompleteAfterReboot {
                note = "扩展将在重启后更新。"; busy = false; pending = nil
            } else if let pending { await persist(pending) }
            else { busy = false }
        }
    }

    nonisolated func request(_ request: OSSystemExtensionRequest, didFailWithError error: Error) {
        Task { @MainActor in note = error.localizedDescription; busy = false; pending = nil }
    }
}
