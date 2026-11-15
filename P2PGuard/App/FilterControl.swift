import SwiftUI
import NetworkExtension
import SystemExtensions

@MainActor final class FilterControl: NSObject, ObservableObject, OSSystemExtensionRequestDelegate {
    static let identifier = "org.thunderguard.firewall.extension"
    @Published private(set) var enabled = false
    @Published private(set) var directIP = false
    @Published private(set) var configured = false
    @Published private(set) var busy = false
    @Published private(set) var note: String?
    private let manager = NEFilterManager.shared()
    private var pending: (bt: Bool, ip: Bool)?

    func load() async {
        guard !busy else { return }
        do {
            try await manager.loadFromPreferences()
            configured = manager.isEnabled && manager.providerConfiguration?.filterDataProviderBundleIdentifier == Self.identifier
            enabled = configured && (manager.providerConfiguration?.vendorConfiguration?["blockThunderBT"] as? Bool == true)
            directIP = configured && (manager.providerConfiguration?.vendorConfiguration?["blockThunderIP"] as? Bool == true)
        } catch { note = error.localizedDescription }
    }

    func change(bt: Bool, ip: Bool) {
        guard !busy else { return }
        note = nil
        busy = true
        pending = (bt, ip)
        if bt || ip {
            let request = OSSystemExtensionRequest.activationRequest(forExtensionWithIdentifier: Self.identifier, queue: .main)
            request.delegate = self
            OSSystemExtensionManager.shared.submitRequest(request)
        } else {
            Task { await persist(bt: false, ip: false) }
        }
    }

    private func persist(bt: Bool, ip: Bool) async {
        defer { busy = false; pending = nil }
        do {
            try await manager.loadFromPreferences()
            let config = manager.providerConfiguration ?? NEFilterProviderConfiguration()
            config.filterSockets = true
            config.filterPackets = false
            config.filterDataProviderBundleIdentifier = Self.identifier
            config.vendorConfiguration = ["blockThunderBT": bt, "blockThunderIP": ip]
            manager.providerConfiguration = config
            manager.localizedDescription = "P2P 护栏"
            manager.isEnabled = true
            try await manager.saveToPreferences()
            try await manager.loadFromPreferences()
            configured = manager.isEnabled
            enabled = configured && (manager.providerConfiguration?.vendorConfiguration?["blockThunderBT"] as? Bool == true)
            directIP = configured && (manager.providerConfiguration?.vendorConfiguration?["blockThunderIP"] as? Bool == true)
            note = (bt || ip) ? "已保存策略，将检查迅雷的新连接。" : "已关闭拦截。"
        } catch { note = error.localizedDescription }
    }

    nonisolated func requestNeedsUserApproval(_ request: OSSystemExtensionRequest) {
        Task { @MainActor in note = "请在系统设置 → 登录项与扩展 → 网络扩展中允许 P2P 护栏。" }
    }

    nonisolated func request(_ request: OSSystemExtensionRequest, actionForReplacingExtension existing: OSSystemExtensionProperties,
                             withExtension replacement: OSSystemExtensionProperties) -> OSSystemExtensionRequest.ReplacementAction {
        (Int(replacement.bundleVersion) ?? 0) >= (Int(existing.bundleVersion) ?? 0) ? .replace : .cancel
    }

    nonisolated func request(_ request: OSSystemExtensionRequest, didFinishWithResult result: OSSystemExtensionRequest.Result) {
        Task { @MainActor in
            if result == .willCompleteAfterReboot {
                note = "扩展将在重启后更新。"; busy = false
            } else if let pending { await persist(bt: pending.bt, ip: pending.ip) }
            else { busy = false }
        }
    }

    nonisolated func request(_ request: OSSystemExtensionRequest, didFailWithError error: Error) {
        Task { @MainActor in note = error.localizedDescription; busy = false }
    }
}
