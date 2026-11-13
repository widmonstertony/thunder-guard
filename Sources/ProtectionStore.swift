import SwiftUI
import AppKit

struct ProtectionSnapshot: Decodable {
    struct Component: Decodable { let id: String; let fallbackBlock: Bool }
    struct Counters: Decodable { let origin: Int64; let p2p: Int64; let dcdn: Int64 }
    let luluExtensionActive: Bool
    let luluProviderRunning: Bool
    let filterEnabled: Bool
    let firewallOn: Bool
    let inboundMainBlocked: Bool
    let inboundServiceBlocked: Bool
    let cloudExceptionsPresent: Bool
    let selectivePeerBlock: Bool
    let passiveMode: Bool
    let globalAllowList: Bool
    let components: [Component]
    let activeCloudHosts: [String]
    let activeCloudCounters: Counters

    var engineReady: Bool { luluExtensionActive && luluProviderRunning && filterEnabled }
    var thunderRulesReady: Bool {
        ["com.xunlei.Thunder", "com.xunlei.DownloadService"].allSatisfy { id in
            components.contains { $0.id == id && $0.fallbackBlock }
        }
    }
    var protectionRunning: Bool {
        engineReady && thunderRulesReady && firewallOn && inboundMainBlocked && inboundServiceBlocked
            && !passiveMode && !globalAllowList
    }
}

@MainActor final class ProtectionStore: ObservableObject {
    @Published var snapshot: ProtectionSnapshot?
    @Published var error: String?
    @Published var checking = false

    var title: String {
        if let error { return "保护状态读取失败：\(error)" }
        guard let snapshot else { return "正在检查保护状态" }
        if !snapshot.engineReady { return "网络过滤未运行" }
        if !snapshot.protectionRunning { return "迅雷保护设置未完成" }
        return "迅雷保护运行中"
    }

    var detail: String {
        guard let snapshot else { return "正在核对过滤器和实际规则…" }
        if !snapshot.engineReady { return "连接监控可用；当前拦截引擎未就绪。" }
        if !snapshot.protectionRunning { return "连接监控可用；打开保护详情查看缺失项。" }
        return snapshot.selectivePeerBlock
            ? "域名连接允许 · IP 直连和已知 peer 目标受限"
            : "当前使用云盘规则 · 新版简化规则尚未应用"
    }

    func refresh() {
        guard !checking else { return }
        checking = true
        let tool = Bundle.main.resourceURL!.appendingPathComponent("guard.py")
        Task {
            let result = await Task.detached { Result { try Self.read(tool) } }.value
            defer { checking = false }
            switch result {
            case .success(let value): snapshot = value; error = nil
            case .failure(let failure): error = failure.localizedDescription
            }
        }
    }

    nonisolated private static func read(_ tool: URL) throws -> ProtectionSnapshot {
        let task = Process()
        task.executableURL = URL(fileURLWithPath: "/usr/bin/python3")
        task.arguments = [tool.path, "audit"]
        let pipe = Pipe()
        task.standardOutput = pipe
        task.standardError = pipe
        try task.run()
        let data = pipe.fileHandleForReading.readDataToEndOfFile()
        task.waitUntilExit()
        guard task.terminationStatus == 0 else {
            throw NSError(domain: "ThunderGuard", code: Int(task.terminationStatus),
                          userInfo: [NSLocalizedDescriptionKey: "无法读取过滤器状态"])
        }
        return try JSONDecoder().decode(ProtectionSnapshot.self, from: data)
    }
}
