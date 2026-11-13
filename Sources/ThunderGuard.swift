import SwiftUI
import AppKit

@main
struct ThunderGuardApp: App {
    var body: some Scene {
        WindowGroup("迅雷护栏") {
            MainWindow()
        }
    }
}

private struct MainWindow: View {
    @StateObject private var protection = ProtectionStore()
    @State private var details = false
    @State private var magnet = false

    var body: some View {
        NetworkDashboardView(showProtectionDetails: { details = true })
            .environmentObject(protection)
            .toolbar {
                ToolbarItemGroup {
                    Button { magnet = true } label: { Label("添加到云盘", systemImage: "cloud.badge.plus") }
                    Button { details = true } label: { Label("保护详情", systemImage: "slider.horizontal.3") }
                }
            }
            .sheet(isPresented: $details) {
                VStack(spacing: 0) {
                    HStack {
                        Text("保护详情与高级设置").font(.headline)
                        Spacer()
                        Button("完成") { details = false }.keyboardShortcut(.cancelAction)
                    }.padding()
                    Divider()
                    GuardView()
                }.frame(width: 730, height: 700)
            }
            .sheet(isPresented: $magnet) {
                VStack {
                    HStack { Spacer(); Button("完成") { magnet = false }.keyboardShortcut(.cancelAction) }
                    CloudMagnetView()
                }.padding().frame(width: 700, height: 620)
            }
            .onAppear { protection.refresh() }
            .onReceive(Timer.publish(every: 15, on: .main, in: .common).autoconnect()) { _ in protection.refresh() }
    }
}

private struct GuardAudit: Decodable {
    struct Component: Decodable { let id: String; let fallbackBlock: Bool }
    struct CloudCounters: Decodable { let origin: Int64; let p2p: Int64; let dcdn: Int64 }
    let luluExtensionActive: Bool
    let filterEnabled: Bool
    let selectivePeerBlock: Bool
    let peerPatterns: [String]
    let peerPorts: [String]
    let luluAppRunning: Bool
    let luluProviderRunning: Bool
    let firewallOn: Bool
    let inboundMainBlocked: Bool
    let inboundServiceBlocked: Bool
    let components: [Component]
    let allowEndpoints: [String]
    let dnsServers: [String]
    let dnsExceptionsPresent: Bool
    let cloudHosts: [String]
    let activeCloudHosts: [String]
    let activeCloudCounters: CloudCounters
    let cloudExceptionsPresent: Bool
    let strictCloudOnly: Bool
    let globalAllowList: Bool
    let localhostBypass: Bool
    let passiveMode: Bool
    let rulesFileExists: Bool
}

struct GuardView: View {
    @State private var audit: GuardAudit?
    @State private var checking = false
    @State private var message = "正在检查…"
    @State private var lastOutput: String?

    private let tool = Bundle.main.resourceURL!.appendingPathComponent("guard.py")
    private let appPath = URL(fileURLWithPath: "/Applications/LuLu.app")
    private let monitorPath = URL(fileURLWithPath: "/Applications/LuLu.app/Contents/Resources/Netiquette.app")

    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 18) {
                Text("迅雷护栏").font(.largeTitle.bold())
                Text("免费 · 全应用连接可见 · 不修改迅雷文件").foregroundStyle(.secondary)
                statusPanel
                GroupBox("1 · 出站连接：LuLu") {
                    VStack(alignment: .leading, spacing: 12) {
                        Text("允许带主机名的连接，拒绝无主机名的 IP 直连和下列已知 peer 目标。不再要求云盘 CDN 的域名或 IP 出现在固定名单中。其他应用规则保留。")
                        Text("目标：phub / shub.sandai.net 子域名、bt.n0808.com 子域名")
                        Text("端口：1500、3076、6881–6889、11400、25401")
                            .font(.caption).textSelection(.enabled)
                        HStack {
                            Button("生成并备份规则") { buildRules() }
                            Button("启动 LuLu") { startLuLu() }
                            Button("打开 LuLu 规则") { openLuLuRules() }
                            if let lastOutput {
                                Button("查看规则文件") {
                                    NSWorkspace.shared.activateFileViewerSelecting([URL(fileURLWithPath: lastOutput)])
                                }
                            }
                        }
                        Text("生成后需在 LuLu 菜单栏图标 → Rules → Import 导入 JSON。会替换旧的迅雷默认拒绝规则，不再维护云盘 IP 白名单。")
                            .font(.caption).foregroundStyle(.secondary)
                    }.frame(maxWidth: .infinity, alignment: .leading).padding(8)
                }
                GroupBox("2 · 入站连接：macOS 防火墙") {
                    VStack(alignment: .leading, spacing: 10) {
                        Text("系统防火墙目前\((audit?.firewallOn ?? false) ? "已开启" : "未开启")。需要把迅雷及下载服务设为拒绝入站。开启系统防火墙可能影响其他应用的入站服务。")
                        HStack {
                            Button("配置迅雷入站拦截") { configureFirewall() }
                            Button("打开防火墙设置") {
                                NSWorkspace.shared.open(URL(string: "x-apple.systempreferences:com.apple.Network-Settings.extension?Firewall")!)
                            }
                        }
                        Text("点击配置会弹出 macOS 管理员授权；授权后核对实际状态。")
                            .font(.caption).foregroundStyle(.secondary)
                    }.frame(maxWidth: .infinity, alignment: .leading).padding(8)
                }
                GroupBox("3 · 验证") {
                    VStack(alignment: .leading, spacing: 10) {
                        Text("核对实际取回速度及下列任务计数。此模式按已知目标与端口拦截，不是所有 P2P 协议的自动识别器；有域名的 P2P 也可能获准，只有 IP 的正常服务也可能被拦。")
                        Button("重新检查") { refresh() }
                        Text(message).font(.system(.caption, design: .monospaced)).textSelection(.enabled)
                    }.frame(maxWidth: .infinity, alignment: .leading).padding(8)
                }
                GroupBox("4 · 查看其他 App") {
                    VStack(alignment: .leading, spacing: 10) {
                        Text("“网络总览”页直接显示所有 App 的当前连接、目标地址、端口及收发量。需要拦截某个 App 时，可在 LuLu 为它设置出站规则。")
                        HStack {
                            Button("打开 Netiquette 详细视图") { openNetworkMonitor() }
                            Button("管理所有 App 出站规则") { openLuLuRules() }
                        }
                        Text("连接信息本身不能可靠判断所有 P2P；按进程和目标逐项核查后再拦截。")
                            .font(.caption).foregroundStyle(.secondary)
                    }.frame(maxWidth: .infinity, alignment: .leading).padding(8)
                }
            }
            .padding(24)
            .frame(width: 680, alignment: .leading)
        }
        .onAppear(perform: refresh)
        .onReceive(Timer.publish(every: 15, on: .main, in: .common).autoconnect()) { _ in refresh() }
    }

    private var statusPanel: some View {
        GroupBox("当前状态") {
            VStack(alignment: .leading, spacing: 6) {
                status("LuLu 主程序", audit?.luluAppRunning == true)
                status("LuLu 实际过滤开关", audit?.filterEnabled == true)
                status("LuLu 过滤进程和系统扩展", audit?.luluProviderRunning == true && audit?.luluExtensionActive == true)
                status("域名连接允许 / IP 直连拒绝规则", audit?.selectivePeerBlock == true)
                if let counters = audit?.activeCloudCounters,
                   audit?.activeCloudHosts.isEmpty == false {
                    status("当前取回任务 P2P / DCDN 计数为零", counters.p2p == 0 && counters.dcdn == 0)
                    Text("迅雷任务计数：源站 \(formatBytes(counters.origin)) · P2P \(formatBytes(counters.p2p)) · DCDN \(formatBytes(counters.dcdn))")
                        .font(.caption).foregroundStyle(.secondary)
                }
                status("系统防火墙", audit?.firewallOn == true)
                status("迅雷与下载服务入站规则", audit?.inboundMainBlocked == true && audit?.inboundServiceBlocked == true)
                if let audit {
                    if !audit.luluAppRunning { Text("⚠ LuLu 主程序未运行：请启动后再依赖迅雷拦截规则") }
                    if !audit.filterEnabled { Text("⚠ LuLu 已停用：规则当前不会拦截连接。请在 LuLu 菜单栏选择 Enable。") }
                    if !audit.selectivePeerBlock { Text("当前使用旧规则；新版简化规则尚未应用。") }
                }
                if audit?.globalAllowList == true { Text("⚠ LuLu 全局放行列表可能绕过迅雷规则") }
                if audit?.localhostBypass == true { Text("⚠ LuLu 当前放行本机回环连接") }
                Text("规则档案和进程状态不能代替流量实测；不能保证识别所有加密 P2P。")
                    .font(.caption).foregroundStyle(.secondary)
            }.frame(maxWidth: .infinity, alignment: .leading).padding(8)
        }
    }

    private func status(_ title: String, _ active: Bool) -> some View {
        Text("\(active ? "●" : "○") \(title)：\(audit == nil ? "检查中" : active ? "已检测" : "待完成")")
            .foregroundStyle(audit == nil ? Color.secondary : active ? Color.green : Color.orange)
    }

    private func formatBytes(_ bytes: Int64) -> String {
        bytes == 0 ? "0 B" : ByteCountFormatter.string(fromByteCount: bytes, countStyle: .file)
    }

    nonisolated private static func run(_ tool: URL, _ args: [String]) throws -> Data {
        let process = Process()
        process.executableURL = URL(fileURLWithPath: "/usr/bin/python3")
        process.arguments = [tool.path] + args
        let pipe = Pipe()
        process.standardOutput = pipe
        process.standardError = pipe
        try process.run()
        let data = pipe.fileHandleForReading.readDataToEndOfFile()
        process.waitUntilExit()
        guard process.terminationStatus == 0 else {
            throw NSError(domain: "ThunderGuard", code: Int(process.terminationStatus), userInfo: [NSLocalizedDescriptionKey: String(data: data, encoding: .utf8) ?? "命令失败"])
        }
        return data
    }

    private func refresh() {
        guard !checking else { return }
        checking = true
        let script = tool
        Task {
            let result = await Task.detached { Result { try Self.run(script, ["audit"]) } }.value
            defer { checking = false }
            do {
                audit = try JSONDecoder().decode(GuardAudit.self, from: result.get())
                message = "找到 \(audit?.components.count ?? 0) 个迅雷组件。过滤开关：\(audit?.filterEnabled == true ? "开启" : "停用")。"
            } catch { message = error.localizedDescription }
        }
    }

    private func buildRules() {
        do {
            let json = try JSONSerialization.jsonObject(with: Self.run(tool, ["prepare"])) as? [String: Any]
            lastOutput = json?["output"] as? String
            message = "已备份原规则并生成合并文件：\(lastOutput ?? "未知路径")。尚未导入 LuLu。"
        } catch { message = error.localizedDescription }
    }

    private func openLuLuRules() {
        let config = NSWorkspace.OpenConfiguration()
        config.arguments = ["-rules"]
        NSWorkspace.shared.openApplication(at: appPath, configuration: config) { _, error in
            if let error { DispatchQueue.main.async { message = error.localizedDescription } }
        }
    }

    private func openNetworkMonitor() {
        NSWorkspace.shared.openApplication(at: monitorPath, configuration: NSWorkspace.OpenConfiguration()) { _, error in
            if let error { DispatchQueue.main.async { message = error.localizedDescription } }
        }
    }

    private func startLuLu() {
        NSWorkspace.shared.openApplication(at: appPath, configuration: NSWorkspace.OpenConfiguration()) { _, error in
            DispatchQueue.main.async {
                if let error { message = error.localizedDescription }
                else { refresh() }
            }
        }
    }

    private func configureFirewall() {
        // Constant, reviewed paths; the rule builder has already checked the binaries' signatures.
        let firewall = "/usr/libexec/ApplicationFirewall/socketfilterfw"
        let main = "/Applications/Thunder.app"
        let service = "/Applications/Thunder.app/Contents/XPCServices/DownloadService.xpc"
        let commands = ["\(firewall) --setglobalstate on", "\(firewall) --add '\(main)'",
                        "\(firewall) --blockapp '\(main)'", "\(firewall) --add '\(service)'",
                        "\(firewall) --blockapp '\(service)'"]
        let shell = commands.joined(separator: " && ")
        let escaped = shell.replacingOccurrences(of: "\\", with: "\\\\")
            .replacingOccurrences(of: "\"", with: "\\\"")
        let script = NSAppleScript(source: "do shell script \"\(escaped)\" with administrator privileges")
        var error: NSDictionary?
        _ = script?.executeAndReturnError(&error)
        if let error { message = "防火墙配置失败：\(error)" }
        else { refresh() }
    }
}
