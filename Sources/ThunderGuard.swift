import SwiftUI
import AppKit

@main
struct ThunderGuardApp: App {
    var body: some Scene {
        WindowGroup("迅雷护栏") { GuardView() }
            .windowResizability(.contentSize)
    }
}

private struct GuardAudit: Decodable {
    struct Component: Decodable { let id: String; let fallbackBlock: Bool }
    let luluExtensionActive: Bool
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
    let cloudExceptionsPresent: Bool
    let globalAllowList: Bool
    let localhostBypass: Bool
    let passiveMode: Bool
    let rulesFileExists: Bool
}

struct GuardView: View {
    @State private var audit: GuardAudit?
    @State private var endpoints = ""
    @State private var cloudHosts = ""
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
                        Text("默认拦截迅雷与下载服务。仅放行你确认用于正常下载的服务器；其他应用的 LuLu 规则会保留。")
                        TextField("下载服务器域名或 IP，每行一个", text: $endpoints, axis: .vertical)
                            .lineLimit(3...6)
                            .textFieldStyle(.roundedBorder)
                        Text("云盘 CDN 主机名（仅支持已核实的 vod…-vip-lixian.xunlei.com；生成时解析为精确 IP:443 规则）")
                        TextField("云盘 CDN 主机名，每行一个", text: $cloudHosts, axis: .vertical)
                            .lineLimit(2...4)
                            .textFieldStyle(.roundedBorder)
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
                        Text("已备份原规则。请在 LuLu 菜单栏图标的 Rules 菜单中导入生成的 JSON，然后点“重新检查”。")
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
                        Text("先实测云盘取回进度，再核对 LuLu 对 1500 端口和未知 IP 的判定。仅看规则文件无法证明上传为零。")
                        Button("重新检查") { refresh() }
                        Text(message).font(.system(.caption, design: .monospaced)).textSelection(.enabled)
                    }.frame(maxWidth: .infinity, alignment: .leading).padding(8)
                }
                GroupBox("4 · 查看其他 App") {
                    VStack(alignment: .leading, spacing: 10) {
                        Text("LuLu 自带的 Netiquette 会显示所有 App 的当前连接、目标地址、端口及收发量。需要拦截某个 App 时，可在 LuLu 为它设置出站规则。")
                        HStack {
                            Button("查看所有 App 实时连接") { openNetworkMonitor() }
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
                status("LuLu 过滤进程和系统扩展", audit?.luluProviderRunning == true && audit?.luluExtensionActive == true)
                status("迅雷主程序与下载服务规则档案", audit?.components.first(where: {$0.id == "com.xunlei.Thunder"})?.fallbackBlock == true && audit?.components.first(where: {$0.id == "com.xunlei.DownloadService"})?.fallbackBlock == true)
                status("当前 DNS 服务器的 53 端口例外", audit?.dnsExceptionsPresent == true)
                status("当前云盘 CDN 的精确 IP:443 例外", audit?.cloudExceptionsPresent == true)
                status("系统防火墙", audit?.firewallOn == true)
                status("迅雷与下载服务入站规则", audit?.inboundMainBlocked == true && audit?.inboundServiceBlocked == true)
                Text("独立实测：Mini 关闭时云盘副本进度增长；LuLu 同时拒绝了 sandai.net:3076 等非云盘连接。")
                    .foregroundStyle(.secondary)
                if audit?.luluAppRunning != true { Text("⚠ LuLu 主程序未运行：请启动后再依赖迅雷拦截规则") }
                if audit?.dnsExceptionsPresent != true { Text("⚠ DNS 例外不完整：云盘取回可能停在 0%；请重新生成并导入规则") }
                if audit?.cloudExceptionsPresent != true { Text("⚠ 云盘 CDN 的 IP 例外不完整：请重新生成并导入规则") }
                if audit?.globalAllowList == true { Text("⚠ LuLu 全局放行列表可能绕过迅雷规则") }
                if audit?.localhostBypass == true { Text("⚠ LuLu 当前放行本机回环连接") }
                Text("规则档案和进程状态不能代替流量实测；不能保证识别所有加密 P2P。")
                    .font(.caption).foregroundStyle(.secondary)
            }.frame(maxWidth: .infinity, alignment: .leading).padding(8)
        }
    }

    private func status(_ title: String, _ active: Bool) -> some View {
        Text("\(active ? "●" : "○") \(title)：\(active ? "已检测" : "待完成")")
            .foregroundStyle(active ? Color.green : Color.orange)
    }

    private func run(_ args: [String]) throws -> Data {
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
        do {
            audit = try JSONDecoder().decode(GuardAudit.self, from: run(["audit"]))
            if endpoints.isEmpty { endpoints = audit?.allowEndpoints.joined(separator: "\n") ?? "" }
            if cloudHosts.isEmpty { cloudHosts = audit?.cloudHosts.joined(separator: "\n") ?? "" }
            let count = audit?.components.filter(\.fallbackBlock).count ?? 0
            message = "找到 \(audit?.components.count ?? 0) 个迅雷组件；其中 \(count) 个具有默认拦截规则。"
        } catch { message = error.localizedDescription }
    }

    private func buildRules() {
        do {
            let hosts = endpoints.split(whereSeparator: { $0 == "\n" || $0 == "," }).map(String.init)
            let clouds = cloudHosts.split(whereSeparator: { $0 == "\n" || $0 == "," }).map(String.init)
            let args = ["prepare"] + hosts.flatMap { ["--allow", $0] } + clouds.flatMap { ["--cloud-host", $0] }
            let json = try JSONSerialization.jsonObject(with: run(args)) as? [String: Any]
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
