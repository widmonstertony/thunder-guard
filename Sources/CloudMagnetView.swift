import SwiftUI
import AppKit

struct CloudMagnetView: View {
    @State private var magnet = ""
    @State private var message = ""

    private let cloudURL = URL(string: "https://pan.xunlei.com/")!

    private var isMagnet: Bool {
        let input = magnet.trimmingCharacters(in: .whitespacesAndNewlines)
        guard let parts = URLComponents(string: input), parts.scheme?.lowercased() == "magnet",
              let items = parts.queryItems else { return false }
        return items.contains { item in
            guard item.name.lowercased() == "xt", let value = item.value?.lowercased() else {
                return false
            }
            return (value.hasPrefix("urn:btih:") && value.count > "urn:btih:".count) ||
                   (value.hasPrefix("urn:btmh:") && value.count > "urn:btmh:".count)
        }
    }

    var body: some View {
        VStack(alignment: .leading, spacing: 20) {
            Label("磁力链接云添加", systemImage: "cloud.badge.plus")
                .font(.largeTitle.bold())
            Text("通过迅雷云盘网页版提交磁力链接，由云端处理种子元数据。本机迅雷的 BT 对等连接规则保持拦截。")
                .foregroundStyle(.secondary)

            GroupBox("添加链接") {
                VStack(alignment: .leading, spacing: 12) {
                    TextField("粘贴 magnet:? 链接", text: $magnet, axis: .vertical)
                        .lineLimit(3...5)
                        .textFieldStyle(.roundedBorder)
                    HStack {
                        Button("复制链接并打开云盘网页") { copyAndOpen() }
                            .disabled(!isMagnet)
                        Button("只打开云盘网页") { openCloud() }
                    }
                    Text("输入只保留在当前窗口内；点击复制后也会放到本机剪贴板，由你在迅雷云盘网页里粘贴并确认。护栏不会读取账号凭据或自行提交任务。")
                        .font(.caption).foregroundStyle(.secondary)
                    if !message.isEmpty {
                        Text(message).font(.caption).textSelection(.enabled)
                    }
                }
                .frame(maxWidth: .infinity, alignment: .leading)
                .padding(8)
            }

            GroupBox("网页操作") {
                VStack(alignment: .leading, spacing: 8) {
                    Text("1. 在已登录的迅雷云盘网页点击“添加” → “添加链接”。")
                    Text("2. 粘贴磁力链接，确认保存到“我的云盘”，再点“确定”。")
                    Text("3. 到“传输列表”核对云添加任务状态。")
                    Text("4. 从云盘取回时若停在 0%，到“迅雷规则”查看自动识别的 CDN，生成并导入规则后重试取回。")
                    Text("磁力链接可能需要 BT 网络才能获取文件清单。这里把解析交给云端；是否能成功还取决于迅雷服务和该资源是否可用。")
                        .font(.caption).foregroundStyle(.secondary)
                }
                .frame(maxWidth: .infinity, alignment: .leading)
                .padding(8)
            }
            Spacer()
        }
        .padding(24)
        .frame(minWidth: 680, minHeight: 520, alignment: .topLeading)
    }

    private func copyAndOpen() {
        guard isMagnet else { return }
        let input = magnet.trimmingCharacters(in: .whitespacesAndNewlines)
        NSPasteboard.general.clearContents()
        NSPasteboard.general.setString(input, forType: .string)
        message = "链接已复制。请在打开的网页中点击“添加” → “添加链接”，粘贴并确认。"
        openCloud()
    }

    private func openCloud() {
        if !NSWorkspace.shared.open(cloudURL) {
            message = "无法打开迅雷云盘网页，请检查默认浏览器。"
        }
    }
}
