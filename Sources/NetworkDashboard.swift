import SwiftUI
import Charts
import AppKit

private struct NetworkSnapshot: Decodable {
    let apps: [NetworkApp]
}

private struct NetworkApp: Decodable, Identifiable {
    let pid: Int
    let name: String
    let received: Int64
    let sent: Int64
    let connections: [NetworkConnection]
    var id: Int { pid }
}

private struct NetworkConnection: Decodable {
    let `protocol`: String
    let local: String
    let remote: String
    let port: String
    let state: String
    let interface: String
    let scope: String
    let received: Int64
    let sent: Int64
}

private struct TransferRate {
    let down: Double
    let up: Double
    static let zero = TransferRate(down: 0, up: 0)
}

private struct TrafficPoint: Identifiable {
    let id = UUID()
    let time: Date
    let down: Double
    let up: Double
}

private final class NetworkStore: ObservableObject {
    @Published var apps: [NetworkApp] = []
    @Published var rates: [Int: TransferRate] = [:]
    @Published var totalRate: TransferRate = .zero
    @Published var history: [TrafficPoint] = []
    @Published var lastUpdated: Date?
    @Published var error: String?
    @Published var isSampling = false

    private var previous: [Int: (down: Int64, up: Int64)] = [:]
    private var previousTime: Date?

    func refresh() {
        guard !isSampling else { return }
        isSampling = true
        let script = Bundle.main.resourceURL!.appendingPathComponent("network_snapshot.py")
        DispatchQueue.global(qos: .utility).async {
            do {
                let process = Process()
                process.executableURL = URL(fileURLWithPath: "/usr/bin/python3")
                process.arguments = [script.path]
                let pipe = Pipe()
                process.standardOutput = pipe
                process.standardError = pipe
                try process.run()
                let output = pipe.fileHandleForReading.readDataToEndOfFile()
                process.waitUntilExit()
                guard process.terminationStatus == 0 else {
                    let detail = String(data: output, encoding: .utf8) ?? "采样失败"
                    throw NSError(domain: "NetworkDashboard", code: Int(process.terminationStatus),
                                  userInfo: [NSLocalizedDescriptionKey: detail])
                }
                let snapshot = try JSONDecoder().decode(NetworkSnapshot.self, from: output)
                DispatchQueue.main.async { self.accept(snapshot) }
            } catch {
                DispatchQueue.main.async {
                    self.error = error.localizedDescription
                    self.isSampling = false
                }
            }
        }
    }

    private func accept(_ snapshot: NetworkSnapshot) {
        let now = Date()
        let seconds = max(now.timeIntervalSince(previousTime ?? now), 0.1)
        var next: [Int: (down: Int64, up: Int64)] = [:]
        var currentRates: [Int: TransferRate] = [:]
        var down = 0.0
        var up = 0.0
        for app in snapshot.apps {
            next[app.pid] = (app.received, app.sent)
            guard let old = previous[app.pid], previousTime != nil else {
                currentRates[app.pid] = .zero
                continue
            }
            let rate = TransferRate(down: Double(max(0, app.received - old.down)) / seconds,
                                    up: Double(max(0, app.sent - old.up)) / seconds)
            currentRates[app.pid] = rate
            down += rate.down
            up += rate.up
        }
        previous = next
        previousTime = now
        apps = snapshot.apps
        rates = currentRates
        totalRate = TransferRate(down: down, up: up)
        history.append(TrafficPoint(time: now, down: down, up: up))
        if history.count > 60 { history.removeFirst(history.count - 60) }
        lastUpdated = now
        error = nil
        isSampling = false
    }
}

struct NetworkDashboardView: View {
    @StateObject private var store = NetworkStore()
    @State private var search = ""
    @State private var internetOnly = true
    @State private var selectedPID: Int?

    private var visibleApps: [NetworkApp] {
        store.apps.filter { app in
            let hasFlow = app.connections.contains { !internetOnly || $0.scope == "internet" }
            let matches = search.isEmpty || displayName(app).localizedCaseInsensitiveContains(search)
                || app.name.localizedCaseInsensitiveContains(search)
                || String(app.pid).contains(search)
                || app.connections.contains { $0.remote.localizedCaseInsensitiveContains(search) }
            return hasFlow && matches
        }.sorted {
            let left = store.rates[$0.pid] ?? .zero
            let right = store.rates[$1.pid] ?? .zero
            if left.down + left.up != right.down + right.up {
                return left.down + left.up > right.down + right.up
            }
            return $0.name.localizedCaseInsensitiveCompare($1.name) == .orderedAscending
        }
    }

    private var selectedApp: NetworkApp? {
        visibleApps.first(where: { $0.pid == selectedPID }) ?? visibleApps.first
    }

    private var visibleConnections: [NetworkConnection] {
        (selectedApp?.connections ?? []).filter { !internetOnly || $0.scope == "internet" }
            .sorted { $0.sent + $0.received > $1.sent + $1.received }
    }

    var body: some View {
        VStack(alignment: .leading, spacing: 14) {
            HStack(alignment: .top) {
                VStack(alignment: .leading, spacing: 3) {
                    Text("网络总览").font(.largeTitle.bold())
                    Text("所有 App 的实时连接 · 每 3 秒采样")
                        .foregroundStyle(.secondary)
                }
                Spacer()
                if let time = store.lastUpdated {
                    Text("更新于 \(time, format: .dateTime.hour().minute().second())")
                        .font(.caption).foregroundStyle(.secondary)
                }
                Button("立即刷新") { store.refresh() }
            }
            HStack(spacing: 16) {
                metric("下载速度", value: store.totalRate.down, color: .cyan, symbol: "arrow.down")
                metric("上传速度", value: store.totalRate.up, color: .orange, symbol: "arrow.up")
                VStack(alignment: .leading, spacing: 4) {
                    Text("可见进程").font(.caption).foregroundStyle(.secondary)
                    Text("\(visibleApps.count)").font(.title2.bold())
                    Text("\(store.apps.reduce(0) { $0 + $1.connections.count }) 条连接")
                        .font(.caption).foregroundStyle(.secondary)
                }
                .frame(maxWidth: .infinity, alignment: .leading)
                .padding(14)
                .background(.quaternary.opacity(0.35), in: RoundedRectangle(cornerRadius: 12))
            }
            Chart {
                ForEach(store.history) { point in
                    LineMark(x: .value("时间", point.time), y: .value("速度", point.down),
                             series: .value("方向", "下载"))
                        .foregroundStyle(Color.cyan)
                }
                ForEach(store.history) { point in
                    LineMark(x: .value("时间", point.time), y: .value("速度", point.up),
                             series: .value("方向", "上传"))
                        .foregroundStyle(Color.orange)
                }
            }
            .chartYScale(domain: .automatic(includesZero: true))
            .chartYAxis {
                AxisMarks(position: .trailing) { value in
                    AxisGridLine()
                    AxisValueLabel {
                        if let amount = value.as(Double.self) { Text(rateText(amount)) }
                    }
                }
            }
            .frame(height: 145)
            .padding(12)
            .background(.quaternary.opacity(0.25), in: RoundedRectangle(cornerRadius: 12))

            HStack(spacing: 10) {
                Image(systemName: "magnifyingglass").foregroundStyle(.secondary)
                TextField("搜索 App、PID 或目标地址", text: $search)
                    .textFieldStyle(.roundedBorder)
                Toggle("仅外网", isOn: $internetOnly)
                    .toggleStyle(.switch)
                    .fixedSize()
                Button("LuLu 规则") { openLuLuRules() }
            }

            HStack(alignment: .top, spacing: 12) {
                appList
                    .frame(width: 300)
                connectionPanel
                    .frame(maxWidth: .infinity, maxHeight: .infinity)
            }
            .frame(maxHeight: .infinity)

            if let error = store.error {
                Text("采样失败：\(error)").foregroundStyle(.red).font(.caption)
            } else {
                Text("速度由两次采样的累计字节差计算；连接列表显示当前采样。地址与端口不能单独证明是否为 P2P，拦截状态以 LuLu 规则和日志为准。")
                    .foregroundStyle(.secondary).font(.caption)
            }
        }
        .padding(18)
        .frame(minWidth: 960, minHeight: 650)
        .onAppear { store.refresh() }
        .onReceive(Timer.publish(every: 3, on: .main, in: .common).autoconnect()) { _ in
            store.refresh()
        }
    }

    private func metric(_ title: String, value: Double, color: Color, symbol: String) -> some View {
        VStack(alignment: .leading, spacing: 4) {
            Label(title, systemImage: symbol).font(.caption).foregroundStyle(color)
            Text(rateText(value)).font(.title2.bold().monospacedDigit())
        }
        .frame(maxWidth: .infinity, alignment: .leading)
        .padding(14)
        .background(.quaternary.opacity(0.35), in: RoundedRectangle(cornerRadius: 12))
    }

    private var appList: some View {
        VStack(alignment: .leading, spacing: 8) {
            Text("应用与进程").font(.headline).padding(.horizontal, 8)
            ScrollView {
                LazyVStack(spacing: 4) {
                    ForEach(visibleApps) { app in
                        let rate = store.rates[app.pid] ?? .zero
                        Button {
                            selectedPID = app.pid
                        } label: {
                            HStack(spacing: 9) {
                                if let icon = NSRunningApplication(processIdentifier: pid_t(app.pid))?.icon {
                                    Image(nsImage: icon).resizable().frame(width: 30, height: 30)
                                } else {
                                    Image(systemName: "app.fill")
                                        .frame(width: 30, height: 30).foregroundStyle(.secondary)
                                }
                                VStack(alignment: .leading, spacing: 2) {
                                    Text(displayName(app)).lineLimit(1).font(.subheadline.weight(.medium))
                                    Text("PID \(app.pid) · \(app.connections.count) 条连接")
                                        .font(.caption2).foregroundStyle(.secondary)
                                }
                                Spacer(minLength: 4)
                                VStack(alignment: .trailing, spacing: 2) {
                                    Text("↓ \(rateText(rate.down))").foregroundStyle(.cyan)
                                    Text("↑ \(rateText(rate.up))").foregroundStyle(.orange)
                                }
                                .font(.caption2.monospacedDigit())
                            }
                            .padding(8)
                            .background(selectedApp?.pid == app.pid ? Color.accentColor.opacity(0.20) : Color.clear,
                                        in: RoundedRectangle(cornerRadius: 9))
                            .contentShape(Rectangle())
                        }
                        .buttonStyle(.plain)
                    }
                }
            }
        }
        .padding(8)
        .background(.quaternary.opacity(0.2), in: RoundedRectangle(cornerRadius: 12))
    }

    private var connectionPanel: some View {
        VStack(alignment: .leading, spacing: 10) {
            if let app = selectedApp {
                HStack {
                    VStack(alignment: .leading, spacing: 2) {
                        Text(displayName(app)).font(.title3.bold())
                        Text("PID \(app.pid) · 累计接收 \(byteText(app.received)) · 累计发送 \(byteText(app.sent))")
                            .font(.caption).foregroundStyle(.secondary)
                    }
                    Spacer()
                    Text("\(visibleConnections.count) 条连接")
                        .font(.caption).foregroundStyle(.secondary)
                }
                Divider()
                HStack {
                    Text("目标地址 / 端口").frame(maxWidth: .infinity, alignment: .leading)
                    Text("协议").frame(width: 60)
                    Text("状态").frame(width: 85)
                    Text("已收 / 已发").frame(width: 145, alignment: .trailing)
                }
                .font(.caption.weight(.semibold)).foregroundStyle(.secondary)
                ScrollView {
                    LazyVStack(spacing: 0) {
                        ForEach(Array(visibleConnections.enumerated()), id: \.offset) { _, flow in
                            HStack(spacing: 6) {
                                VStack(alignment: .leading, spacing: 2) {
                                    Text(flow.remote + (flow.port.isEmpty ? "" : ":" + flow.port))
                                        .lineLimit(1).textSelection(.enabled)
                                    Text(flow.interface + " · " + scopeName(flow.scope))
                                        .font(.caption2).foregroundStyle(.secondary)
                                }
                                .frame(maxWidth: .infinity, alignment: .leading)
                                Text(flow.protocol).frame(width: 60)
                                Text(flow.state.isEmpty ? "—" : flow.state)
                                    .lineLimit(1).frame(width: 85)
                                Text("↓\(byteText(flow.received))  ↑\(byteText(flow.sent))")
                                    .frame(width: 145, alignment: .trailing)
                            }
                            .font(.caption.monospacedDigit())
                            .padding(.vertical, 6)
                            Divider()
                        }
                    }
                }
            } else {
                ContentUnavailableView("暂无连接", systemImage: "network",
                                       description: Text("等待采样，或关闭“仅外网”查看本地连接"))
                    .frame(maxWidth: .infinity, maxHeight: .infinity)
            }
        }
        .padding(12)
        .background(.quaternary.opacity(0.2), in: RoundedRectangle(cornerRadius: 12))
    }

    private func openLuLuRules() {
        let config = NSWorkspace.OpenConfiguration()
        config.arguments = ["-rules"]
        NSWorkspace.shared.openApplication(at: URL(fileURLWithPath: "/Applications/LuLu.app"), configuration: config) { _, _ in }
    }

    private func rateText(_ value: Double) -> String {
        if value < 1 { return "0 B/s" }
        return ByteCountFormatter.string(fromByteCount: Int64(value), countStyle: .binary) + "/s"
    }

    private func displayName(_ app: NetworkApp) -> String {
        NSRunningApplication(processIdentifier: pid_t(app.pid))?.localizedName ?? app.name
    }

    private func byteText(_ value: Int64) -> String {
        ByteCountFormatter.string(fromByteCount: value, countStyle: .binary)
    }

    private func scopeName(_ scope: String) -> String {
        switch scope {
        case "internet": return "外网"
        case "local": return "局域网"
        case "loopback": return "本机"
        default: return "未知"
        }
    }
}
