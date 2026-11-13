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
    var showProtectionDetails: () -> Void = {}
    @EnvironmentObject private var protection: ProtectionStore
    @StateObject private var store = NetworkStore()
    @StateObject private var decisions = DecisionStore()
    @State private var search = ""
    @State private var internetOnly = true
    @State private var selectedPID: Int?
    @State private var showingBlocked = false

    private var visibleBlocks: [ConnectionDecision] {
        decisions.blocked.filter { search.isEmpty || $0.appName.localizedCaseInsensitiveContains(search)
            || $0.processPath.localizedCaseInsensitiveContains(search) || $0.address.localizedCaseInsensitiveContains(search) }
    }

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
                    Text("网络连接").font(.largeTitle.bold())
                    Text("查看应用在连接哪里，以及哪些连接被拒绝")
                        .foregroundStyle(.secondary)
                }
                Spacer()
                if let time = store.lastUpdated {
                    Text("更新于 \(time, format: .dateTime.hour().minute().second())")
                        .font(.caption).foregroundStyle(.secondary)
                }
                Button { store.refresh(); protection.refresh() } label: { Image(systemName: "arrow.clockwise") }
                    .help("刷新连接和保护状态")
            }
            protectionCard
            HStack(spacing: 16) {
                metric("下载速度", value: store.totalRate.down, color: .cyan, symbol: "arrow.down")
                metric("上传速度", value: store.totalRate.up, color: .orange, symbol: "arrow.up")
                VStack(alignment: .leading, spacing: 4) {
                    Text("联网应用 / 进程").font(.caption).foregroundStyle(.secondary)
                    Text("\(visibleApps.count)").font(.title2.bold())
                    Text("\(store.apps.reduce(0) { $0 + $1.connections.count }) 条连接 · \(decisions.blocked.count) 条拦截记录")
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
            .frame(height: 100)
            .padding(12)
            .background(.quaternary.opacity(0.25), in: RoundedRectangle(cornerRadius: 12))

            HStack(spacing: 10) {
                Image(systemName: "magnifyingglass").foregroundStyle(.secondary)
                TextField("搜索 App、PID 或目标地址", text: $search)
                    .textFieldStyle(.roundedBorder)
                Picker("连接类型", selection: $showingBlocked) {
                    Text("当前连接").tag(false)
                    Text("已拦截 \(decisions.blocked.count)").tag(true)
                }.pickerStyle(.segmented).frame(width: 240)
                Toggle("仅外网", isOn: $internetOnly)
                    .toggleStyle(.switch)
                    .fixedSize()
                    .disabled(showingBlocked)
            }

            if showingBlocked {
                blockedPanel.frame(maxWidth: .infinity, maxHeight: .infinity)
            } else {
                HStack(alignment: .top, spacing: 12) {
                    appList.frame(width: 300)
                    connectionPanel.frame(maxWidth: .infinity, maxHeight: .infinity)
                }.frame(maxHeight: .infinity)
            }

            if let error = store.error {
                Text("采样失败：\(error)").foregroundStyle(.red).font(.caption)
            } else {
                Text("实时连接每 3 秒更新。拦截记录来自 LuLu 的实际判定，仅保留本次打开后的最近 200 条；未出现记录不表示没有被拦截。")
                    .foregroundStyle(.secondary).font(.caption)
            }
        }
        .padding(18)
        .frame(minWidth: 960, minHeight: 650)
        .onAppear { store.refresh(); decisions.start() }
        .onDisappear { decisions.stop() }
        .onReceive(Timer.publish(every: 3, on: .main, in: .common).autoconnect()) { _ in
            store.refresh()
        }
    }

    private var protectionCard: some View {
        HStack(spacing: 12) {
            Image(systemName: protection.snapshot?.protectionRunning == true ? "shield.lefthalf.filled" : "shield.slash")
                .font(.title2)
                .foregroundStyle(protection.snapshot == nil ? Color.secondary : protection.snapshot?.protectionRunning == true ? .green : .orange)
            VStack(alignment: .leading, spacing: 3) {
                Text(protection.title).font(.headline)
                Text(protection.detail).font(.caption).foregroundStyle(.secondary)
            }
            Spacer()
            if let snapshot = protection.snapshot, !snapshot.activeCloudHosts.isEmpty {
                VStack(alignment: .trailing, spacing: 3) {
                    Text("云盘任务源站 \(byteText(snapshot.activeCloudCounters.origin))").font(.caption)
                    Text("迅雷自报 P2P \(byteText(snapshot.activeCloudCounters.p2p)) · DCDN \(byteText(snapshot.activeCloudCounters.dcdn))")
                        .font(.caption2).foregroundStyle(.secondary)
                }
            }
            Button("详情", action: showProtectionDetails)
        }.padding(14)
            .background(.quaternary.opacity(0.28), in: RoundedRectangle(cornerRadius: 12))
    }

    private var blockedPanel: some View {
        VStack(alignment: .leading, spacing: 10) {
            HStack {
                Label("已拒绝的连接", systemImage: "hand.raised.fill").foregroundStyle(.red).font(.headline)
                Spacer()
                if !decisions.listening { Button("重试记录") { decisions.start() } }
                Text("仅本次打开期间").font(.caption).foregroundStyle(.secondary)
            }
            if let error = decisions.error { Text(error).font(.caption).foregroundStyle(.orange) }
            if visibleBlocks.isEmpty {
                ContentUnavailableView("尚无可见拦截记录", systemImage: "shield",
                    description: Text("等待 LuLu 拒绝新的连接。这里不会根据端口猜测拦截结果。"))
                    .frame(maxWidth: .infinity, maxHeight: .infinity)
            } else {
                ScrollView {
                    LazyVStack(spacing: 0) {
                        ForEach(visibleBlocks) { item in
                            HStack(spacing: 12) {
                                Image(systemName: "xmark.circle.fill").foregroundStyle(.red)
                                VStack(alignment: .leading, spacing: 3) {
                                    Text(item.appName).font(.subheadline.weight(.medium))
                                    Text(item.address + ":" + item.port).font(.caption.monospaced()).textSelection(.enabled)
                                }
                                Spacer()
                                Text("已拒绝").font(.caption).foregroundStyle(.red)
                                Text(item.time, format: .dateTime.hour().minute().second()).font(.caption.monospacedDigit()).foregroundStyle(.secondary)
                            }.padding(.vertical, 9)
                            Divider()
                        }
                    }
                }
            }
        }.padding(14).background(.quaternary.opacity(0.2), in: RoundedRectangle(cornerRadius: 12))
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
