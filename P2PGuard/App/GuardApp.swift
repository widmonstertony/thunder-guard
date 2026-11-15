import AppKit
import Charts
import SwiftUI

@main struct GuardApp: App {
    static let support = URL(string: "https://github.com/widmonstertony/thunder-guard/issues")!
    @StateObject private var control = FilterControl()

    var body: some Scene {
        WindowGroup("P2P 护栏") {
            GuardDashboard(control: control)
                .frame(minWidth: 960, minHeight: 610)
        }
        .defaultSize(width: 1220, height: 740)
        .windowStyle(.titleBar)
        .commands {
            CommandGroup(replacing: .help) { Link("GitHub 支持与问题反馈", destination: Self.support) }
        }
    }
}

private enum Selection: Hashable { case all, thunder, process(Int32) }
private enum ViewMode: String, CaseIterable { case connections = "连接", blocked = "拦截" }
private enum VerdictKind: String, CaseIterable {
    case upload = "BT 上传", download = "BT 下载", other = "其他拒绝"
    var symbol: String {
        switch self { case .upload: "arrow.up"; case .download: "arrow.down"; case .other: "hand.raised" }
    }
    var color: Color {
        switch self { case .upload: .orange; case .download: .pink; case .other: .secondary }
    }
    func includes(_ event: BlockEvent) -> Bool {
        switch self {
        case .upload: event.isFile && event.direction == .upload
        case .download: event.isFile && event.direction == .download
        case .other: !event.isFile
        }
    }
}
private struct Sample: Identifiable {
    let id = Date()
    let received: Double
    let sent: Double
}

private struct GuardDashboard: View {
    @ObservedObject var control: FilterControl
    @StateObject private var activity = Activity()
    @State private var selection: Selection? = .thunder
    @State private var mode: ViewMode = .blocked
    @State private var search = ""
    @State private var previous: [Int32: Totals] = [:]
    @State private var history: [Sample] = []
    @State private var confirmIP = false
    @State private var showPolicy = false
    @State private var region: String?
    @State private var verdictKind: VerdictKind?
    private struct Totals { var received: Int64 = 0; var sent: Int64 = 0 }

    private var title: String {
        switch selection {
        case .thunder: "迅雷"
        case .process(let pid): activity.processes.first(where: { $0.id == pid })?.name ?? "已退出的进程"
        default: "全部 App"
        }
    }
    private var processes: [NetworkProcess] {
        activity.processes.filter { process in
            switch selection {
            case .thunder: process.thunder
            case .process(let pid): process.id == pid
            default: true
            }
        }
    }
    private var baseConnections: [AppConnection] {
        processes.flatMap(\.connections).filter { search.isEmpty || $0.endpoint.localizedCaseInsensitiveContains(search) }
            .sorted { $0.received + $0.sent > $1.received + $1.sent }
    }
    private var baseEvents: [BlockEvent] {
        if case .process = selection { return [] }
        return activity.events.filter {
            // Controlled developer probes must not appear as real app activity.
            !$0.process.hasPrefix("GuardPeer-") &&
            (search.isEmpty || $0.address.localizedCaseInsensitiveContains(search) ||
             $0.process.localizedCaseInsensitiveContains(search) ||
             $0.verdictTitle.localizedCaseInsensitiveContains(search))
        }
    }
    private var connections: [AppConnection] {
        guard let region else { return baseConnections }
        return baseConnections.filter { NetworkGeography.code(for: $0.endpoint) == region }
    }
    private var events: [BlockEvent] {
        guard let region else { return baseEvents }
        return baseEvents.filter { NetworkGeography.code(for: $0.address) == region }
    }
    private var regions: [RouteGroup] {
        var groups: [String: RouteGroup] = [:]
        for item in baseConnections {
            let key = NetworkGeography.code(for: item.endpoint)
            groups[key, default: RouteGroup(id: key)].observed += 1
        }
        for item in baseEvents where verdictKind?.includes(item) != false || mode == .connections {
            let key = NetworkGeography.code(for: item.address)
            groups[key, default: RouteGroup(id: key)].blocked += 1
        }
        return groups.values.sorted { $0.id < $1.id }
    }
    private var split: some View {
        NavigationSplitView {
            List(selection: $selection) {
                Section("监控") {
                    Label("全部 App", systemImage: "square.grid.2x2").tag(Selection.all)
                    Label("迅雷", systemImage: "shield.lefthalf.filled").tag(Selection.thunder)
                }
                Section("联网进程") {
                    ForEach(activity.processes.filter { !$0.thunder }) { process in
                        HStack(spacing: 8) {
                            if let icon = NSRunningApplication(processIdentifier: process.id)?.icon {
                                Image(nsImage: icon).resizable().frame(width: 20, height: 20)
                            } else { Image(systemName: "app").frame(width: 20) }
                            Text(process.name).lineLimit(1)
                            Spacer()
                            Text(process.connections.count, format: .number).foregroundStyle(.secondary).monospacedDigit()
                        }.tag(Selection.process(process.id))
                    }
                }
            }
            .listStyle(.sidebar)
            .navigationSplitViewColumnWidth(min: 170, ideal: 196, max: 270)
        } detail: {
            VStack(alignment: .leading, spacing: 0) {
                header.padding(.bottom, 16)
                HStack(alignment: .top, spacing: 16) {
                    VStack(alignment: .leading, spacing: 8) {
                        NetworkMap(groups: regions, selection: $region)
                            .frame(maxWidth: .infinity, maxHeight: .infinity)
                        HStack(spacing: 5) {
                            Text("按 IP 估算国家或地区")
                            if NetworkGeography.hasData {
                                Text("·")
                                Link("IP Geolocation by DB-IP", destination: URL(string: "https://db-ip.com/")!)
                            } else {
                                Text("· 暂无离线定位数据")
                            }
                        }.font(.caption2).foregroundStyle(.secondary)
                    }
                    inspector.frame(minWidth: 274, idealWidth: 318, maxWidth: 355)
                }
                if mode == .connections { chart.padding(.top, 10) }
            }
            .padding(.horizontal, 18).padding(.top, 16).padding(.bottom, 12)
            .navigationTitle(title)
        }
    }
    var body: some View {
        split.searchable(text: $search, placement: .toolbar, prompt: "搜索目标地址")
            .toolbar {
                ToolbarItem(placement: .primaryAction) {
                    Link(destination: GuardApp.support) { Label("GitHub 支持", systemImage: "questionmark.circle") }
                }
            }
            .task {
                activity.start()
                while !Task.isCancelled {
                    await control.load()
                    await activity.sample()
                    recordSample()
                    try? await Task.sleep(for: .seconds(3))
                }
            }
            .onDisappear { activity.stop() }
            .onChange(of: selection) { _, _ in
                region = nil; verdictKind = nil; history = []; previous = [:]; recordSample()
            }
            .confirmationDialog("限制迅雷的 IP 位址连接？", isPresented: $confirmIP, titleVisibility: .visible) {
                Button("启用 IP 位址规则") { control.change(bt: control.enabled, ip: true) }
                Button("取消", role: .cancel) {}
            } message: { Text("放行已识别的域名服务和标准磁力清单。直连时拦截文件数据和无法识别的协议。") }
    }
    private var header: some View {
        HStack(alignment: .center) {
            VStack(alignment: .leading, spacing: 4) {
                Text(selection == .thunder ? "迅雷网络活动" : title).font(.title2.bold())
                if selection == .thunder {
                    let enabled = control.directIP || control.enabled
                    Label(control.directIP ? "IP 位址规则已启用" : enabled ? "BT 文件规则已启用" : "拦截规则未启用",
                          systemImage: enabled ? "checkmark.shield" : "shield")
                        .font(.callout).foregroundStyle(enabled ? Color.green : .secondary)
                } else {
                    Text("查看各 App 的连接去向").font(.callout).foregroundStyle(.secondary)
                }
            }
            Spacer()
            if selection == .thunder {
                let enabled = control.enabled || control.directIP
                Button { showPolicy.toggle() } label: {
                    Label(enabled ? "防护设置" : "开启防护", systemImage: enabled ? "shield.lefthalf.filled" : "shield")
                }.popover(isPresented: $showPolicy, arrowEdge: .bottom) {
                    policies.frame(width: 340).padding(12)
                }
                .accessibilityHint(activity.observedThunder ? "最近已收到迅雷连接" : "尚未观察到新的迅雷连接")
            }
        }
    }

    private var inspector: some View {
        VStack(alignment: .leading, spacing: 12) {
            HStack {
                Text(region.map(NetworkGeography.title) ?? "网络记录").font(.headline)
                Spacer()
                if region != nil {
                    Button("全部") { region = nil }.buttonStyle(.borderless)
                }
            }
            Picker("网络记录", selection: $mode) {
                ForEach(ViewMode.allCases, id: \.self) { Text($0.rawValue).tag($0) }
            }.pickerStyle(.segmented).labelsHidden()
            if mode == .blocked {
                HStack(spacing: 6) {
                    ForEach(VerdictKind.allCases, id: \.self) { kind in
                        verdictCount(kind, events.filter(kind.includes).count)
                    }
                }
                eventList(events.filter { verdictKind?.includes($0) != false })
                Text("近 10 分钟 · 最多 250 条护栏记录").font(.caption2).foregroundStyle(.secondary)
            } else {
                connectionList
                Text("可见连接不代表护栏已放行。").font(.caption2).foregroundStyle(.secondary)
            }
        }
        .padding(12)
        .background(.quaternary.opacity(0.26), in: .rect(cornerRadius: 18))
    }

    private func verdictCount(_ kind: VerdictKind, _ n: Int) -> some View {
        Button {
            verdictKind = verdictKind == kind ? nil : kind
        } label: {
            VStack(alignment: .leading, spacing: 4) {
                Label(kind.rawValue, systemImage: kind.symbol).font(.caption2).lineLimit(1).foregroundStyle(.secondary)
                Text("\(n)").font(.title3.weight(.semibold).monospacedDigit()).foregroundStyle(n == 0 ? .secondary : kind.color)
            }.frame(maxWidth: .infinity, alignment: .leading).padding(8)
             .background(.background.opacity(0.55), in: .rect(cornerRadius: 10))
             .overlay(RoundedRectangle(cornerRadius: 10).strokeBorder(kind.color.opacity(verdictKind == kind ? 0.75 : 0.0)))
        }.buttonStyle(.plain)
         .accessibilityLabel("\(kind.rawValue)，\(n) 条")
         .accessibilityAddTraits(verdictKind == kind ? .isSelected : [])
    }
    private var policies: some View {
        GroupBox {
            VStack(alignment: .leading, spacing: 8) {
                Toggle(isOn: Binding(get: { control.enabled }, set: { control.change(bt: $0, ip: control.directIP) })) {
                    Label("拦截已识别的 BT 文件上传和下载", systemImage: "arrow.up.arrow.down")
                }
                Divider()
                Toggle(isOn: Binding(get: { control.directIP }, set: { if $0 { confirmIP = true } else { control.change(bt: control.enabled, ip: false) } })) {
                    Label("IP 位址 · 直连仅允许获取清单", systemImage: "globe")
                }
                if control.enabled || control.directIP {
                    Button("重新应用当前规则") {
                        control.change(bt: control.enabled, ip: control.directIP)
                    }
                }
                Text(control.note ?? "IP 位址规则允许标准清单，拒绝文件块和无法识别的直连。")
                    .font(.caption).foregroundStyle(.secondary)
            }.padding(5).toggleStyle(.switch).disabled(control.busy)
        }
    }
    private var chart: some View {
        VStack(alignment: .leading, spacing: 4) {
            HStack(spacing: 17) {
                Label(bytes(Int64(history.last?.received ?? 0)) + " 下载", systemImage: "arrow.down").foregroundStyle(.cyan)
                Label(bytes(Int64(history.last?.sent ?? 0)) + " 上传", systemImage: "arrow.up").foregroundStyle(.orange)
                Spacer()
                Text("每次采样间隔的流量").foregroundStyle(.secondary)
            }.font(.caption.monospacedDigit())
            Chart(history) { point in
                AreaMark(x: .value("时间", point.id), y: .value("字节", point.received), series: .value("方向", "下载"))
                    .foregroundStyle(.cyan.opacity(0.25))
                LineMark(x: .value("时间", point.id), y: .value("字节", point.received), series: .value("方向", "下载")).foregroundStyle(.cyan)
                LineMark(x: .value("时间", point.id), y: .value("字节", point.sent), series: .value("方向", "上传")).foregroundStyle(.orange)
            }.chartXAxis(.hidden).chartYAxis(.hidden).frame(height: 48)
        }
    }
    private var connectionList: some View {
        Group {
            if connections.isEmpty {
                ContentUnavailableView("暂无可见连接", systemImage: "network", description: Text(activity.status ?? "有新的网络活动时会更新。"))
            } else {
                List(Array(connections.enumerated()), id: \.offset) { _, item in
                    HStack {
                        Label(item.endpoint, systemImage: "globe").lineLimit(1).textSelection(.enabled)
                        Spacer()
                        Text(item.protocolName.uppercased()).font(.caption)
                        Text("↓ \(bytes(item.received))   ↑ \(bytes(item.sent))").frame(width: 160, alignment: .trailing)
                    }.font(.callout.monospacedDigit()).foregroundStyle(.primary)
                }.listStyle(.inset)
            }
        }.frame(maxWidth: .infinity, maxHeight: .infinity)
    }
    private func eventList(_ shown: [BlockEvent]) -> some View {
        Group {
            if shown.isEmpty {
                ContentUnavailableView("没有匹配的拒绝记录", systemImage: "shield", description: Text("未观察到拦截不代表没有 P2P 活动。"))
            } else {
                List(shown) { event in
                    HStack(spacing: 12) {
                        Image(systemName: event.isFile ? (event.direction == .upload ? "arrow.up.circle.fill" : "arrow.down.circle.fill") : "hand.raised.fill")
                            .foregroundStyle(event.isFile ? .red : .orange)
                        VStack(alignment: .leading, spacing: 3) {
                            Text(event.verdictTitle).font(.callout.weight(.semibold))
                            Text(event.rationale).font(.caption).foregroundStyle(.secondary)
                            Text(event.endpoint).font(.caption.monospacedDigit()).foregroundStyle(.secondary).textSelection(.enabled)
                            Text(event.process).font(.caption2).foregroundStyle(.tertiary)
                        }
                        Spacer()
                        Text(Date(timeIntervalSince1970: event.timestamp), format: .dateTime.hour().minute().second())
                            .foregroundStyle(.secondary).font(.caption.monospacedDigit())
                    }.padding(.vertical, 3)
                }.listStyle(.plain).scrollContentBackground(.hidden)
            }
        }.frame(maxWidth: .infinity, maxHeight: .infinity)
    }
    private func bytes(_ count: Int64) -> String { ByteCountFormatter.string(fromByteCount: count, countStyle: .file) }
    private func recordSample() {
        var next: [Int32: Totals] = [:]
        var delta = Totals()
        for process in processes {
            let totals = process.connections.reduce(into: Totals()) { $0.received += $1.received; $0.sent += $1.sent }
            next[process.id] = totals
            if let old = previous[process.id] {
                delta.received += max(0, totals.received - old.received)
                delta.sent += max(0, totals.sent - old.sent)
            }
        }
        previous = next
        history.append(Sample(received: Double(delta.received), sent: Double(delta.sent)))
        if history.count > 40 { history.removeFirst(history.count - 40) }
    }
}
