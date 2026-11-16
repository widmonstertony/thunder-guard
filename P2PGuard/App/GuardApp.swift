import AppKit
import Charts
import SwiftUI
import UniformTypeIdentifiers

@main struct GuardApp: App {
    static let support = URL(string: "https://github.com/widmonstertony/thunder-guard/issues")!
    static let privacy = URL(string: "https://github.com/widmonstertony/thunder-guard/blob/main/P2PGuard/Store/PRIVACY.md")!
    @StateObject private var control = FilterControl()
    @StateObject private var activity = Activity()
    @StateObject private var meter = NetworkMeter()
    @AppStorage("showNetworkMenu") private var showNetworkMenu = true
    @NSApplicationDelegateAdaptor(DockPresence.self) private var dock

    var body: some Scene {
        Window("TonTon P2PGuard", id: "dashboard") {
            GuardDashboard(control: control, activity: activity)
                .frame(minWidth: 960, minHeight: 610)
                .background(DockWindowAnchor(dock: dock))
        }
        .defaultSize(width: 1220, height: 740)
        .windowStyle(.titleBar)
        .commands {
            CommandGroup(replacing: .help) {
                Link("GitHub 支持与问题反馈", destination: Self.support)
#if PG_STORE
                Link("隐私政策", destination: Self.privacy)
#endif
            }
        }
        MenuBarExtra(isInserted: $showNetworkMenu) {
            NetworkMenu(meter: meter, activity: activity, control: control, dock: dock)
        } label: {
            NetworkMenuLabel(meter: meter, activity: activity)
        }.menuBarExtraStyle(.window)
        Settings {
            Form {
                Toggle("在菜单栏显示下载和上传速度", isOn: $showNetworkMenu)
#if PG_STORE
                Link("隐私政策", destination: Self.privacy)
#endif
            }.padding(20).frame(width: 400)
                .background(DockWindowAnchor(dock: dock))
                .onChange(of: showNetworkMenu) { _, _ in dock.update() }
        }
    }
}

private enum Selection: Hashable { case all, app(String) }
private enum ViewMode: String, CaseIterable { case connections = "连接", blocked = "拦截" }
enum VerdictKind: String, CaseIterable {
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
private struct DisplayedConnection {
    let socket: AppConnection
    let appName: String
}

private struct GuardDashboard: View {
    @ObservedObject var control: FilterControl
    @ObservedObject var activity: Activity
    @State private var selection: Selection? = .all
    @State private var mode: ViewMode = .connections
    @State private var search = ""
    @State private var previous: [Int32: Totals] = [:]
    @State private var history: [Sample] = []
    @State private var confirmIP = false
    @State private var showPolicy = false
    @State private var region: String?
    @State private var verdictKind: VerdictKind?
    @State private var choosingApp = false
    @State private var appPickerMessage: String?
    @AppStorage("watchedApps") private var watchedApps = ""
    private struct Totals { var received: Int64 = 0; var sent: Int64 = 0 }

    private var catalog: [String: MonitoredApp] {
        var result: [String: MonitoredApp] = [:]
        for app in activity.runningApps { result[app.id] = app }
        for process in activity.processes {
            let id = process.groupID
            if result[id] == nil {
                let running = NSRunningApplication(processIdentifier: process.id)
                result[id] = MonitoredApp(id: id, name: running?.localizedName ?? process.name,
                                          appID: process.appID, icon: running?.icon)
            }
            result[id]?.processes.append(process)
        }
        func offline(_ appID: String?, group: String, fallback: String) {
            guard result[group] == nil else { return }
            let url = appID.flatMap { NSWorkspace.shared.urlForApplication(withBundleIdentifier: $0) }
            let bundle = url.flatMap { Bundle(url: $0) }
            let name = (bundle?.object(forInfoDictionaryKey: "CFBundleDisplayName") as? String)
                ?? url?.deletingPathExtension().lastPathComponent ?? fallback
            result[group] = MonitoredApp(id: group, name: name, appID: appID,
                icon: url.map { NSWorkspace.shared.icon(forFile: $0.path) })
        }
        for id in control.policy.appIDs.union(watchedIDs) { offline(id, group: "app:" + id, fallback: id) }
        for event in visibleEvents { offline(event.appID, group: event.groupID, fallback: event.process) }
        return result
    }
    private var selectedApp: MonitoredApp? {
        if case .app(let id) = selection { return catalog[id] }
        return nil
    }
    private var watchedIDs: Set<String> { Set(watchedApps.split(separator: "\n").map(String.init)) }
    private func watchApp(at url: URL) {
        let accessed = url.startAccessingSecurityScopedResource()
        defer { if accessed { url.stopAccessingSecurityScopedResource() } }
        guard let bundle = Bundle(url: url), let id = bundle.bundleIdentifier,
              !id.isEmpty, !id.contains("\n"),
              bundle.object(forInfoDictionaryKey: "CFBundlePackageType") as? String == "APPL" else {
            appPickerMessage = "请选择一个 macOS 应用。"
            return
        }
        watchedApps = watchedIDs.union([id]).sorted().joined(separator: "\n")
        search = ""
        selection = .app("app:" + id)
    }
    private var title: String {
        if case .app = selection { return selectedApp?.name ?? "已退出的 App" }
        return "全部 App"
    }
    private func matches(_ values: String...) -> Bool {
        search.isEmpty || values.contains { $0.localizedCaseInsensitiveContains(search) }
    }
    private func sidebarApps(_ apps: [String: MonitoredApp]) -> [MonitoredApp] {
        let matchesEvents = Set(baseEvents(in: apps, limitToSelection: false).map(\.groupID))
        return apps.values.filter { app in
            matches(app.name, app.appID ?? "") || matchesEvents.contains(app.id)
                || app.processes.contains { $0.connections.contains { matches($0.endpoint) } }
        }.sorted { $0.name.localizedStandardCompare($1.name) == .orderedAscending }
    }
    private var visibleEvents: [BlockEvent] {
        activity.events.filter { !$0.process.hasPrefix("GuardPeer-") }
    }
    private var processes: [NetworkProcess] {
        if case .app(let id) = selection { return activity.processes.filter { $0.groupID == id } }
        return activity.processes
    }
    private var baseConnections: [DisplayedConnection] {
        let apps = catalog
        return processes.flatMap { process in
            let name = apps[process.groupID]?.name ?? process.name
            let matching = matches(name, process.appID ?? "")
            return process.connections.filter { matching || matches($0.endpoint) }.map {
                DisplayedConnection(socket: $0, appName: name)
            }
        }.sorted { $0.socket.received + $0.socket.sent > $1.socket.received + $1.socket.sent }
    }
    private func baseEvents(in apps: [String: MonitoredApp], limitToSelection: Bool = true) -> [BlockEvent] {
        return visibleEvents.filter { event in
            if limitToSelection, case .app(let id) = selection, event.groupID != id { return false }
            return matches(event.address, event.process, event.verdictTitle, apps[event.groupID]?.name ?? "", event.app)
        }
    }
    private var connections: [DisplayedConnection] {
        guard let region else { return baseConnections }
        return baseConnections.filter { NetworkGeography.code(for: $0.socket.endpoint) == region }
    }
    private var events: [BlockEvent] {
        let baseEvents = baseEvents(in: catalog)
        guard let region else { return baseEvents }
        return baseEvents.filter { NetworkGeography.code(for: $0.address) == region }
    }
    private var regions: [RouteGroup] {
        var groups: [String: RouteGroup] = [:]
        for item in baseConnections {
            let key = NetworkGeography.code(for: item.socket.endpoint)
            groups[key, default: RouteGroup(id: key)].observed += 1
        }
        for item in baseEvents(in: catalog) where verdictKind?.includes(item) != false || mode == .connections {
            let key = NetworkGeography.code(for: item.address)
            groups[key, default: RouteGroup(id: key)].blocked += 1
        }
        return groups.values.sorted { $0.id < $1.id }
    }
    private var split: some View {
        NavigationSplitView {
            List(selection: $selection) {
                Label("全部 App", systemImage: "square.grid.2x2").tag(Selection.all)
                Section("App 与进程") {
                    ForEach(sidebarApps(catalog)) { app in
                        HStack(spacing: 8) {
                            if let icon = app.icon {
                                Image(nsImage: icon).resizable().frame(width: 20, height: 20)
                            } else { Image(systemName: "app").frame(width: 20) }
                            Text(app.name).lineLimit(1)
                            Spacer()
                            if app.connectionCount > 0 {
                                Text(app.connectionCount, format: .number).foregroundStyle(.secondary).monospacedDigit()
                            }
                        }.tag(Selection.app(app.id))
                            .contextMenu {
                                if let id = app.appID, watchedIDs.contains(id) {
                                    Button("从关注列表移除") {
                                        watchedApps = watchedIDs.subtracting([id]).sorted().joined(separator: "\n")
                                    }
                                }
                            }
                    }
                }
            }
            .listStyle(.sidebar)
            .navigationSplitViewColumnWidth(min: 170, ideal: 196, max: 270)
            .safeAreaInset(edge: .bottom, spacing: 0) {
                Button { choosingApp = true } label: {
                    Label("添加 App…", systemImage: "plus").frame(maxWidth: .infinity, alignment: .leading)
                }.buttonStyle(.borderless).padding(.horizontal, 14).padding(.vertical, 9)
            }
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
        split.searchable(text: $search, placement: .toolbar, prompt: "搜索 App、地址或拦截")
            .fileImporter(isPresented: $choosingApp, allowedContentTypes: [.application]) { result in
                switch result {
                case .success(let url): watchApp(at: url)
                case .failure(let error): appPickerMessage = error.localizedDescription
                }
            }
            .alert("无法添加 App", isPresented: Binding(get: { appPickerMessage != nil },
                    set: { if !$0 { appPickerMessage = nil } })) {
                Button("好", role: .cancel) { appPickerMessage = nil }
            } message: { Text(appPickerMessage ?? "") }
            .task {
                activity.start()
                while !Task.isCancelled {
                    await control.load()
                    try? await Task.sleep(for: .seconds(3))
                }
            }
            .onReceive(activity.$processes) { recordSample(from: $0) }
            .onChange(of: selection) { _, _ in
                showPolicy = false; region = nil; verdictKind = nil
                history = []; previous = [:]; recordSample()
            }
            .confirmationDialog("限制迅雷的 IP 位址连接？", isPresented: $confirmIP, titleVisibility: .visible) {
                Button("启用 IP 位址规则") { change { $0.thunderIP = true } }
                Button("取消", role: .cancel) {}
            } message: { Text("放行已识别的域名服务和标准磁力清单。直连时拦截文件数据和无法识别的协议。") }
    }
    private var header: some View {
        HStack(alignment: .center) {
            VStack(alignment: .leading, spacing: 4) {
                Text(title).font(.title2.bold())
                Text(selectedApp?.appID == GuardPolicy.thunderID
                     ? (control.policy.thunderIP ? (control.configured ? "IP 位址规则已开启" : "IP 位址规则未生效：过滤器未启用") : "IP 位址规则未开启")
                     : "查看网络连接和实际拦截")
                    .font(.callout).foregroundStyle(.secondary)
            }
            Spacer()
            if selection == nil || selection == .all {
                Toggle("全局拦截 BT 文件", isOn: Binding(get: { control.policy.blockAll },
                    set: { value in change { $0.blockAll = value } }))
                    .toggleStyle(.switch).controlSize(.small).disabled(control.busy)
            } else if let id = selectedApp?.appID {
                Picker("BT 文件规则", selection: Binding(get: { control.policy.mode(for: id) },
                    set: { mode in change { $0.setMode(mode, for: id) } })) {
                    ForEach(AppBTMode.allCases, id: \.self) { Text($0.title).tag($0) }
                }.fixedSize().disabled(control.busy)
            } else {
                Text("沿用全局").font(.callout).foregroundStyle(.secondary)
            }
            if selection == nil || selection == .all || selectedApp?.appID == GuardPolicy.thunderID || control.note != nil {
                Button { showPolicy.toggle() } label: {
                    Label("设置", systemImage: "slider.horizontal.3").labelStyle(.iconOnly)
                }.popover(isPresented: $showPolicy, arrowEdge: .bottom) {
                    policies.frame(width: 320).padding(12)
                }
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
                if activity.blockFeedAvailable {
                    HStack(spacing: 6) {
                        ForEach(VerdictKind.allCases, id: \.self) { kind in
                            verdictCount(kind, events.filter(kind.includes).count)
                        }
                    }
                    eventList(events.filter { verdictKind?.includes($0) != false })
                    Text("近 10 分钟 · 只显示本版护栏的拦截").font(.caption2).foregroundStyle(.secondary)
                } else {
                    ContentUnavailableView("尚未收到拦截记录", systemImage: "shield.slash",
                                           description: Text("记录来源未连接，无法判断拦截次数。"))
                }
#if PG_STORE
                if activity.legacyDashboardRunning {
                    Text("旧版护栏也在运行。旧版先拒绝的连接不会出现在这里。")
                        .font(.caption2).foregroundStyle(.secondary)
                }
#endif
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
        VStack(alignment: .leading, spacing: 12) {
#if PG_STORE
            Toggle("观察连接和 App 流量", isOn: Binding(get: { control.observing }, set: {
                control.change(to: control.policy, observe: $0)
            })).toggleStyle(.switch).disabled(control.busy)
            Text("开启后，扩展在本机提供连接统计。关闭后，已选择的拦截规则仍然有效。")
                .font(.caption).foregroundStyle(.secondary)
            Divider()
#endif
            if selectedApp?.appID == GuardPolicy.thunderID {
                Toggle("IP 位址 · 直连仅允许获取清单", isOn: Binding(get: { control.policy.thunderIP },
                    set: { value in
                        if value { confirmIP = true }
                        else { change { $0.thunderIP = false } }
                    }))
                    .toggleStyle(.switch).disabled(control.busy)
                Text("迅雷的额外兼容规则。识别出的域名服务和标准磁力清单可通过。")
                    .font(.caption).foregroundStyle(.secondary)
                Divider()
            }
            Text(control.note ?? "BT 文件规则拦截可识别的标准 BitTorrent 上传和下载，保留文件清单和其他流量。")
                .font(.caption).foregroundStyle(.secondary)
            if control.policy.needsFilter {
                Button("重新应用当前规则") { control.change(to: control.policy) }.disabled(control.busy)
            }
        }
    }

    private func change(_ update: (inout GuardPolicy) -> Void) {
        var updated = control.policy
        update(&updated)
        guard updated != control.policy else { return }
        control.change(to: updated)
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
                    let socket = item.socket
                    HStack {
                        VStack(alignment: .leading, spacing: 3) {
                            Text(socket.endpoint).lineLimit(1).truncationMode(.middle).textSelection(.enabled)
                            if selection == .all || selection == nil {
                                Text(item.appName).font(.caption).foregroundStyle(.secondary).lineLimit(1)
                            }
                        }
                        Spacer()
                        VStack(alignment: .trailing, spacing: 3) {
                            Text(socket.protocolName.uppercased()).font(.caption2)
                            Text("↓ \(bytes(socket.received))  ↑ \(bytes(socket.sent))").font(.caption)
                        }.fixedSize().foregroundStyle(.secondary)
                    }.font(.callout.monospacedDigit()).padding(.vertical, 2)
                }.listStyle(.inset)
            }
        }.frame(maxWidth: .infinity, maxHeight: .infinity)
    }
    private func eventList(_ shown: [BlockEvent]) -> some View {
        let apps = catalog
        return Group {
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
                            let app = apps[event.groupID]?.name
                            Text(app.map { $0 == event.process ? $0 : "\($0) · \(event.process)" } ?? event.process)
                                .font(.caption2).foregroundStyle(.secondary)
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
    private func recordSample(from latest: [NetworkProcess]? = nil) {
        var next: [Int32: Totals] = [:]
        var delta = Totals()
        let selectedProcesses = latest.map { values in
            if case .app(let id) = selection { return values.filter { $0.groupID == id } }
            return values
        } ?? processes
        for process in selectedProcesses {
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
