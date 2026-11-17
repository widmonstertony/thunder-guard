import AppKit
import Charts
import Network
import SwiftUI

enum NetworkFormat {
    static func rate(_ bytes: Double, bits: Bool, compact: Bool = false) -> String {
        let value = max(0, bytes) * (bits ? 8 : 1)
        let units = bits ? ["b", "Kb", "Mb", "Gb", "Tb"] : ["B", "KB", "MB", "GB", "TB"]
        var amount = value
        var i = 0
        while amount >= 1000, i < units.count - 1 { amount /= 1000; i += 1 }
        let number = amount.formatted(.number.precision(.fractionLength(0...(i > 0 && amount < 10 ? 1 : 0))))
        return compact ? "\(number)\(units[i])" : "\(number) \(units[i])/s"
    }

    static func bytes(_ value: Double) -> String {
        ByteCountFormatter.string(fromByteCount: Int64(clamping: UInt64(max(0, min(value, Double(Int64.max) / 2)))), countStyle: .decimal)
    }
}

struct NetworkMenuLabel: View {
    @ObservedObject var meter: NetworkMeter
    @ObservedObject var activity: Activity
    @AppStorage("networkInterface") private var interface = ""
    @AppStorage("networkBits") private var bits = false

    var body: some View {
        let rate = meter.rates[interface]
        let down = rate.map { NetworkFormat.rate($0.down, bits: bits, compact: true) } ?? "–"
        let up = rate.map { NetworkFormat.rate($0.up, bits: bits, compact: true) } ?? "–"
        let description = "TonTon 网络：下载 \(down)，上传 \(up)，每秒"
        Image(nsImage: Self.statusImage(down: down, up: up, description: description))
            .accessibilityLabel(description)
            .task { meter.start(); activity.start() }
    }

    static func statusImage(down: String, up: String, description: String) -> NSImage {
        // A status-item template image preserves the two compact rows through the
        // native menu bar bridge, and takes its color from the system appearance.
        let style: [NSAttributedString.Key: Any] = [
            .font: NSFont.monospacedDigitSystemFont(ofSize: 8.5, weight: .medium), .foregroundColor: NSColor.black,
        ]
        func width(_ text: String) -> CGFloat { (text as NSString).size(withAttributes: style).width }
        let arrowWidth = ceil(max(width("↓"), width("↑")))
        let rateX = arrowWidth + 1
        // Reserve room for three digits and a unit to keep the menu steady as
        // rates change. Both values start next to their arrow, even at zero.
        let downRate = down + "/s", upRate = up + "/s"
        let reservedWidth = ["000KB/s", "000MB/s", "000GB/s", "000TB/s"].map(width).max() ?? 0
        let size = NSSize(width: rateX + ceil(max(reservedWidth, width(downRate), width(upRate))), height: 19)
        let image = NSImage(size: size, flipped: true) { _ in
            func draw(_ arrow: String, _ rate: String, y: CGFloat) {
                (arrow as NSString).draw(at: NSPoint(x: (arrowWidth - width(arrow)) / 2, y: y), withAttributes: style)
                (rate as NSString).draw(at: NSPoint(x: rateX, y: y), withAttributes: style)
            }
            draw("↓", downRate, y: 0)
            draw("↑", upRate, y: 9)
            return true
        }
        image.isTemplate = true
        image.accessibilityDescription = description
        return image
    }
}

struct NetworkMenu: View {
    @ObservedObject var meter: NetworkMeter
    @ObservedObject var activity: Activity
    @ObservedObject var control: FilterControl
    let dock: DockPresence
    @Environment(\.openWindow) private var openWindow
    @Environment(\.openSettings) private var openSettings
    @AppStorage("networkInterface") private var interface = ""
    @AppStorage("networkBits") private var bits = false
    @AppStorage("latencyHost") private var latencyHost = "1.1.1.1"
    @AppStorage("latencyPort") private var latencyPort = "443"
    @State private var tab = Tab.network
    @State private var interval = Interval.recent
    @State private var appFilter = ""
    @State private var appFilterName = ""
    @State private var verdictKind: VerdictKind?

    private enum Tab: String, CaseIterable { case network = "网络", blocks = "P2P 拦截" }
    private enum Interval: String, CaseIterable {
        case recent = "1 分钟", medium = "10 分钟", long = "1 小时", day = "24 小时", week = "7 天"
        var seconds: TimeInterval {
            switch self {
            case .recent: 60
            case .medium: 600
            case .long: 3600
            case .day: ArchivedRates.Range.day.duration
            case .week: ArchivedRates.Range.week.duration
            }
        }
        var step: TimeInterval {
            switch self {
            case .recent: 1
            case .medium, .long: 10
            case .day: ArchivedRates.Range.day.step
            case .week: ArchivedRates.Range.week.step
            }
        }
    }
    private var selected: InterfaceTraffic? {
        meter.interfaces.first { $0.id == (interface.isEmpty ? meter.primary : interface) }
    }
    private var route: (String, String, Color) {
        switch meter.route {
        case .satisfied: ("网络路径可用", "checkmark.circle.fill", .green)
        case .requiresConnection: ("连接待建立", "exclamationmark.circle", .orange)
        case .unsatisfied: ("未连接", "wifi.slash", .secondary)
        default: ("正在检测", "network", .secondary)
        }
    }
    private var reportsAvailable: Bool {
#if PG_STORE
        activity.blockFeedAvailable && control.configured
#else
        activity.blockFeedAvailable
#endif
    }

    var body: some View {
        VStack(alignment: .leading, spacing: 0) {
            VStack(alignment: .leading, spacing: 10) {
                HStack {
                    Text("网络活动").font(.headline)
                    Spacer()
                    Label(route.0, systemImage: route.1).font(.caption).foregroundStyle(route.2)
                }
                Picker("查看", selection: $tab) {
                    ForEach(Tab.allCases, id: \.self) { Text($0.rawValue).tag($0) }
                }.labelsHidden().pickerStyle(.segmented)
            }.padding(12)
            Divider()
            ScrollView {
                Group {
                    switch tab {
                    case .network: network
                    case .blocks: blocks
                    }
                }.padding(12).frame(maxWidth: .infinity, alignment: .leading)
            }.id(tab).frame(height: 340)
            Divider()
            HStack {
                Button("打开护栏") { dock.showDock(); NSApplication.shared.activate(); openWindow(id: "dashboard") }
                Button {
                    dock.showDock(); NSApplication.shared.activate(); openSettings()
                } label: {
                    Image(systemName: "gearshape").accessibilityLabel("设置")
                }.help("设置")
                Spacer()
                if tab == .network {
                    Toggle("以位/秒显示", isOn: $bits).controlSize(.small)
                } else {
                    Text("仅显示护栏自己的记录").font(.caption2).foregroundStyle(.secondary)
                }
            }.padding(12)
        }
        // A menu-bar window sizes itself from its content. A flexible ScrollView
        // alone can report a height of zero during that first measurement.
        .frame(width: 360)
        .fixedSize(horizontal: true, vertical: true)
        .task { meter.start(); activity.start(); await control.load() }
    }

    private var network: some View {
        VStack(alignment: .leading, spacing: 12) {
            HStack(spacing: 8) {
                speed("下载", systemImage: "arrow.down", color: .cyan, value: meter.rates[interface]?.down)
                speed("上传", systemImage: "arrow.up", color: .orange, value: meter.rates[interface]?.up)
            }
            HStack {
                Text("网速历史").font(.headline)
                Spacer()
                Picker("网速历史范围", selection: $interval) {
                    ForEach(Interval.allCases, id: \.self) { Text($0.rawValue).tag($0) }
                }.labelsHidden().fixedSize()
            }
            graph
            if let selected {
                let totals = meter.totals[selected.id] ?? .init()
                Text("本次运行：↓ \(NetworkFormat.bytes(totals.down))   ↑ \(NetworkFormat.bytes(totals.up))")
                    .font(.caption).foregroundStyle(.secondary).monospacedDigit()
            }
            Divider()
            Text("App 流量排行").font(.headline)
#if PG_STORE
            if !control.observing {
                Text("在护栏设置中开启「观察连接和 App 流量」后显示。").font(.caption).foregroundStyle(.secondary)
            } else { trafficRows }
#else
            trafficRows
#endif
            Divider()
            connection
        }
    }

    private var graph: some View {
        let end = Date()
        let start = end.addingTimeInterval(-interval.seconds)
        let source: [RatePoint]
        switch interval {
        case .recent: source = meter.history[interface] ?? []
        case .medium, .long: source = meter.longHistory[interface] ?? []
        case .day: source = meter.archivedHistory(.day, for: interface, at: end)
        case .week: source = meter.archivedHistory(.week, for: interface, at: end)
        }
        let entries = source.filter { $0.at >= start && $0.at <= end }
        let spans = chartSpans(entries)
        return Group {
            if !spans.isEmpty {
                Chart {
                    ForEach(spans.indices, id: \.self) { index in
                        ForEach(spans[index]) { point in
                            if spans[index].count == 1 {
                                PointMark(x: .value("时间", point.at), y: .value("速度", point.rate.down)).foregroundStyle(Color.cyan)
                                PointMark(x: .value("时间", point.at), y: .value("速度", point.rate.up)).foregroundStyle(Color.orange)
                            } else {
                                LineMark(x: .value("时间", point.at), y: .value("速度", point.rate.down),
                                         series: .value("方向", "下载\(index)")).foregroundStyle(Color.cyan)
                                LineMark(x: .value("时间", point.at), y: .value("速度", point.rate.up),
                                         series: .value("方向", "上传\(index)")).foregroundStyle(Color.orange)
                            }
                        }
                    }
                }
                .chartXAxis(.hidden)
                .chartXScale(domain: start...end)
                .chartYAxis {
                    AxisMarks(position: .leading, values: .automatic(desiredCount: 3)) { value in
                        AxisGridLine()
                        if let rate = value.as(Double.self) {
                            AxisValueLabel { Text(NetworkFormat.rate(rate, bits: bits, compact: true) + "/s").font(.caption2) }
                        }
                    }
                }
                .accessibilityLabel("最近\(interval.rawValue)的下载及上传网速曲线")
            } else {
                Text(meter.available ? "等待网速采样" : "无法读取此系统的网卡计数")
                    .font(.caption).foregroundStyle(.secondary)
                    .frame(maxWidth: .infinity)
            }
        }.frame(height: 65)
    }

    private func chartSpans(_ points: [RatePoint]) -> [[RatePoint]] {
        var spans: [[RatePoint]] = []
        for point in points {
            if let last = spans.last?.last, point.at.timeIntervalSince(last.at) <= interval.step * (interval == .recent ? 2.5 : 1.5) {
                spans[spans.count - 1].append(point)
            } else { spans.append([point]) }
        }
        return spans
    }

    @ViewBuilder private var trafficRows: some View {
        if activity.topTraffic.isEmpty {
            Text(activity.status ?? "采样期间没有可计量的 App 流量").font(.caption).foregroundStyle(.secondary)
        } else {
            ForEach(activity.topTraffic.prefix(5)) { app in
                Button {
                    appFilter = app.id
                    appFilterName = app.name
                    tab = .blocks
                } label: {
                    HStack {
                        Text(app.name).lineLimit(1)
                        Spacer(minLength: 5)
                        Text("↓ \(NetworkFormat.rate(app.rate.down, bits: bits))  ↑ \(NetworkFormat.rate(app.rate.up, bits: bits))")
                            .monospacedDigit().foregroundStyle(.secondary)
                        Image(systemName: "chevron.right").font(.caption2).foregroundStyle(.tertiary)
                    }.font(.caption).contentShape(Rectangle())
                }.buttonStyle(.plain).help("查看\(app.name)的拦截记录")
            }
        }
    }

    private var connection: some View {
        VStack(alignment: .leading, spacing: 6) {
            HStack {
                Text("连接详情").font(.headline)
                Spacer()
                Picker("网卡", selection: $interface) {
                    Text(meter.primary.map { "自动 · \($0)" } ?? "自动").tag("")
                    if !interface.isEmpty && selected == nil { Text("\(interface) · 未连接").tag(interface) }
                    ForEach(meter.interfaces) { Text($0.id).tag($0.id) }
                }.labelsHidden().fixedSize()
            }
            if let selected, !selected.addresses.isEmpty {
                ForEach(selected.addresses, id: \.self) { address in
                    Text(address).font(.caption.monospaced()).textSelection(.enabled)
                }
            } else { Text("暂无本机 IP").font(.caption).foregroundStyle(.secondary) }
            if let link = selected?.linkSpeed, link > 0 {
                Text("链路速率：\(NetworkFormat.rate(Double(link) / 8, bits: true))").font(.caption).foregroundStyle(.secondary)
            }
            let details = interface.isEmpty ? meter.systemDetails : (meter.interfaceDetails[interface] ?? .init())
            addressRow("网关", values: details.routers)
            addressRow("DNS", values: details.dns)
            if let address = meter.publicIP, let time = meter.responseMs {
                Text("公网 IP：\(address) · HTTPS 响应 \(time) ms").font(.caption).textSelection(.enabled)
            } else if meter.checkFailed {
                Text("本次未能连接 ipify").font(.caption).foregroundStyle(.secondary)
            }
            Button(meter.checking ? "检测中…" : "查询公网 IP 和 HTTPS 响应…") {
                Task { await meter.testInternet() }
            }.disabled(meter.checking)
            Text("仅点按查询时连到 ipify；网速、排行和本机 IP 在本机计算。")
                .font(.caption2).foregroundStyle(.secondary)
            Divider()
            latencyPanel
        }
    }

    private func addressRow(_ title: String, values: [String]) -> some View {
        HStack(alignment: .top, spacing: 8) {
            Text(title).foregroundStyle(.secondary).frame(width: 34, alignment: .leading)
            Text(values.isEmpty ? "未报告" : values.joined(separator: "\n"))
                .monospaced().textSelection(.enabled)
        }.font(.caption)
    }

    private var latencyPanel: some View {
        let target = LatencyTarget(host: latencyHost, port: latencyPort)
        return VStack(alignment: .leading, spacing: 6) {
            Text("连接延迟").font(.headline)
            HStack(spacing: 6) {
                TextField("主机或 IP", text: $latencyHost).textFieldStyle(.roundedBorder)
                TextField("端口", text: $latencyPort).textFieldStyle(.roundedBorder).frame(width: 52)
                Button(meter.latencyTesting ? "检测中…" : "测延迟") {
                    if let target { Task { await meter.testLatency(to: target) } }
                }.disabled(meter.latencyTesting || target == nil)
            }
            if let result = meter.latency, result.target == target, !meter.latencyTesting {
                Text(result.ms.map { "\(result.target.label) · \($0.formatted(.number.precision(.fractionLength(1)))) ms" }
                     ?? "\(result.target.label) · 连接失败或超时")
                    .font(.caption.monospacedDigit()).textSelection(.enabled)
            }
            Text("仅在点按时连接目标。显示系统路由的 TCP 建连耗时。")
                .font(.caption2).foregroundStyle(.secondary)
        }
    }

    private var blocks: some View {
        let cutoff = Date().addingTimeInterval(-600).timeIntervalSince1970
        let recent = activity.events.filter { $0.timestamp >= cutoff && (appFilter.isEmpty || $0.groupID == appFilter) }
            .sorted { $0.timestamp > $1.timestamp }
        let visible = recent.filter { verdictKind?.includes($0) != false }
        let names = appNames
        return VStack(alignment: .leading, spacing: 12) {
            VStack(alignment: .leading, spacing: 4) {
                Text("最近 10 分钟").font(.headline)
                Text(control.configured ? (control.policy.needsFilter ? "已启用所选拦截规则" : "未对 App 启用拦截") : "护栏过滤器未启用")
                    .font(.caption).foregroundStyle(.secondary)
                if appFilter == "app:" + GuardPolicy.thunderID, control.configured {
                    Text(control.policy.thunderIP ? "迅雷 IP 位址规则已开启" : "迅雷 IP 位址规则未开启")
                        .font(.caption).foregroundStyle(.secondary)
                }
#if PG_STORE
                if activity.legacyDashboardRunning {
                    Label("旧版护栏也在运行；它先拒绝的连接不计入本版。", systemImage: "info.circle")
                        .font(.caption).foregroundStyle(.secondary)
                }
#endif
            }
            Picker("只看这个 App", selection: $appFilter) {
                Text("全部 App").tag("")
                if !appFilter.isEmpty, names[appFilter] == nil { Text(appFilterName.isEmpty ? appFilter : appFilterName).tag(appFilter) }
                ForEach(names.keys.sorted(by: {
                    let order = names[$0]!.localizedStandardCompare(names[$1]!)
                    return order == .orderedSame ? $0 < $1 : order == .orderedAscending
                }), id: \.self) { id in
                    Text(names[id] ?? id).tag(id)
                }
            }.onChange(of: appFilter) {
                if let name = names[appFilter] { appFilterName = name }
                verdictKind = nil
            }
            if reportsAvailable {
                HStack(spacing: 6) {
                    ForEach(VerdictKind.allCases, id: \.self) { kind in
                        counter(kind, count: recent.filter(kind.includes).count)
                    }
                }
                Text("IP 直连拒绝计入「其他拒绝」；只有识别到文件块或请求时，才计入 BT 上传或下载。")
                    .font(.caption2).foregroundStyle(.secondary)
                Divider()
                Text(verdictKind?.rawValue ?? "最近拦截").font(.headline)
                if visible.isEmpty {
                    Text("本版护栏近 10 分钟未记录匹配的拦截。")
                        .font(.caption).foregroundStyle(.secondary)
                } else {
                    ForEach(visible.prefix(20)) { event in
                        eventRow(event, name: names[event.groupID] ?? (event.app == "thunder" ? "迅雷" : event.process))
                    }
                }
            } else {
                Label("尚未收到护栏的拦截数据", systemImage: "clock").foregroundStyle(.secondary)
                    .font(.caption)
            }
        }
    }

    private var appNames: [String: String] {
        var names: [String: String] = [:]
        for id in control.policy.appIDs { names["app:" + id] = id }
        for event in activity.events { names[event.groupID] = event.appID == GuardPolicy.thunderID ? "迅雷" : event.process }
        for item in activity.processes { names[item.groupID] = item.name }
        for app in activity.runningApps { names[app.id] = app.name }
        return names
    }

    private func counter(_ kind: VerdictKind, count: Int) -> some View {
        Button {
            verdictKind = verdictKind == kind ? nil : kind
        } label: {
            VStack(alignment: .leading, spacing: 4) {
                Label(kind.rawValue, systemImage: kind.symbol).font(.caption2).foregroundStyle(kind.color).lineLimit(1)
                Text(count.formatted()).font(.headline.monospacedDigit())
            }.frame(maxWidth: .infinity, alignment: .leading).padding(8)
                .background(.quaternary.opacity(0.4), in: .rect(cornerRadius: 9))
                .overlay(RoundedRectangle(cornerRadius: 9).strokeBorder(kind.color.opacity(verdictKind == kind ? 0.75 : 0)))
        }.buttonStyle(.plain)
            .accessibilityLabel("\(kind.rawValue)，\(count) 条")
            .accessibilityAddTraits(verdictKind == kind ? .isSelected : [])
    }

    private func eventRow(_ event: BlockEvent, name: String) -> some View {
        let icon = event.isFile ? (event.direction == .upload ? "arrow.up.circle.fill" : "arrow.down.circle.fill") : "hand.raised.circle"
        let color: Color = event.isFile ? (event.direction == .upload ? .orange : .pink) : .secondary
        return HStack(alignment: .top, spacing: 8) {
            Image(systemName: icon).foregroundStyle(color).accessibilityHidden(true)
            VStack(alignment: .leading, spacing: 3) {
                HStack {
                    Text(event.verdictTitle).font(.caption.bold())
                    Spacer()
                    Text(Date(timeIntervalSince1970: event.timestamp), format: .dateTime.hour().minute().second())
                        .font(.caption2.monospacedDigit()).foregroundStyle(.secondary)
                }
                Text(name + " · " + event.endpoint).lineLimit(2).font(.caption.monospacedDigit()).textSelection(.enabled)
                Text(event.rationale).font(.caption2).foregroundStyle(.secondary)
            }
        }
    }

    private func speed(_ title: String, systemImage: String, color: Color, value: Double?) -> some View {
        VStack(alignment: .leading, spacing: 3) {
            Label(title, systemImage: systemImage).font(.caption).foregroundStyle(color)
            Text(value.map { NetworkFormat.rate($0, bits: bits) } ?? "—").font(.headline.monospacedDigit())
        }.frame(maxWidth: .infinity, alignment: .leading).padding(9)
            .background(.quaternary.opacity(0.4), in: .rect(cornerRadius: 9))
    }
}
