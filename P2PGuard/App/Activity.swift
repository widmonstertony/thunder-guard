import AppKit
import SwiftUI

struct AppConnection: Identifiable, Hashable {
    var id: String { protocolName + " " + path }
    let protocolName: String
    let path: String
    let endpoint: String
    let received: Int64
    let sent: Int64
}

struct NetworkProcess: Identifiable {
    let id: Int32
    let name: String
    var connections: [AppConnection] = []
    var appID: String?
    var groupID: String { appID.map { "app:" + $0 } ?? "process:" + name }
}

struct MonitoredApp: Identifiable {
    let id: String
    let name: String
    var appID: String?
    var icon: NSImage?
    var processes: [NetworkProcess] = []
    var connectionCount: Int { processes.reduce(0) { $0 + $1.connections.count } }
}

struct AppTraffic: Identifiable {
    let id: String
    let name: String
    var rate: Traffic
}

struct BlockEvent: Identifiable, Decodable {
    var id: String { "\(timestamp)-\(process)-\(address)-\(port)-\(direction.rawValue)" }
    let app: String
    let process: String
    let address: String
    let port: String
    let timestamp: TimeInterval
    let direction: Direction
    let reason: String
    let detail: String?
    var appID: String? { app == "thunder" ? GuardPolicy.thunderID : app.isEmpty ? nil : app }
    var groupID: String { appID.map { "app:" + $0 } ?? "process:" + process }
    enum Direction: String, Decodable { case upload, download, connection }
    var endpoint: String { guard !address.isEmpty else { return "—" }; return address.contains(":") ? "[\(address)]:\(port)" : "\(address):\(port)" }
    var isFile: Bool { reason == "bt-file" && direction != .connection }
    var verdictTitle: String {
        if isFile { return direction == .upload ? "已拦截 BT 上传" : "已拦截 BT 下载" }
        switch reason {
        case "bt-control": return "已拦截 BT 控制消息"
        case "inspection-offset", "inspection-capacity": return "已拒绝检查异常的连接"
        default: return "已拒绝 IP 直连"
        }
    }
    var rationale: String {
        if isFile {
            switch detail {
            case "request": return "BitTorrent 文件块请求"
            case "piece": return "BitTorrent 文件数据块"
            default: return "识别到 BitTorrent 文件传输"
            }
        }
        switch reason {
        case "inspection-offset": return "数据不连续，无法安全判断"
        case "inspection-capacity": return "检查容量已满"
        case "bt-control": return "文件传输控制消息"
        default: return "直连未识别为受支持的清单或域名服务"
        }
    }
}

@MainActor final class Activity: ObservableObject {
    @Published private(set) var processes: [NetworkProcess] = []
    @Published private(set) var runningApps: [MonitoredApp] = []
    @Published private(set) var events: [BlockEvent] = []
    @Published private(set) var status: String?
    @Published private(set) var topTraffic: [AppTraffic] = []
    @Published private(set) var blockFeedAvailable = false
#if PG_STORE
    @Published private(set) var legacyDashboardRunning = false
#endif
    private var sampling = false
    private var reader: Task<Void, Never>?
    private var sampler: Task<Void, Never>?
    private var lastSample: TimeInterval?
    private var lastCounts: [String: Traffic] = [:]

    func sample() async {
        guard !sampling else { return }
        sampling = true
        defer { sampling = false }
        let observed = NSWorkspace.shared.runningApplications
        runningApps = observed.compactMap { app in
            guard app.activationPolicy == .regular, let id = app.bundleIdentifier else { return nil }
            return MonitoredApp(id: "app:" + id, name: app.localizedName ?? id, appID: id, icon: app.icon)
        }
#if PG_STORE
        let legacyRunning = observed.contains { $0.bundleIdentifier == "org.thunderguard.firewall.app" }
        if legacyDashboardRunning != legacyRunning { legacyDashboardRunning = legacyRunning }
        guard let update = await StoreFeed.read() else {
            blockFeedAvailable = false
            status = "尚未收到商店版扩展的连接数据。"; topTraffic = []; lastCounts = [:]; processes = []; events = []
            return
        }
        let updated = update.processes
        updateTraffic(updated)
        processes = updated
        events = update.blocks
        blockFeedAvailable = true
        status = nil
#else
        do {
            let snapshot = try await Task.detached(priority: .utility) { try Self.networkSnapshot() }.value
            let ids = observed.reduce(into: [Int32: String]()) { result, app in
                result[app.processIdentifier] = app.bundleIdentifier
            }
            let thunderRunning = observed.contains { $0.bundleIdentifier == GuardPolicy.thunderID }
            let updated = snapshot.map { process in
                var process = process
                process.appID = ids[process.id]
                if process.appID == nil, thunderRunning,
                   ["Thunder", "迅雷", "DownloadService", "XLEmbeddedPlayer", "ThunderHelper"].contains(process.name) {
                    process.appID = GuardPolicy.thunderID
                }
                return process
            }
            updateTraffic(updated)
            processes = updated
            status = nil
        } catch { status = "暂时无法读取系统连接。"; topTraffic = []; lastCounts = [:] }
#endif
    }

    func start() {
        if sampler == nil {
            sampler = Task { [weak self] in
                while !Task.isCancelled {
                    await self?.sample()
                    try? await Task.sleep(for: .seconds(2))
                }
            }
        }
#if !PG_STORE
        guard reader == nil else { return }
        reader = Task { [weak self] in
            while !Task.isCancelled {
                let evidence = await Task.detached(priority: .utility) { Self.readEvidence() }.value
                if let evidence { self?.events = evidence }
                self?.blockFeedAvailable = evidence != nil
                try? await Task.sleep(for: .seconds(5))
            }
        }
#endif
    }

    private func updateTraffic(_ snapshot: [NetworkProcess]) {
        let now = ProcessInfo.processInfo.systemUptime
        let elapsed = lastSample.map { now - $0 } ?? 0
        lastSample = now
        let names = runningApps.reduce(into: [String: String]()) { $0[$1.id] = $1.name }
        var fresh: [String: Traffic] = [:]
        var groups: [String: AppTraffic] = [:]
        for process in snapshot {
            for flow in process.connections {
                let key = "\(process.id):\(process.groupID):\(flow.id)"
                let value = Traffic(down: Double(flow.received), up: Double(flow.sent))
                fresh[key] = value
                guard (0.2...15).contains(elapsed), let old = lastCounts[key] else { continue }
                let rate = Traffic.delta(now: value, previous: old).perSecond(elapsed)
                guard rate.total > 0 else { continue }
                let id = process.groupID
                groups[id, default: .init(id: id, name: names[id] ?? process.name, rate: Traffic())].rate =
                    (groups[id]?.rate ?? .init()) + rate
            }
        }
        lastCounts = fresh
        topTraffic = groups.values.sorted { $0.rate.total > $1.rate.total }.prefix(8).map { $0 }
    }

#if !PG_STORE
    private nonisolated static func run(_ command: String, _ arguments: [String]) throws -> String {
        let process = Process()
        let output = Pipe()
        process.executableURL = URL(fileURLWithPath: command)
        process.arguments = arguments
        process.standardOutput = output
        process.standardError = FileHandle.nullDevice
        try process.run()
        let data = output.fileHandleForReading.readDataToEndOfFile()
        process.waitUntilExit()
        guard process.terminationStatus == 0 else { throw CocoaError(.fileReadUnknown) }
        return String(decoding: data, as: UTF8.self)
    }

    private nonisolated static func readEvidence() -> [BlockEvent]? {
        guard let log = try? run("/usr/bin/log", ["show", "--last", "10m", "--style", "compact", "--predicate",
            #"subsystem == "org.thunderguard.firewall" AND category == "packet-evidence" AND eventMessage BEGINSWITH "P2PGUARD_BLOCK ""#])
        else { return nil }
        let decoder = JSONDecoder()
        var counts: [VerdictKind: Int] = [:]
        var retained: [BlockEvent] = []
        for line in log.split(separator: "\n").reversed() {
            guard let tag = line.range(of: "P2PGUARD_BLOCK "),
                  let event = try? decoder.decode(BlockEvent.self, from: Data(line[tag.upperBound...].utf8)) else { continue }
            let kind: VerdictKind = event.isFile ? (event.direction == .upload ? .upload : .download) : .other
            guard counts[kind, default: 0] < 250 else { continue }
            counts[kind, default: 0] += 1
            retained.append(event)
            if retained.count == 750 { break }
        }
        return retained
    }

    private nonisolated static func networkSnapshot() throws -> [NetworkProcess] {
        let output = try run("/usr/bin/nettop", ["-n", "-L", "1", "-x"])
        var groups: [NetworkProcess] = []
        for line in output.split(separator: "\n").dropFirst() {
            let columns = line.split(separator: ",", omittingEmptySubsequences: false)
            guard columns.count >= 6 else { continue }
            let label = columns[1].trimmingCharacters(in: .whitespaces)
            if let arrow = label.range(of: "<->"), let space = label.firstIndex(of: " "), !groups.isEmpty {
                let remote = label[arrow.upperBound...]
                guard !remote.isEmpty && !remote.hasPrefix("*") else { continue }
                let item = AppConnection(protocolName: String(label[..<space]), path: String(label[space...]),
                    endpoint: String(remote), received: Int64(columns[4]) ?? 0, sent: Int64(columns[5]) ?? 0)
                groups[groups.count - 1].connections.append(item)
            } else if let dot = label.lastIndex(of: "."), let pid = Int32(label[label.index(after: dot)...]) {
                groups.append(NetworkProcess(id: pid, name: String(label[..<dot])))
            }
        }
        return groups.filter { !$0.connections.isEmpty }.sorted { $0.name.localizedStandardCompare($1.name) == .orderedAscending }
    }
#endif
}
