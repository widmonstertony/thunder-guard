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
    var thunder: Bool { name == "Thunder" || name == "DownloadService" || name == "XLEmbeddedPlayer" || name == "迅雷" }
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
    enum Direction: String, Decodable { case upload, download, connection }
    var endpoint: String { guard !address.isEmpty else { return "—" }; return address.contains(":") ? "[\(address)]:\(port)" : "\(address):\(port)" }
    var isFile: Bool { reason == "bt-file" && direction != .connection }
    var verdictTitle: String {
        if isFile { return direction == .upload ? "已拦截 BT 上传" : "已拦截 BT 下载" }
        return reason == "bt-control" ? "已拦截 BT 控制消息" : "已拒绝 IP 直连"
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
    @Published private(set) var events: [BlockEvent] = []
    @Published private(set) var observedThunder = false
    @Published private(set) var status: String?
    private var sampling = false
    private var reader: Task<Void, Never>?

    func sample() async {
        guard !sampling else { return }
        sampling = true
        defer { sampling = false }
        do {
            let snapshot = try await Task.detached(priority: .utility) { try Self.networkSnapshot() }.value
            processes = snapshot
            status = nil
        } catch { status = "暂时无法读取系统连接。" }
    }

    func start() {
        guard reader == nil else { return }
        reader = Task { [weak self] in
            while !Task.isCancelled {
                let evidence = await Task.detached(priority: .utility) { Self.readEvidence() }.value
                if let evidence {
                    self?.events = evidence.events
                    self?.observedThunder = evidence.observedThunder
                }
                try? await Task.sleep(for: .seconds(5))
            }
        }
    }

    func stop() { reader?.cancel(); reader = nil }

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

    private nonisolated static func readEvidence() -> (events: [BlockEvent], observedThunder: Bool)? {
        guard let log = try? run("/usr/bin/log", ["show", "--last", "10m", "--style", "compact", "--predicate",
            #"subsystem == "org.thunderguard.firewall" AND category == "packet-evidence" AND (eventMessage BEGINSWITH "P2PGUARD_BLOCK " OR eventMessage BEGINSWITH "P2PGUARD_FLOW ")"#])
        else { return nil }
        let events: [BlockEvent] = log.split(separator: "\n").lazy.filter { $0.contains("P2PGUARD_BLOCK ") }
            .suffix(250).reversed().compactMap { line in
            guard let tag = line.range(of: "P2PGUARD_BLOCK ") else { return nil }
            return try? JSONDecoder().decode(BlockEvent.self, from: Data(line[tag.upperBound...].utf8))
        }
        return (events, log.contains("P2PGUARD_FLOW "))
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
}
