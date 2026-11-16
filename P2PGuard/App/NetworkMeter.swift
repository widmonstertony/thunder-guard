import AppKit
import Darwin
import Foundation
import Network
import SwiftUI
import SystemConfiguration

struct Traffic: Codable, Equatable {
    var down: Double = 0
    var up: Double = 0
    static func +(a: Self, b: Self) -> Self { .init(down: a.down + b.down, up: a.up + b.up) }
    static func delta(now: Self, previous: Self) -> Self {
        .init(down: max(0, now.down - previous.down), up: max(0, now.up - previous.up))
    }
    func perSecond(_ seconds: Double) -> Self { .init(down: down / seconds, up: up / seconds) }
    var total: Double { down + up }
}

struct InterfaceTraffic: Identifiable, Equatable {
    let id: String
    let index: UInt16
    let counts: Traffic
    var addresses: [String] = []
    var running: Bool
    var linkSpeed: UInt64
}

struct RatePoint: Identifiable, Equatable {
    let at: Date
    let rate: Traffic
    var id: Date { at }
}

struct RateHistory {
    private var seconds: [RatePoint] = []
    private var aggregates: [RatePoint] = []
    private var bucketCount = 0
    var recent: [RatePoint] { seconds }
    var long: [RatePoint] { aggregates }

    mutating func append(_ point: RatePoint) {
        seconds.append(point)
        if seconds.count > 90 { seconds.removeFirst() }
        let bucket = Date(timeIntervalSince1970: floor(point.at.timeIntervalSince1970 / 10) * 10)
        if let last = aggregates.last, last.at == bucket {
            bucketCount += 1
            let mean = Traffic(down: last.rate.down + (point.rate.down - last.rate.down) / Double(bucketCount),
                               up: last.rate.up + (point.rate.up - last.rate.up) / Double(bucketCount))
            aggregates[aggregates.count - 1] = RatePoint(at: bucket, rate: mean)
        } else {
            if let last = aggregates.last, last.at > bucket { aggregates.removeAll(); seconds = [point] }
            bucketCount = 1
            aggregates.append(RatePoint(at: bucket, rate: point.rate))
            aggregates.removeAll { $0.at < bucket.addingTimeInterval(-3600) }
        }
    }
}

// Persist interface totals by time bucket only. No app names, IPs or
// connection history are stored in the network history archive.
struct ArchivedRates: Codable {
    enum Range {
        case day, week
        var duration: TimeInterval { self == .day ? 86_400 : 604_800 }
        var step: TimeInterval { self == .day ? 300 : 1_800 }
    }

    private struct Bucket: Codable {
        var rate: Traffic
        var seconds: Double
    }
    private var day: [Int: Bucket] = [:]
    private var week: [Int: Bucket] = [:]
    private(set) var latest = Date.distantPast

    mutating func append(_ point: RatePoint, seconds: Double) {
        guard seconds > 0 else { return }
        if point.at < latest { prune(at: point.at) }
        latest = point.at
        Self.add(point, seconds: seconds, step: Range.day.step, to: &day)
        Self.add(point, seconds: seconds, step: Range.week.step, to: &week)
    }

    private static func add(_ point: RatePoint, seconds: Double, step: TimeInterval,
                            to buckets: inout [Int: Bucket]) {
        let time = Int(floor(point.at.timeIntervalSince1970 / step))
        let previous = buckets[time, default: Bucket(rate: .init(), seconds: 0)]
        let elapsed = previous.seconds + seconds
        let fraction = seconds / elapsed
        let rate = Traffic(down: previous.rate.down + (point.rate.down - previous.rate.down) * fraction,
                           up: previous.rate.up + (point.rate.up - previous.rate.up) * fraction)
        buckets[time] = Bucket(rate: rate, seconds: elapsed)
    }

    mutating func prune(at date: Date) {
        let now = date.timeIntervalSince1970
        day = day.filter { (now - Range.day.duration ... now).contains(Double($0.key) * Range.day.step) }
        week = week.filter { (now - Range.week.duration ... now).contains(Double($0.key) * Range.week.step) }
    }

    func points(_ range: Range, endingAt end: Date) -> [RatePoint] {
        let buckets = range == .day ? day : week
        let latestTime = end.timeIntervalSince1970
        return buckets.keys.sorted().compactMap { key in
            let time = Double(key) * range.step
            guard time >= latestTime - range.duration, time <= latestTime, let bucket = buckets[key] else { return nil }
            return RatePoint(at: Date(timeIntervalSince1970: time), rate: bucket.rate)
        }
    }
}

struct InterfaceRates {
    private var previous: [String: InterfaceTraffic] = [:]
    private var previousTime: TimeInterval?
    private(set) var totals: [String: Traffic] = [:]
    private(set) var sampleDuration: Double = 0

    mutating func ingest(_ sample: [InterfaceTraffic], now: TimeInterval) -> [String: Traffic] {
        let current = Dictionary(uniqueKeysWithValues: sample.map { ($0.id, $0) })
        defer { previous = current; previousTime = now }
        sampleDuration = 0
        guard let last = previousTime, (0.1...10).contains(now - last) else { return [:] }
        sampleDuration = now - last
        var rates: [String: Traffic] = [:]
        for (name, interface) in current where interface.running {
            guard let prior = previous[name], prior.running, prior.index == interface.index else { continue }
            let bytes = Traffic.delta(now: interface.counts, previous: prior.counts)
            rates[name] = bytes.perSecond(now - last)
            totals[name, default: .init()] = totals[name, default: .init()] + bytes
        }
        return rates
    }
}

struct InterfaceDetails: Equatable {
    var routers: [String] = []
    var dns: [String] = []
}

enum NetworkInterfaces {
    static func primary() -> String? {
        for family in ["IPv4", "IPv6"] {
            if let state = SCDynamicStoreCopyValue(nil, "State:/Network/Global/\(family)" as CFString) as? [String: Any],
               let name = state[kSCDynamicStorePropNetPrimaryInterface as String] as? String { return name }
        }
        return nil
    }

    static func details() -> (interfaces: [String: InterfaceDetails], system: InterfaceDetails) {
        let families = ["IPv4", "IPv6"]
        let keys = (families + ["DNS"]).map { "State:/Network/Global/\($0)" }
        let patterns = ["State:/Network/Service/[^/]+/(IPv4|IPv6|DNS)"]
        let rows = SCDynamicStoreCopyMultiple(nil, keys as CFArray, patterns as CFArray) as? [String: [String: Any]] ?? [:]
        let routers = [kSCPropNetIPv4Router as String, kSCPropNetIPv6Router as String]
        let dnsKey = kSCPropNetDNSServerAddresses as String
        var map: [String: InterfaceDetails] = [:]
        var dnsServices: [String: Set<String>] = [:]
        var system = InterfaceDetails()
        func insert(_ address: String, into list: inout [String]) {
            if !address.isEmpty && !list.contains(address) && list.count < 8 { list.append(address) }
        }
        for (family, routerKey) in zip(families, routers) {
            guard let row = rows["State:/Network/Global/\(family)"] else { continue }
            if let address = row[routerKey] as? String {
                insert(address, into: &system.routers)
                if let name = row[kSCDynamicStorePropNetPrimaryInterface as String] as? String {
                    insert(address, into: &map[name, default: .init()].routers)
                }
            }
        }
        for key in rows.keys.sorted() where key.hasPrefix("State:/Network/Service/") {
            guard let family = families.firstIndex(where: { key.hasSuffix("/" + $0) }),
                  let row = rows[key], let name = row[kSCPropInterfaceName as String] as? String else { continue }
            let prefix = key.dropLast(families[family].count)
            dnsServices[name, default: []].insert(prefix + "DNS")
            if let address = row[routers[family]] as? String {
                insert(address, into: &map[name, default: .init()].routers)
            }
        }
        for (name, services) in dnsServices {
            for service in services.sorted() {
                for address in rows[service]?[dnsKey] as? [String] ?? [] {
                    insert(address, into: &map[name, default: .init()].dns)
                }
            }
        }
        for address in rows["State:/Network/Global/DNS"]?[dnsKey] as? [String] ?? [] {
            insert(address, into: &system.dns)
        }
        return (map, system)
    }

    static func snapshot() -> [InterfaceTraffic]? {
        var addresses: [String: Set<String>] = [:]
        var first: UnsafeMutablePointer<ifaddrs>?
        if getifaddrs(&first) == 0 {
            defer { freeifaddrs(first) }
            var current = first
            while let row = current {
                let entry = row.pointee
                current = entry.ifa_next
                guard let name = entry.ifa_name, let address = entry.ifa_addr,
                      [AF_INET, AF_INET6].contains(Int32(address.pointee.sa_family)) else { continue }
                var text = [CChar](repeating: 0, count: Int(NI_MAXHOST))
                if getnameinfo(address, socklen_t(address.pointee.sa_len), &text, socklen_t(text.count), nil, 0, NI_NUMERICHOST) == 0 {
                    addresses[String(cString: name), default: []].insert(String(cString: text))
                }
            }
        }
        var mib = [CTL_NET, PF_ROUTE, 0, AF_UNSPEC, NET_RT_IFLIST2, 0]
        for _ in 0..<2 {
            var len = 0
            guard sysctl(&mib, u_int(mib.count), nil, &len, nil, 0) == 0,
                  len > 0, len < 4_000_000 else { return nil }
            var buffer = [UInt8](repeating: 0, count: len)
            let result = buffer.withUnsafeMutableBytes { sysctl(&mib, u_int(mib.count), $0.baseAddress, &len, nil, 0) }
            if result != 0 { if errno == ENOMEM { continue }; return nil }
            return buffer.withUnsafeBytes { raw in
                var items: [InterfaceTraffic] = []
                var cursor = 0
                while cursor + 4 <= len {
                    let length = Int(raw.loadUnaligned(fromByteOffset: cursor, as: UInt16.self))
                    guard length >= 4, length <= len - cursor else { return nil }
                    defer { cursor += length }
                    guard raw[cursor + 2] == UInt8(RTM_VERSION), raw[cursor + 3] == UInt8(RTM_IFINFO2),
                          length >= MemoryLayout<if_msghdr2>.size else { continue }
                    let info = raw.loadUnaligned(fromByteOffset: cursor, as: if_msghdr2.self)
                    guard info.ifm_flags & IFF_LOOPBACK == 0 else { continue }
                    var name = [CChar](repeating: 0, count: Int(IF_NAMESIZE))
                    guard if_indextoname(UInt32(info.ifm_index), &name) != nil else { continue }
                    let id = String(cString: name)
                    let ips = addresses[id, default: []].sorted()
                    let running = info.ifm_flags & IFF_UP != 0 && info.ifm_flags & IFF_RUNNING != 0
                    guard running || !ips.isEmpty else { continue }
                    items.append(.init(id: id, index: info.ifm_index,
                        counts: .init(down: Double(info.ifm_data.ifi_ibytes), up: Double(info.ifm_data.ifi_obytes)),
                        addresses: ips, running: running, linkSpeed: info.ifm_data.ifi_baudrate))
                }
                return items.sorted { $0.id.localizedStandardCompare($1.id) == .orderedAscending }
            }
        }
        return nil
    }
}

struct LatencyTarget: Equatable {
    let host: String
    let port: UInt16

    init?(host: String, port: String) {
        let host = host.trimmingCharacters(in: .whitespacesAndNewlines)
        let letters = CharacterSet(charactersIn: "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-")
        let labels = (host.hasSuffix(".") ? String(host.dropLast()) : host).split(separator: ".", omittingEmptySubsequences: false)
        let hostname = host.utf8.count <= 253 && !labels.isEmpty && labels.allSatisfy {
            (1...63).contains($0.utf8.count) && $0.first != "-" && $0.last != "-" &&
                $0.unicodeScalars.allSatisfy(letters.contains)
        }
        guard hostname || IPv6Address(host) != nil,
              let port = UInt16(port.trimmingCharacters(in: .whitespaces)), port > 0 else { return nil }
        self.host = host
        self.port = port
    }

    var label: String { host.contains(":") ? "[\(host)]:\(port)" : "\(host):\(port)" }

    func measure() async -> Double? {
        guard let endpointPort = NWEndpoint.Port(rawValue: port) else { return nil }
        let connection = NWConnection(host: NWEndpoint.Host(host), port: endpointPort, using: .tcp)
        return await withCheckedContinuation { continuation in
            let probe = LatencyProbe(connection: connection, reply: continuation)
            probe.start()
        }
    }
}

private final class LatencyProbe: @unchecked Sendable {
    private let queue = DispatchQueue(label: "org.thunderguard.latency")
    private let connection: NWConnection
    // Accessed only by the connection's serial queue after start().
    private var reply: CheckedContinuation<Double?, Never>?
    private var timeout: DispatchWorkItem?

    init(connection: NWConnection, reply: CheckedContinuation<Double?, Never>) {
        self.connection = connection
        self.reply = reply
    }

    func start() {
        let start = DispatchTime.now()
        connection.stateUpdateHandler = { [self] state in
            switch state {
            case .ready: finish(Double(DispatchTime.now().uptimeNanoseconds - start.uptimeNanoseconds) / 1_000_000)
            case .failed, .cancelled: finish(nil)
            default: break
            }
        }
        let timeout = DispatchWorkItem { [weak self] in self?.finish(nil) }
        self.timeout = timeout
        queue.asyncAfter(deadline: start + .seconds(5), execute: timeout)
        connection.start(queue: queue)
    }

    private func finish(_ result: Double?) {
        guard let reply else { return }
        self.reply = nil
        timeout?.cancel(); timeout = nil
        connection.stateUpdateHandler = nil
        connection.cancel()
        reply.resume(returning: result)
    }
}

@MainActor final class NetworkMeter: ObservableObject {
    @Published private(set) var interfaces: [InterfaceTraffic] = []
    @Published private(set) var primary: String?
    @Published private(set) var rates: [String: Traffic] = [:]
    @Published private var graphs: [String: RateHistory] = [:]
    var history: [String: [RatePoint]] { graphs.mapValues(\.recent) }
    var longHistory: [String: [RatePoint]] { graphs.mapValues(\.long) }
    @Published private(set) var totals: [String: Traffic] = [:]
    @Published private(set) var route: NWPath.Status?
    @Published private(set) var available = false
    @Published private(set) var checking = false
    @Published private(set) var publicIP: String?
    @Published private(set) var responseMs: Int?
    @Published private(set) var checkFailed = false
    @Published private(set) var interfaceDetails: [String: InterfaceDetails] = [:]
    @Published private(set) var systemDetails = InterfaceDetails()
    @Published private(set) var latencyTesting = false
    @Published private(set) var latency: (target: LatencyTarget, ms: Double?)?
    private var task: Task<Void, Never>?
    private var counter = InterfaceRates()
    private var archives: [String: ArchivedRates] = [:]
    private let defaults: UserDefaults
    private static let historyKey = "interfaceRateHistoryV1"
    private var archiveDirty = false
    private var lastSave: TimeInterval = 0
    private var terminationObserver: NSObjectProtocol?
    private let monitor = NWPathMonitor()

    init(defaults: UserDefaults = .standard) {
        self.defaults = defaults
        if let data = defaults.data(forKey: Self.historyKey), data.count < 1_500_000,
           let stored = try? JSONDecoder().decode([String: ArchivedRates].self, from: data) {
            archives = stored
            pruneArchive(at: Date())
        }
    }

    func start() {
        guard task == nil else { return }
        terminationObserver = NotificationCenter.default.addObserver(forName: NSApplication.willTerminateNotification,
                                                                      object: nil, queue: .main) { [weak self] _ in
            MainActor.assumeIsolated { self?.saveArchive(at: Date()) }
        }
        monitor.pathUpdateHandler = { [weak self] path in
            Task { @MainActor in self?.route = path.status }
        }
        monitor.start(queue: DispatchQueue(label: "org.thunderguard.route"))
        task = Task { [weak self] in
            var tick = 0
            while !Task.isCancelled {
                let refreshDetails = tick.isMultiple(of: 5)
                let values = await Task.detached(priority: .utility) {
                    (NetworkInterfaces.snapshot(), NetworkInterfaces.primary(), refreshDetails ? NetworkInterfaces.details() : nil)
                }.value
                self?.update(values.0, primary: values.1)
                if let details = values.2 {
                    if self?.interfaceDetails != details.interfaces { self?.interfaceDetails = details.interfaces }
                    if self?.systemDetails != details.system { self?.systemDetails = details.system }
                }
                tick = (tick + 1) % 5
                try? await Task.sleep(for: .seconds(1))
            }
        }
    }

    func archivedHistory(_ range: ArchivedRates.Range, for interface: String, at date: Date) -> [RatePoint] {
        guard let name = interface.isEmpty ? primary : interface else { return [] }
        return archives[name]?.points(range, endingAt: date) ?? []
    }

    private func pruneArchive(at date: Date) {
        for key in Array(archives.keys) {
            if let item = archives[key], date.timeIntervalSince(item.latest) >= ArchivedRates.Range.week.duration {
                archives[key] = nil
            } else { archives[key]?.prune(at: date) }
        }
        for key in archives.keys.sorted(by: { (archives[$0]?.latest ?? .distantPast) > (archives[$1]?.latest ?? .distantPast) }).dropFirst(16) {
            archives[key] = nil
        }
    }

    private func saveArchive(at date: Date) {
        guard archiveDirty else { return }
        pruneArchive(at: date)
        guard let data = try? JSONEncoder().encode(archives) else { return }
        defaults.set(data, forKey: Self.historyKey)
        archiveDirty = false
    }

    private func update(_ readings: [InterfaceTraffic]?, primary preferred: String?) {
        available = readings != nil
        let sample = readings ?? []
        if interfaces.map(\.id) != sample.map(\.id) || zip(interfaces, sample).contains(where: {
            $0.addresses != $1.addresses || $0.running != $1.running || $0.linkSpeed != $1.linkSpeed
        }) { interfaces = sample }
        let chosen = preferred.flatMap { id in sample.contains { $0.id == id && $0.running } ? id : nil }
            ?? sample.first(where: { $0.id.hasPrefix("en") && $0.running && !$0.addresses.isEmpty })?.id
        if primary != chosen {
            primary = chosen; publicIP = nil; responseMs = nil; checkFailed = false
            graphs[""] = nil
        }
        let uptime = ProcessInfo.processInfo.systemUptime
        let current = counter.ingest(sample, now: uptime)
        var observed = current
        if let chosen, let rate = current[chosen] { observed[""] = rate }
        rates = observed
        totals = counter.totals
        let time = Date()
        var retained = graphs.filter { entry in entry.key.isEmpty || sample.contains { $0.id == entry.key } }
        for (id, rate) in observed { retained[id, default: RateHistory()].append(RatePoint(at: time, rate: rate)) }
        graphs = retained
        for (id, rate) in current {
            archives[id, default: ArchivedRates()].append(RatePoint(at: time, rate: rate), seconds: counter.sampleDuration)
            archiveDirty = true
        }
        if uptime - lastSave >= 60 {
            lastSave = uptime
            saveArchive(at: time)
        }
    }

    func testLatency(to target: LatencyTarget) async {
        guard !latencyTesting else { return }
        latencyTesting = true
        defer { latencyTesting = false }
        latency = (target, await target.measure())
    }

    func testInternet() async {
        guard !checking else { return }
        checking = true; checkFailed = false
        defer { checking = false }
        let chosen = primary
        let start = ProcessInfo.processInfo.systemUptime
        let settings = URLSessionConfiguration.ephemeral
        settings.timeoutIntervalForRequest = 6; settings.timeoutIntervalForResource = 8
        let session = URLSession(configuration: settings)
        defer { session.finishTasksAndInvalidate() }
        do {
            let url = URL(string: "https://api64.ipify.org/")!
            let (data, response) = try await session.data(from: url)
            guard primary == chosen, (response as? HTTPURLResponse)?.statusCode == 200, data.count < 64,
                  let ip = String(data: data, encoding: .utf8)?.trimmingCharacters(in: .whitespacesAndNewlines),
                  Self.isIP(ip) else { throw URLError(.badServerResponse) }
            publicIP = ip
            responseMs = Int((ProcessInfo.processInfo.systemUptime - start) * 1000)
        } catch {
            if primary == chosen { publicIP = nil; responseMs = nil; checkFailed = true }
        }
    }

    private static func isIP(_ input: String) -> Bool {
        var v4 = in_addr(); var v6 = in6_addr()
        return inet_pton(AF_INET, input, &v4) == 1 || inet_pton(AF_INET6, input, &v6) == 1
    }
}
