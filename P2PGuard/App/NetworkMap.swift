import AppKit
import MapKit
import SwiftUI

struct MapPlace: Codable {
    let latitude: Double
    let longitude: Double
    var coordinate: CLLocationCoordinate2D { .init(latitude: latitude, longitude: longitude) }
}

struct RouteGroup: Identifiable {
    let id: String
    var observed = 0
    var blocked = 0
    var coordinate: CLLocationCoordinate2D? { NetworkGeography.centers[id]?.coordinate }
    var title: String { NetworkGeography.title(id) }
}

enum NetworkGeography {
    static let local = "local"
    static let unknown = "unknown"
    private static func resource(_ name: String, _ ext: String) -> Data? {
        guard let url = Bundle.main.url(forResource: name, withExtension: ext) else { return nil }
        return try? Data(contentsOf: url, options: [.mappedIfSafe])
    }
    static let centers = resource("map-centers", "json").flatMap {
        try? JSONDecoder().decode([String: MapPlace].self, from: $0)
    } ?? [:]
    private static let ip4 = resource("ip4ranges", "bin")
    private static let ip6 = resource("ip6ranges", "bin")
    static var hasData: Bool { ip4 != nil && ip6 != nil && !centers.isEmpty }

    static func title(_ code: String) -> String {
        switch code {
        case local: "本地网络"
        case unknown: "未知位置"
        default: Locale(identifier: "zh_Hans").localizedString(forRegionCode: code) ?? code
        }
    }

    private static func parse(_ host: String) -> [UInt8]? {
        let host = String(host.prefix { $0 != "%" })
        var a4 = in_addr()
        if host.withCString({ inet_pton(AF_INET, $0, &a4) }) == 1 {
            return withUnsafeBytes(of: &a4) { Array($0) }
        }
        var a6 = in6_addr()
        if host.withCString({ inet_pton(AF_INET6, $0, &a6) }) == 1 {
            let bytes = withUnsafeBytes(of: &a6) { Array($0) }
            if bytes.prefix(10).allSatisfy({ $0 == 0 }), bytes[10] == 255, bytes[11] == 255 {
                return Array(bytes.suffix(4))
            }
            return bytes
        }
        return nil
    }

    private static func address(_ endpoint: String) -> [UInt8]? {
        let value = endpoint.trimmingCharacters(in: .whitespacesAndNewlines)
        if value.hasPrefix("["), let end = value.firstIndex(of: "]") {
            return parse(String(value[value.index(after: value.startIndex)..<end]))
        }
        // nettop uses .port after address literals, including scoped IPv6.
        if let last = value.lastIndex(of: "."),
           UInt16(value[value.index(after: last)...]) != nil,
           let unadorned = parse(String(value[..<last])) { return unadorned }
        if let ip = parse(value) { return ip }
        if value.contains("."), let split = value.lastIndex(of: ":") {
            return parse(String(value[..<split]))
        }
        return nil
    }

    static func code(for endpoint: String) -> String {
        guard let ip = address(endpoint) else { return unknown }
        if ip.count == 4 {
            let a = ip[0], b = ip[1]
            if a == 0 || a == 10 || a == 127 || a >= 224 || (a == 169 && b == 254) ||
                (a == 172 && (16...31).contains(b)) || (a == 192 && b == 168) ||
                (a == 100 && (64...127).contains(b)) { return local }
        } else if ip[0] == 0xff || (ip[0] & 0xfe) == 0xfc ||
                     (ip[0] == 0xfe && (ip[1] & 0xc0) == 0x80) ||
                     ip.prefix(15).allSatisfy({ $0 == 0 }) && ip[15] < 2 { return local }
        guard let table = ip.count == 4 ? ip4 : ip6 else { return unknown }
        let n = ip.count, stride = 2 * n + 2
        return table.withUnsafeBytes { bytes in
            guard let base = bytes.baseAddress, bytes.count % stride == 0 else { return unknown }
            return ip.withUnsafeBytes { key in
                guard let needle = key.baseAddress else { return unknown }
                var lo = 0, hi = bytes.count / stride
                while lo < hi {
                    let mid = (lo + hi) / 2, row = base.advanced(by: mid * stride)
                    if memcmp(needle, row, n) < 0 { hi = mid }
                    else if memcmp(needle, row.advanced(by: n), n) > 0 { lo = mid + 1 }
                    else {
                        let i = mid * stride + 2 * n
                        guard let code = String(bytes: [bytes[i], bytes[i + 1]], encoding: .ascii),
                              centers[code] != nil else { return unknown }
                        return code
                    }
                }
                return unknown
            }
        }
    }
}

struct NetworkMap: View {
    let groups: [RouteGroup]
    @Binding var selection: String?
    @State private var camera: MapCameraPosition = Self.world
    private static let hub = CLLocationCoordinate2D(latitude: 22, longitude: -32)
    private static let world = MapCameraPosition.region(MKCoordinateRegion(
        center: .init(latitude: 24, longitude: 0), span: .init(latitudeDelta: 122, longitudeDelta: 345)))
    private let blockedColor = Color(red: 1, green: 0.38, blue: 0.37)
    private let connectionColor = Color(red: 0.54, green: 0.84, blue: 0.95)
    private var placed: [RouteGroup] { groups.filter { $0.coordinate != nil } }

    var body: some View {
        Map(position: $camera, interactionModes: [.pan, .zoom]) {
            ForEach(placed) { region in
                if let endpoint = region.coordinate {
                    if region.observed > 0 {
                        MapPolyline(coordinates: arc(to: endpoint, lift: 13))
                            .stroke(connectionColor.opacity(selection == nil || selection == region.id ? 0.73 : 0.18), lineWidth: 1.5)
                    }
                    if region.blocked > 0 {
                        MapPolyline(coordinates: arc(to: endpoint, lift: 23))
                            .stroke(blockedColor.opacity(selection == nil || selection == region.id ? 0.94 : 0.23),
                                    style: StrokeStyle(lineWidth: 2.4, lineCap: .round, dash: [5, 4]))
                    }
                    Annotation(region.title, coordinate: endpoint, anchor: .center) {
                        Button {
                            selection = selection == region.id ? nil : region.id
                        } label: {
                            Image(systemName: region.blocked > 0 ? "hand.raised.fill" : "circle.fill")
                                .font(.system(size: region.blocked > 0 ? 10 : 6, weight: .semibold))
                                .foregroundStyle(region.blocked > 0 ? blockedColor : connectionColor)
                                .frame(width: 26, height: 26)
                                .background(.black.opacity(0.82), in: .circle)
                                .overlay(Circle().strokeBorder(region.blocked > 0 ? blockedColor : connectionColor,
                                                               lineWidth: selection == region.id ? 2 : 1))
                        }.buttonStyle(.plain)
                         .accessibilityLabel("\(region.title)，\(region.observed) 条可见连接，\(region.blocked) 条已拒绝")
                    }.annotationTitles(selection == region.id ? .visible : .hidden)
                }
            }
            Annotation("本机 · 示意起点", coordinate: Self.hub) {
                Image(systemName: "laptopcomputer")
                    .font(.system(size: 17, weight: .semibold)).foregroundStyle(.white)
                    .frame(width: 38, height: 38).background(.black.opacity(0.8), in: .circle)
                    .overlay(Circle().strokeBorder(.white.opacity(0.6), lineWidth: 1))
                    .accessibilityLabel("本机示意起点，并非本机地理位置")
            }
        }
        .mapStyle(.hybrid(elevation: .flat, pointsOfInterest: .excludingAll, showsTraffic: false))
        .mapControlVisibility(.hidden)
        .overlay(alignment: .topLeading) {
            HStack(spacing: 12) {
                Label("可见连接", systemImage: "line.diagonal").foregroundStyle(connectionColor)
                Label("护栏已拒绝", systemImage: "line.3.horizontal.decrease").foregroundStyle(blockedColor)
            }.font(.caption.weight(.semibold))
             .padding(.horizontal, 12).padding(.vertical, 8).mapGlass().padding(12)
        }
        .overlay(alignment: .topTrailing) {
            Button { withAnimation(.easeInOut(duration: 0.35)) { camera = Self.world; selection = nil } } label: {
                Image(systemName: "globe.americas").frame(width: 30, height: 30)
            }.buttonStyle(.plain).foregroundStyle(.white).mapGlass().padding(12).help("查看全球")
        }
        .overlay(alignment: .bottomTrailing) {
            HStack(spacing: 6) {
                ForEach(groups.filter { $0.coordinate == nil }) { item in
                    Button { selection = selection == item.id ? nil : item.id } label: {
                        Label("\(item.title) \(item.observed + item.blocked)",
                              systemImage: item.id == NetworkGeography.local ? "wifi" : "questionmark.circle")
                            .font(.caption.weight(.medium)).padding(.horizontal, 10).padding(.vertical, 7)
                    }.buttonStyle(.plain).foregroundStyle(selection == item.id ? connectionColor : .white).mapGlass()
                }
            }.padding(.trailing, 12).padding(.bottom, 24)
        }
        .environment(\.colorScheme, .dark)
        .clipShape(.rect(cornerRadius: 20))
        .accessibilityLabel("网络连接世界地图")
    }

    private func arc(to endpoint: CLLocationCoordinate2D, lift: Double) -> [CLLocationCoordinate2D] {
        let start = Self.hub
        let raw = endpoint.longitude - start.longitude
        let delta = raw > 180 ? raw - 360 : raw < -180 ? raw + 360 : raw
        return (0...32).map { index in
            let t = Double(index) / 32
            let distance = min(1, abs(delta) / 100)
            let lon = start.longitude + delta * t
            return .init(latitude: min(82, start.latitude + (endpoint.latitude - start.latitude) * t + sin(.pi * t) * lift * distance),
                         longitude: lon > 180 ? lon - 360 : lon < -180 ? lon + 360 : lon)
        }
    }
}

private extension View {
    @ViewBuilder func mapGlass() -> some View {
        if #available(macOS 26.0, *) {
            glassEffect(.regular.tint(.black.opacity(0.33)), in: .capsule)
        } else {
            background(.ultraThinMaterial, in: .capsule)
        }
    }
}
