import Foundation

struct StoreFeed: Decodable {
    struct Flow: Decodable {
        let id: String
        let pid: Int32
        let app: String
        let name: String
        let host: String
        let port: String
        let proto: String
        let received: Int64
        let sent: Int64

        var connection: AppConnection {
            let endpoint = host.contains(":") ? "[\(host)]:\(port)" : "\(host):\(port)"
            return .init(protocolName: proto, path: id, endpoint: endpoint, received: received, sent: sent)
        }
    }
    let flows: [Flow]
    let blocks: [BlockEvent]
    var processes: [NetworkProcess] {
        let groups = Dictionary(grouping: flows) { "\($0.pid):\($0.app):\($0.name)" }
        return groups.values.compactMap { rows in
            guard let first = rows.first else { return nil }
            return .init(id: first.pid, name: first.name, connections: rows.map(\.connection),
                         appID: first.app.isEmpty ? nil : first.app)
        }.sorted { $0.name.localizedStandardCompare($1.name) == .orderedAscending }
    }

    static func read() async -> Self? {
        let info = Bundle.main.infoDictionary ?? [:]
        guard let service = info["PGFeedService"] as? String,
              let team = info["PGSigningTeam"] as? String, team.count == 10,
              let provider = info["PGFilterIdentifier"] as? String else { return nil }
        let data: Data? = await withCheckedContinuation { finish in
            let requirement = "anchor apple generic and identifier \"\(provider)\" and certificate leaf[subject.OU] = \(team)"
            PGReadStoreFeed(service, requirement) { finish.resume(returning: $0) }
        }
        guard let data, data.count <= 800_000 else { return nil }
        return try? JSONDecoder().decode(Self.self, from: data)
    }
}
