import Foundation

@main struct MeterTest {
    static func main() throws {
        func sample(_ name: String, _ index: UInt16, _ down: Double, _ up: Double, running: Bool = true) -> InterfaceTraffic {
            .init(id: name, index: index, counts: .init(down: down, up: up), running: running, linkSpeed: 0)
        }
        var rates = InterfaceRates()
        assert(rates.ingest([sample("en0", 3, 4_294_967_295, 800)], now: 1).isEmpty)
        let next = rates.ingest([sample("en0", 3, 4_294_969_295, 1_200), sample("utun7", 5, 500_000, 0)], now: 3)
        assert(next == ["en0": .init(down: 1_000, up: 200)])
        assert(rates.totals["en0"] == .init(down: 2_000, up: 400))
        let reset = rates.ingest([sample("en0", 3, 40, 1_300), sample("utun7", 6, 900_000, 0)], now: 4)
        assert(reset == ["en0": .init(down: 0, up: 100)])
        assert(rates.ingest([sample("en0", 3, 1_000_000, 0)], now: 60).isEmpty)
        assert(rates.ingest([sample("en0", 3, 1_100_000, 8, running: false)], now: 61).isEmpty)
        assert(rates.ingest([sample("en0", 3, 1_200_000, 18)], now: 62).isEmpty)
        assert(rates.totals["en0"] == .init(down: 2_000, up: 500))

        let start = Date(timeIntervalSince1970: 1_790_001_000)
        var archive = ArchivedRates()
        archive.append(.init(at: start, rate: .init(down: 500, up: 100)), seconds: 1)
        archive.append(.init(at: start.addingTimeInterval(3), rate: .init(down: 100, up: 200)), seconds: 2)
        let points = archive.points(.day, endingAt: start.addingTimeInterval(900))
        assert(points.count == 1)
        assert(abs(points[0].rate.down - 700.0 / 3) < 0.01 && abs(points[0].rate.up - 500.0 / 3) < 0.01)
        let reloaded = try JSONDecoder().decode(ArchivedRates.self, from: JSONEncoder().encode(archive))
        assert(reloaded.points(.day, endingAt: start.addingTimeInterval(900)) == points)
        assert(reloaded.points(.day, endingAt: start.addingTimeInterval(86_700)).isEmpty)
        assert(reloaded.points(.week, endingAt: start.addingTimeInterval(86_700)).count == 1)
        assert(reloaded.points(.week, endingAt: start.addingTimeInterval(608_400)).isEmpty)

        assert(LatencyTarget(host: "2001:db8::1", port: "443")?.label == "[2001:db8::1]:443")
        assert(LatencyTarget(host: "example.com.", port: "80")?.label == "example.com.:80")
        assert(LatencyTarget(host: "https://example.com/", port: "443") == nil)
        assert(LatencyTarget(host: "example.com", port: "65536") == nil)

        if CommandLine.arguments.contains("--live") {
            guard let interfaces = NetworkInterfaces.snapshot(), !interfaces.isEmpty,
                  interfaces.contains(where: { $0.running && $0.counts.total > 0 }) else {
                fatalError("No active interface counters")
            }
            print("Read live 64-bit interface counters successfully.")
        }
        print("Rate sampling handles 64-bit counts, interface changes and sleep gaps.")
    }
}
