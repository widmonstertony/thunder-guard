import Foundation

@main struct TestAppPolicy {
    static func main() {
        let thunder = GuardPolicy.thunderID
        let other = "org.example.PeerClient"
        var migrated = GuardPolicy(vendorConfiguration: [
            "blockThunderBT": true, "blockThunderIP": true,
        ])
        precondition(migrated.needsFilter && migrated.thunderIP)
        precondition(migrated.mode(for: thunder) == .block && !migrated.blockAll)
        precondition(!migrated.blocksBT(for: other))
        migrated.blockAll = true
        precondition(migrated.blocksBT(for: other) && migrated.blocksBT(for: nil))
        migrated.setMode(.allow, for: other)
        precondition(!migrated.blocksBT(for: other))
        precondition(GuardPolicy(vendorConfiguration: migrated.vendorConfiguration) == migrated)
        migrated.setMode(.inherit, for: thunder)
        migrated.setMode(.inherit, for: other)
        migrated.blockAll = false
        precondition(migrated.thunderIP && migrated.appIDs == [thunder])
        precondition(GuardPolicy(vendorConfiguration: migrated.vendorConfiguration) == migrated)
        let explicit = GuardPolicy(vendorConfiguration: [
            "blockThunderBT": true, "blockAllBT": true,
            "appBTOverrides": [thunder: "allow", other: "bogus"],
        ])
        precondition(!explicit.blocksBT(for: thunder) && explicit.blocksBT(for: other))
    }
}
