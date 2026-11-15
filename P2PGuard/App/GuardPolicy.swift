import Foundation

enum AppBTMode: String, CaseIterable {
    case inherit, block, allow

    var title: String {
        switch self {
        case .inherit: "沿用全局"
        case .block: "拦截 BT 文件"
        case .allow: "不拦截 BT 文件"
        }
    }
}

struct GuardPolicy: Equatable {
    static let thunderID = "com.xunlei.Thunder"
    var blockAll = false
    var overrides: [String: AppBTMode] = [:]
    var thunderIP = false

    init() {}

    init(vendorConfiguration: [String: Any]) {
        blockAll = vendorConfiguration["blockAllBT"] as? Bool == true
        thunderIP = vendorConfiguration["blockThunderIP"] as? Bool == true
        let saved = vendorConfiguration["appBTOverrides"] as? [String: String] ?? [:]
        for (app, value) in saved where !app.isEmpty {
            if let mode = AppBTMode(rawValue: value), mode != .inherit { overrides[app] = mode }
        }
        if overrides[Self.thunderID] == nil, vendorConfiguration["blockThunderBT"] as? Bool == true {
            overrides[Self.thunderID] = .block
        }
    }

    var vendorConfiguration: [String: Any] {
        ["blockAllBT": blockAll, "appBTOverrides": overrides.mapValues(\.rawValue),
         "blockThunderBT": overrides[Self.thunderID] == .block, "blockThunderIP": thunderIP]
    }

    var needsFilter: Bool { blockAll || thunderIP || overrides.values.contains(.block) }
    var appIDs: Set<String> {
        var ids = Set(overrides.keys)
        if thunderIP { ids.insert(Self.thunderID) }
        return ids
    }

    func mode(for app: String) -> AppBTMode { overrides[app] ?? .inherit }

    func blocksBT(for app: String?) -> Bool {
        guard let app else { return blockAll }
        switch mode(for: app) {
        case .inherit: return blockAll
        case .allow: return false
        case .block: return true
        }
    }

    mutating func setMode(_ mode: AppBTMode, for app: String) {
        overrides[app] = mode == .inherit ? nil : mode
    }
}
