import Foundation

@main struct DecisionTests {
    static func main() {
        let prefix = "2026-11-12 20:18:46 Db com.objective-see.lulu.extension[457:123] [LULU] PROCESS: "
        let blocked = prefix + "/Applications/Thunder.app/Contents/XPCServices/DownloadService.xpc, FLOW (endpoint): 240e:940:a03:300::1.4000, RULE: RULE: endpoint addr: *, action: 0, verdict: 1"
        let item = DecisionStore.parse(blocked)!
        precondition(item.blocked && item.address == "240e:940:a03:300::1" && item.port == "4000")
        precondition(item.appName == "迅雷下载服务")
        let allowed = prefix + "/Applications/Example.app, FLOW (endpoint): 192.0.2.4:443, RULE: RULE: action: 1, verdict: 0"
        precondition(DecisionStore.parse(allowed)?.blocked == false)
        precondition(DecisionStore.parse(allowed)?.appName == "Example")
        precondition(DecisionStore.parse("remote endpoint: 1.2.3.4:443 / url: https://example.com/?token=secret") == nil)
        precondition(DecisionStore.parse(blocked.replacingOccurrences(of: "verdict: 1", with: "verdict: 9")) == nil)
        precondition(DecisionStore.parse(blocked.replacingOccurrences(of: ".4000", with: ".99999")) == nil)
        precondition(DecisionStore.parse(blocked.replacingOccurrences(of: "/Applications/Thunder.app", with: "relative/Thunder.app")) == nil)
        print("Decision metadata parsing: 8 checks passed")
    }
}
