# Thunder Guard / 迅雷护栏

Free macOS connection dashboard and Thunder firewall controller. It does not modify Thunder. Version 0.4.2 is a dashboard preview, not a finished one-click Mini replacement: outbound rule changes still require LuLu's import interface. Opening the dashboard reads existing rules and does not change network policy.

Thunder Guard respects quitting LuLu. The legacy 10-second auto-restart watchdog has been removed. The 0.4.2 package retires its old LaunchAgent and preserves a disabled backup; a source checkout can run `./uninstall-monitor.sh` for the current user. The old `install-monitor.sh` command now performs the same cleanup instead of installing a background job. No LuLu login setting, system extension or firewall rule is changed by this cleanup.

## One download, two signed components

The Release package installs Thunder Guard and, only if missing, Objective-See's signed LuLu. The user downloads one package and uses Thunder Guard as the main entry point. macOS still runs LuLu as a separate app and Network Extension. This is necessary because a custom Network Extension needs Apple's restricted entitlement; copying open-source code into an ad hoc signed app would disable the filter. Netiquette is bundled with LuLu. Source snapshots for both are in `Vendor/`, with licensing and version details in [UPSTREAM.md](UPSTREAM.md).

The package is unsigned and Thunder Guard is ad hoc signed. macOS may require the owner to explicitly allow installation/opening in Privacy & Security. LuLu itself retains its original developer signature and notarization. This project is not affiliated with Objective-See or Xunlei.

## Use

1. Install the Release package. On first run, approve LuLu's system extension in macOS if prompted.
2. The app opens directly to “网络连接”: a live upload/download chart, searchable app list, and current destination addresses, ports, connection states and byte counts. Toggle “仅外网” to include or hide local connections. The status card checks the actual filter switch, provider, rules and inbound firewall; it distinguishes existing cloud rules from the proposed hostname profile.
3. Switch to “已拦截” to see actual LuLu deny decisions received during this session, including app, destination, port and observation time. A denied port is not automatically labelled P2P. This view has no allow/block controls yet.
4. “保护详情” contains the existing advanced setup: generate and back up LuLu rules, then import the generated JSON through LuLu's Rules menu. Configure the inbound firewall with a local administrator password. LuLu has no supported rule-writing API for this separately signed controller; this release does not bypass its signature checks or rewrite its live archive.
5. For a magnet link that the local Thunder client cannot parse while peer connections are blocked, use “添加到云盘”. It validates the magnet format, copies the link locally, and opens the signed-in Xunlei cloud website. There, choose “添加” → “添加链接” and submit it as a cloud task. The controller never sends the link or reads account credentials. Cloud acceptance still depends on Xunlei and the resource.

The dashboard reads one-shot CSV samples from macOS's built-in `nettop` every three seconds. Rates are differences in process byte counters, and the chart retains about three minutes of history while the window is open. Deny decisions come from a narrowly filtered local unified-log stream, with only process path, endpoint, port and observation time retained in memory (up to 200 records). It does not retain signed URLs or traffic content, save the session, or upload snapshots. Missing log records do not prove no blocking occurred.

The experimental `peer-block` generator profile is an alternative to the earlier cloud IP allowlist. It mirrors the named-host versus direct-IP distinction observed in the user's Mini rules: LuLu can allow a flow when its URL or remote-hostname metadata contains a DNS hostname, while numeric-IP-only flows remain denied. DNS exceptions use the current system DNS servers. Additional deny rules cover `phub.sandai.net` / `shub.sandai.net` and `bt.n0808.com` subdomains, plus ports 1500, 3076, 6881–6889, 11400 and 25401, on the verified Thunder components. Cloud CDN, avatar and API domains are not individually allowlisted. Other apps' permanent rules are preserved. This profile is not applied automatically and has not completed live acceptance testing.

This is destination-based filtering, not protocol inspection. Named P2P flows may still pass, and legitimate connections with only IP metadata may still be blocked. The app does not claim to detect all P2P or guarantee zero P2P. It shows Thunder's own `origin_bytes`, `p2p_Bytes`, and `dcdn_Bytes` counters and checks LuLu's actual disabled/enabled preference in addition to the extension and process states. A running extension alone is not proof that filtering is enabled. No previous test result is displayed as a permanent live success claim.

Generate the default policy with `python3 Sources/guard.py prepare`, back up, then import the resulting JSON in LuLu. The old restrictive cloud policy remains available only as an explicit CLI option, `--policy cloud-only --cloud-host HOST`; it is not the app default.

## Build

Requires macOS 14+, Xcode command-line tools, and Python 3. Build the controller with `./build.sh`. Run `python3 -m unittest discover -s Tests -v` for rule-builder and network-sampler tests. Test decision parsing with `swiftc -parse-as-library -swift-version 5 -module-cache-path Build/ModuleCache -framework SwiftUI Sources/DecisionStore.swift Tests/test_decisions.swift -o Build/test-decisions && Build/test-decisions`. To create a local Release package, place an original signed LuLu v4.5.3 app in `/Applications/LuLu.app` or `Build/LuLu-4.5.3-backup.app` and run `./package-release.sh`.

Thunder Guard's code is GPL-3.0. See [LICENSE.md](LICENSE.md) and [UPSTREAM.md](UPSTREAM.md).
