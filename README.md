# Thunder Guard / 迅雷护栏

Free macOS controller for a narrow Thunder policy: allow verified cloud retrieval endpoints, block other outbound Thunder traffic with LuLu, block inbound Thunder traffic with the macOS firewall, and inspect all apps' connections through Netiquette. It does not modify Thunder.

## One download, two signed components

The Release package installs Thunder Guard and, only if missing, Objective-See's signed LuLu. The user downloads one package and uses Thunder Guard as the main entry point. macOS still runs LuLu as a separate app and Network Extension. This is necessary because a custom Network Extension needs Apple's restricted entitlement; copying open-source code into an ad hoc signed app would disable the filter. Netiquette is bundled with LuLu. Source snapshots for both are in `Vendor/`, with licensing and version details in [UPSTREAM.md](UPSTREAM.md).

The package is unsigned and Thunder Guard is ad hoc signed. macOS may require the owner to explicitly allow installation/opening in Privacy & Security. LuLu itself retains its original developer signature and notarization. This project is not affiliated with Objective-See or Xunlei.

## Use

1. Install the Release package. On first run, approve LuLu's system extension in macOS if prompted.
2. In Thunder Guard, generate and back up LuLu rules, then import the generated JSON through LuLu's Rules menu. Configure the inbound firewall with a local administrator password.
3. Use “查看所有 App 实时连接” to inspect connections and “管理所有 App 出站规则” to set per-app rules.

The current policy only controls Thunder and its helpers. It does not automatically classify or block P2P for every app. Allowed HTTPS may carry traffic that cannot be classified from an IP address and port. CDN IPs can change; regenerate and import rules after such changes.

## Build

Requires macOS 14+, Xcode command-line tools, and Python 3. Build the controller with `./build.sh`. Run `python3 -m unittest discover -s Tests -v` for rule-builder tests. To create a local Release package, place an original signed LuLu v4.5.3 app in `/Applications/LuLu.app` or `Build/LuLu-4.5.3-backup.app` and run `./package-release.sh`.

Thunder Guard's code is GPL-3.0. See [LICENSE.md](LICENSE.md) and [UPSTREAM.md](UPSTREAM.md).
