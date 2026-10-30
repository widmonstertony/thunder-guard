# Thunder Guard / 迅雷护栏

Free macOS controller for a narrow Thunder policy: allow verified cloud retrieval endpoints, block other outbound Thunder traffic with LuLu, block inbound Thunder traffic with the macOS firewall, and inspect all apps' connections in a native visual dashboard. It does not modify Thunder.

## One download, two signed components

The Release package installs Thunder Guard and, only if missing, Objective-See's signed LuLu. The user downloads one package and uses Thunder Guard as the main entry point. macOS still runs LuLu as a separate app and Network Extension. This is necessary because a custom Network Extension needs Apple's restricted entitlement; copying open-source code into an ad hoc signed app would disable the filter. Netiquette is bundled with LuLu. Source snapshots for both are in `Vendor/`, with licensing and version details in [UPSTREAM.md](UPSTREAM.md).

The package is unsigned and Thunder Guard is ad hoc signed. macOS may require the owner to explicitly allow installation/opening in Privacy & Security. LuLu itself retains its original developer signature and notarization. This project is not affiliated with Objective-See or Xunlei.

## Use

1. Install the Release package. On first run, approve LuLu's system extension in macOS if prompted.
2. In Thunder Guard, generate and back up LuLu rules, then import the generated JSON through LuLu's Rules menu. Configure the inbound firewall with a local administrator password.
3. Open “网络总览” for a live upload/download chart, searchable app list, and current destination addresses, ports, connection states and byte counts. Toggle “仅外网” to include or hide local connections. Use “LuLu 规则” to manage per-app outbound rules; the Thunder rules tab also opens Netiquette's detailed view.
4. For a magnet link that the local Thunder client cannot parse while peer connections are blocked, use “磁力云添加”. It validates the magnet format, copies the link locally, and opens the signed-in Xunlei cloud website. There, choose “添加” → “添加链接” and submit it as a cloud task. The controller never sends the link or reads account credentials. Cloud acceptance still depends on Xunlei and the resource. If a later cloud retrieval stops at 0%, “迅雷规则” reads the active task's signed CDN URL locally, extracts its host, and includes that host in the next precise IP:443 rule build; import the new JSON through LuLu.

The dashboard reads one-shot CSV samples from macOS's built-in `nettop` every three seconds. Rates are differences in process byte counters, and the chart retains about three minutes of history while the window is open. It does not record traffic content or upload snapshots. Blocked attempts are generally absent from `nettop`; use LuLu logs to verify blocks.

The strict cloud policy gives DownloadService DNS access and precise IP:443 access only to verified `vod…-vip-lixian.xunlei.com` hosts found in active cloud retrieval tasks. The Thunder UI process retains its cloud control endpoints. The rules tab also shows Thunder's own `origin_bytes`, `p2p_Bytes`, and `dcdn_Bytes` counters for active cloud retrievals. The current policy only controls Thunder and its helpers. It does not classify P2P for every app, and neither the firewall nor Thunder's counters can prove the semantic content of encrypted HTTPS. CDN IPs can change; regenerate and import rules after such changes.

## Build

Requires macOS 14+, Xcode command-line tools, and Python 3. Build the controller with `./build.sh`. Run `python3 -m unittest discover -s Tests -v` for rule-builder and network-sampler tests. To create a local Release package, place an original signed LuLu v4.5.3 app in `/Applications/LuLu.app` or `Build/LuLu-4.5.3-backup.app` and run `./package-release.sh`.

Thunder Guard's code is GPL-3.0. See [LICENSE.md](LICENSE.md) and [UPSTREAM.md](UPSTREAM.md).
