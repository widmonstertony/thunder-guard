# TonTon P2PGuard · 0.7.0

Native macOS monitor and content filter. The host uses SwiftUI and the embedded extension uses Apple's Network Extension API. This target builds with no LuLu source, resources, rules, helper, or login item. The old product and its upstream attribution are preserved in the repository as historical source.

The dashboard starts on **All Apps**. It shows visible connections and denials for the selected app, and can watch an installed app before it is running.

The menu bar shows upload and download speeds. Its popover shows network statistics and recent denials by app; the three denial counters also filter the displayed records. The last ten minutes of BT upload, BT download and other denials each have a separate limit, so IP denials cannot displace BT records.

- **BT files** is an opt-in rule for all apps or an individual app. An app can inherit the global setting, block BT files even when the global setting is off, or be exempt from the global rule. The scope is recognized file request and piece messages on plaintext BitTorrent TCP streams. BitTorrent metadata, ordinary HTTP/TLS, and unrecognized protocols pass. This setting does not detect encrypted BitTorrent, uTP or proprietary peer protocols. Apps whose identity cannot be confirmed can inherit the global setting but have no individual rule.
- Thunder's optional **IP addresses** rule remains separate in its settings. It uses system hostname information, HTTP Host, TLS SNI and Xunlei CDN handling to preserve named services. On unnamed connections it permits supported plaintext BitTorrent metadata and DHT discovery, and rejects file messages or unsupported direct-to-IP traffic. Existing Thunder rules are migrated without turning on global blocking.
- The main map shows observed connections in blue and guard denials in red. The event inspector separates BT upload, BT download and other denials, and shows the peer address, process, time, and reason. A file request and an actual file data block are labelled separately. IP lookup uses bundled offline country ranges where available; the map does not mark the user's exact location or invent one for unknown peers.

Support: [GitHub Issues](https://github.com/widmonstertony/thunder-guard/issues).

## Build and test

```sh
python3 P2PGuard/build.py
python3 -m unittest discover -s Tests -v
```

Requires Xcode and a macOS SDK with Swift Charts and the Network Extension frameworks. The universal unsigned build is a compile check only. For a local system-extension test, set `THUNDER_TEAM_ID`, `THUNDER_SIGNING_IDENTITY`, `THUNDER_APP_PROFILE` and `THUNDER_EXTENSION_PROFILE` and run `P2PGuard/archive.sh`. The archive contains `TonTon P2PGuard.app` and retains the existing bundle IDs and application group so the filter can update in place. Developer ID profiles must separately authorize the host and its embedded system extension. The signed archive requires notarization before standard installation.

To bundle the offline country map, put the pinned [DB-IP Country Lite CSV](https://download.db-ip.com/free/dbip-country-lite-2026-11.csv.gz) and [Natural Earth country shapes](https://raw.githubusercontent.com/nvkelso/natural-earth-vector/v5.1.2/geojson/ne_110m_admin_0_countries.geojson) in `Build/Geography/`, then run `python3 P2PGuard/prepare_geography.py` before building. The script checks both inputs against their expected hashes. Without this data, public endpoints are grouped under Unknown.

## Acceptance

Use a controlled fixture with a known hash. Keep unrelated filters and original files unchanged. To test the **IP addresses** rule, leave the BT file switch off and verify:

1. Thunder displays a fresh magnet's file list before downloading the file.
2. A small cloud file retrieves to a separate local path and matches its original hash.
3. A controlled numeric peer supplies valid BEP 9 metadata, then tries to send and receive a file piece. Confirm that the metadata arrived, each piece did not arrive, and the same transfer triggered the guard's directional **BT 文件上传** and **BT 文件下载** records. A connection refused before metadata or a generic address denial does not satisfy this check.

The separate BT file rule has a different acceptance test: a controlled peer's file request or transfer should trigger distinct **BT 文件上传** and **BT 文件下载** verdicts. Do not count an address denial as a protocol verdict.

Run `python3 Tests/live_p2p_acceptance.py` on the Mac after enabling the IP rule. It exercises a TCP client and server over loopback without touching the installed Thunder, Mini, or LuLu. It requires both a peer-side result and a matching guard event. Use `--baseline` on an already permissive test system to confirm the fixture can transfer both ways. A passing run still needs a separate real Thunder magnet and cloud test.

For a change to the all-apps engine, also test a non-Thunder client with the default off, with a per-app block, and with an explicit exemption under the global rule. Keep the opposite peer outside the rule (for example on a second Mac), verify that the client still reads metadata and that ordinary HTTP/TLS still work in the same configuration, and attribute the block to the corresponding app in the UI. A denied connection or a decision recorded against the opposite peer cannot count as a file block for the client.

Run `python3 Tests/live_app_acceptance.py prepare Build/PeerQA`, add the resulting `TonTon Peer QA.app` in the sidebar, and keep the global rule off. Run `python3 Tests/live_app_acceptance.py verify Build/PeerQA allow` with the per-app rule inherited, then `python3 Tests/live_app_acceptance.py verify Build/PeerQA block` with only that app blocked. Both runs use the same signed app for HTTPS and file transfer, and check peer-side data plus the filter's decision. Tests use synthetic file data and do not access your existing download tasks.

A successful build or notarization is not runtime acceptance.

## Mac App Store

The [Mac App Store target](Store/README.md) uses a sandboxed host and an authenticated local feed from its embedded filter. The Developer ID build described above is for direct distribution and uses the local system log to read its own denials. Both share the filtering engine and UI.
