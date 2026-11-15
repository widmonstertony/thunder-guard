# TonTon P2PGuard · 0.6.3 candidate

Native macOS monitor and content filter. The host uses SwiftUI and the embedded extension uses Apple's Network Extension API. This target builds with no LuLu source, resources, rules, helper, or login item. The old product and its upstream attribution are preserved in the repository as historical source.

The sidebar shows other apps' current connections. The first supported blocking profile is Thunder:

- **BT file uploads and downloads** rejects recognized file request and piece messages on plaintext BitTorrent TCP streams. BitTorrent metadata extensions pass. Normal HTTP, TLS, and unidentified traffic pass; encrypted, uTP and proprietary peer transfers are not covered by this protocol switch.
- **IP addresses** uses system hostname information, HTTP Host, and TLS SNI to distinguish named services, including Xunlei and its CDN. On unnamed connections, it allows standard plaintext BitTorrent metadata requests and their matched responses, plus DHT discovery queries and matched replies. It drops BT file messages and other unidentified or unsupported direct-to-IP transfers. If the OS has not supplied an endpoint at the start, the filter examines the first data before deciding. This mode is off by default. The separate BT toggle covers recognizable plaintext BT on named connections; encrypted or proprietary protocols inside a named connection cannot be distinguished by these rules.
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

A successful build or notarization is not runtime acceptance.
