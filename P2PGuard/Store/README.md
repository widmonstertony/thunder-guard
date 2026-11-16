# TonTon P2PGuard for the Mac App Store

This target shares the main app, menu bar, and filtering code. It embeds Apple's system-extension content filter. The app's sandbox does not read system logs or run `nettop`. After the user enables connection observation, the provider reports recent endpoint, process and byte-count information to the host on this Mac. The host and extension each authenticate the other's code signature, and connected clients can only see records from their own user ID. The feed is read-only; settings still go through macOS Network Extension preferences. No packet payload, URL, or connection history is written to disk or sent to an external server. The optional public IP check contacts ipify only on request.

The menu bar stays compact. Its Network tab shows current bandwidth, history for the last minute, 10 minutes, hour, 24 hours or seven days, interface totals, top observed apps, local IP, gateway, DNS and on-demand TCP connection time. The long-term history stores only aggregate rates per interface on the Mac. Its P2P Blocks tab can filter by app and shows the app, endpoint, direction, time and reason for each recent verdict. A block is counted as a BT upload or download only if the provider recognized a file piece or a file piece request. An unavailable feed is shown separately from an available feed with no recent blocks.

BT upload, BT download, and other denials each have their own ten-minute history and feed limits. Repeated direct-IP denials cannot replace BT verdicts. Use the category counters to show the corresponding records in the menu or main window.

Use Xcode 27.2 and XcodeGen 2.46 or newer:

```sh
PG_STORE_TEAM=YOURTEAMID bash P2PGuard/Store/build.sh
```

This assembles an **unsigned** universal Xcode archive under `Build/P2PGuard/Store/`, and does not register identifiers, change any network filters, upload, or submit the app. For a signed archive, use `--generate-only`, open `P2PGuard/Store/TonTonP2PGuardStore.xcodeproj`, and assign the same team to both targets. The Store target identifiers are `org.thunderguard.firewall.store` and `org.thunderguard.firewall.store.filter`. Register them with the content-filter capability and provide development and distribution profiles for both. Use Apple's `content-filter-provider` entitlement in this build. The Developer ID build's `content-filter-provider-systemextension` profiles do not cover it.

The App Store upload uses Xcode's Mac App Store export and a corresponding App Store Connect app record. Before upload, use a signed test build to verify activation, app-by-app file blocking, ordinary networking, the Thunder acceptance cases, and the authenticated local feed in the sandbox. Separately verify the menu bar survives closing the window and opens it again. Do not exercise the Store provider on a production policy without deliberate activation. Apple requires final listing metadata and privacy disclosures before review.

- [System extension deployment](https://developer.apple.com/documentation/technotes/tn3134-network-extension-provider-deployment)
- [Signing a macOS app for distribution](https://developer.apple.com/documentation/xcode/creating-distribution-signed-code-for-the-mac)
- [Apple's network extension entitlements](https://developer.apple.com/documentation/bundleresources/entitlements/com.apple.developer.networking.networkextension)
