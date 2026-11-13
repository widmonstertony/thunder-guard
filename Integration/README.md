# Source-integrated app — compile-only

This development target builds LuLu's GPL-3.0 Objective-C app and content-filter
extension together with Thunder Guard's SwiftUI dashboard. There is one main
`ThunderGuard.app` executable, an embedded system extension, and no nested LuLu or
Netiquette application. Native rule editing and XPC communication live in the
same main process. No watchdog relaunches the app after quitting.

Run `./build-integrated.sh --compile-only`. It generates a fork in
`Build/IntegratedSource/`, leaving the pinned `Vendor/LuLu/` snapshot unchanged,
then builds both the arm64 and x86_64 app and extension. The generated app is
**not a usable firewall release**. Do not install it over a working filter.

The generator gives the fork distinct bundle identifiers, storage paths, IPC
names and log identifiers. It replaces the Objective-See signing requirement
with the specified publisher's Developer ID requirement; it retains the Apple
trust-anchor, hardened-runtime and client-identity checks. The default unsigned
identity is deliberately not a real publisher identity. It disables upstream
automatic update checks so the fork cannot offer to replace itself with LuLu.

The publisher must obtain and validate Developer ID signing and provisioning
profiles for both targets, with Network Extension and system-extension
capabilities, then notarize the result. An Objective-See signed extension cannot
be reused as the embedded filter under this fork's identity. On this machine no
profile authorizes these capabilities. This prevents signed activation and
runtime testing; it is not a source-compilation problem. End users need not buy
a developer membership to use a properly published free app.

The existing installed 0.4.x controller and original LuLu are not replaced by
this build. Signing, first-run activation, integrated rule changes, migration
and download/filter acceptance tests are still pending. The build does not
automatically apply an experimental Thunder profile and does not claim to
identify all P2P. Normal first-run macOS approval for a network filter will
still be required in a signed release.

LuLu v4.5.3 copyright belongs to Objective-See and its contributors. Its source
and GPL-3.0 license remain in `Vendor/LuLu/`; generated copies include the
upstream license. Integration changes and Thunder Guard are GPL-3.0 as stated in
the repository [LICENSE.md](../LICENSE.md).
