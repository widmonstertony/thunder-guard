# Source-integrated app

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
be reused as the embedded filter under this fork's identity. End users need not
buy a developer membership to use a properly published free app.

The existing installed 0.4.x controller and original LuLu are not replaced by
this build. Signing, first-run activation, integrated rule changes, migration
and download/filter acceptance tests are still pending. The build does not
automatically apply an experimental Thunder profile and does not claim to
identify all P2P. Normal first-run macOS approval for a network filter will
still be required in a signed release.

## Signing preparation

With a paid development team, first create or import that team's Developer ID
Application certificate (including its private key) into the local keychain.
Apple may require the team's Account Holder to create this certificate; an
App Store Connect Admin role alone does not guarantee that permission.

Register the two explicit identifiers `org.thunderguard.firewall.app` and
`org.thunderguard.firewall.extension`. Both need Network Extensions and App Groups;
the host also needs System Extension. Create one Developer ID provisioning
profile for each identifier using the publishing certificate. The shared macOS
app group uses the team-prefixed format, so it does not need a separate portal
registration.

Set these variables locally and run `./build-integrated.sh --sign`:

```sh
export THUNDER_TEAM_ID='YOURTEAMID'
export THUNDER_SIGNING_IDENTITY='Developer ID Application: Your Name (YOURTEAMID)'
export THUNDER_APP_PROFILE='/absolute/path/to/host.provisionprofile'
export THUNDER_EXTENSION_PROFILE='/absolute/path/to/filter.provisionprofile'
./build-integrated.sh --sign
```

This builds with the exact publisher requirement, validates both profiles for
the bundle ID, team, certificate, expiration, distribution scope and required
capabilities, then signs the embedded extension before the host. It retains the
private key in Keychain and requests Apple's secure timestamp. The output in
`Build/IntegratedSigned/ThunderGuard.app` is **signed but not yet notarized**.
Notarize and staple before installation, then verify system-extension activation
and actual traffic behavior. Source compilation and signature checks cannot
substitute for those runtime tests.

Alternatively, with the same variables, `--archive` creates a Developer ID signed
Xcode archive for notarization in Organizer. It uses the same profile validation
and signing process, without requiring Xcode to create another development
certificate. No certificate, private key or login token is written into tracked
source. Signed activation and traffic acceptance must pass before a release can
be delivered.

LuLu v4.5.3 copyright belongs to Objective-See and its contributors. Its source
and GPL-3.0 license remain in `Vendor/LuLu/`; generated copies include the
upstream license. Integration changes and Thunder Guard are GPL-3.0 as stated in
the repository [LICENSE.md](../LICENSE.md).
