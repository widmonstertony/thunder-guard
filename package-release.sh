#!/bin/zsh
set -euo pipefail
cd "${0:A:h}"

version=0.4.2
upstream='Build/LuLu-4.5.3-backup.app'
if [[ ! -d "$upstream" ]]; then
    upstream='/Applications/LuLu.app'
fi
[[ -d "$upstream" ]] || { print -u2 'LuLu v4.5.3 app is required'; exit 1; }
[[ "$(/usr/libexec/PlistBuddy -c 'Print :CFBundleShortVersionString' "$upstream/Contents/Info.plist")" == '4.5.3' ]] || { print -u2 'Expected LuLu v4.5.3'; exit 1; }
/usr/bin/codesign --verify --deep --strict "$upstream"
team=$(/usr/bin/codesign -dv --verbose=2 "$upstream" 2>&1 | /usr/bin/sed -n 's/^TeamIdentifier=//p')
[[ "$team" == 'VBG97UB4TA' ]] || { print -u2 'Unexpected LuLu signing team'; exit 1; }

./build.sh
root='Build/ReleaseRoot'
scripts='Build/ReleaseScripts'
/bin/rm -rf "$root" "$scripts"
/bin/mkdir -p "$root/Applications" "$root/Library/Application Support/ThunderGuard" "$scripts" Build/Release
/usr/bin/ditto 'Build/Thunder Guard.app' "$root/Applications/Thunder Guard.app"
/usr/bin/ditto "$upstream" "$root/Library/Application Support/ThunderGuard/BundledLuLu.app"
/bin/cp LICENSE.md "$root/Library/Application Support/ThunderGuard/LICENSE.md"
/bin/cp UPSTREAM.md "$root/Library/Application Support/ThunderGuard/UPSTREAM.md"
/bin/cat > "$scripts/postinstall" <<'SCRIPT'
#!/bin/zsh
set -euo pipefail
# Retire only Thunder Guard's legacy watchdog, including for logged-out users.
# Renaming preserves a backup but prevents launchd from loading it on login.
for agent in /Users/*/Library/LaunchAgents/local.thunderguard.monitor.plist(N); do
    owner_uid=$(/usr/bin/stat -f %u "$agent")
    /bin/launchctl bootout "gui/${owner_uid}/local.thunderguard.monitor" >/dev/null 2>&1 || true
    /bin/mv "$agent" "${agent}.disabled-$(/bin/date +%Y%m%d-%H%M%S)-$$"
done
source_app='/Library/Application Support/ThunderGuard/BundledLuLu.app'
target_app='/Applications/LuLu.app'
if [[ ! -d "$target_app" ]]; then
    /usr/bin/codesign --verify --deep --strict "$source_app"
    team=$(/usr/bin/codesign -dv --verbose=2 "$source_app" 2>&1 | /usr/bin/sed -n 's/^TeamIdentifier=//p')
    [[ "$team" == 'VBG97UB4TA' ]] || exit 1
    /usr/bin/ditto "$source_app" "$target_app"
    /usr/bin/codesign --verify --deep --strict "$target_app"
fi
/bin/rm -rf "$source_app"
exit 0
SCRIPT
/bin/chmod 755 "$scripts/postinstall"
/usr/bin/pkgbuild --root "$root" --scripts "$scripts" --identifier 'local.thunderguard.bundle' --version "$version" --install-location / "Build/Release/ThunderGuard-${version}-macOS.pkg"
/usr/bin/shasum -a 256 "Build/Release/ThunderGuard-${version}-macOS.pkg" > "Build/Release/ThunderGuard-${version}-macOS.pkg.sha256"
