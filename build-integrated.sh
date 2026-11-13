#!/bin/zsh
set -euo pipefail
cd "${0:A:h}"
mode="${1:---compile-only}"
if [[ "$mode" != '--compile-only' ]]; then
    print -u2 'Only --compile-only is supported until signed activation is verified.'
    exit 2
fi
/usr/bin/python3 Integration/prepare.py
/usr/bin/xcodebuild -project Build/IntegratedSource/LuLu.xcodeproj -scheme LuLu \
    -configuration Release -derivedDataPath Build/IntegratedDerived \
    CODE_SIGNING_ALLOWED=NO CODE_SIGNING_REQUIRED=NO build
/usr/bin/python3 - <<'PY'
import pathlib, plistlib
app = pathlib.Path('Build/IntegratedDerived/Build/Products/Release/ThunderGuard.app')
assert not list(app.rglob('*.app')), 'Unexpected nested application'
extensions = list((app / 'Contents/Library/SystemExtensions').glob('*.systemextension'))
assert len(extensions) == 1, 'Expected exactly one embedded filter'
for bundle, identifier in [(app, 'org.thunderguard.firewall.app'),
                           (extensions[0], 'org.thunderguard.firewall.extension')]:
    info = plistlib.loads((bundle / 'Contents/Info.plist').read_bytes())
    assert info['CFBundleIdentifier'] == identifier
    assert (bundle / 'Contents/MacOS' / info['CFBundleExecutable']).is_file()
assert (app / 'Contents/Resources/ThunderGuard.icns').is_file()
assert not (app / 'Contents/Resources/monitor.py').exists()
print('Verified: one app, one embedded filter, no watchdog or helper app.')
PY
print 'Compile-only output: Build/IntegratedDerived/Build/Products/Release/ThunderGuard.app'
print 'NOT INSTALLABLE: requires valid Network Extension profiles, Developer ID signing and notarization.'
