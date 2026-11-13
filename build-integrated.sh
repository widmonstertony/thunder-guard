#!/bin/zsh
set -euo pipefail
cd "${0:A:h}"
mode="${1:---compile-only}"
case "$mode" in
    --compile-only)
        /usr/bin/python3 Integration/prepare.py
        /usr/bin/xcodebuild -project Build/IntegratedSource/LuLu.xcodeproj -scheme LuLu \
            -configuration Release -derivedDataPath Build/IntegratedDerived \
            CODE_SIGNING_ALLOWED=NO CODE_SIGNING_REQUIRED=NO build
        ;;
    --sign|--archive)
        : "${THUNDER_TEAM_ID:?Set the publishing Team ID}"
        : "${THUNDER_SIGNING_IDENTITY:?Set the full Developer ID Application certificate name}"
        : "${THUNDER_APP_PROFILE:?Set the downloaded host Developer ID profile path}"
        : "${THUNDER_EXTENSION_PROFILE:?Set the downloaded extension Developer ID profile path}"
        /usr/bin/python3 Integration/prepare.py --team "$THUNDER_TEAM_ID" --identity "$THUNDER_SIGNING_IDENTITY"
        task_action=build
        task_archive_args=()
        task_source='Build/IntegratedDerived/Build/Products/Release/ThunderGuard.app'
        if [[ "$mode" == '--archive' ]]; then
            task_action=archive
            task_archive_args=(-archivePath Build/ThunderGuard-Integrated.xcarchive)
            task_source='Build/ThunderGuard-Integrated.xcarchive/Products/Applications/ThunderGuard.app'
        fi
        /usr/bin/xcodebuild -project Build/IntegratedSource/LuLu.xcodeproj -scheme LuLu \
            -configuration Release -derivedDataPath Build/IntegratedDerived "${task_archive_args[@]}" \
            CODE_SIGNING_ALLOWED=NO CODE_SIGNING_REQUIRED=NO "$task_action"
        /usr/bin/python3 Integration/sign.py --team "$THUNDER_TEAM_ID" --identity "$THUNDER_SIGNING_IDENTITY" \
            --app-profile "$THUNDER_APP_PROFILE" --extension-profile "$THUNDER_EXTENSION_PROFILE" \
            --source "$task_source"
        if [[ "$mode" == '--archive' ]]; then
            /usr/bin/python3 - <<'PYARCHIVE'
import os, pathlib, plistlib, shutil
archive = pathlib.Path('Build/ThunderGuard-Integrated.xcarchive')
target = archive / 'Products/Applications/ThunderGuard.app'
shutil.rmtree(target)
shutil.copytree('Build/IntegratedSigned/ThunderGuard.app', target, symlinks=True)
path = archive / 'Info.plist'
info = plistlib.loads(path.read_bytes())
info['Name'] = 'Thunder Guard'
info['ApplicationProperties'].update(SigningIdentity=os.environ['THUNDER_SIGNING_IDENTITY'],
                                     Team=os.environ['THUNDER_TEAM_ID'])
path.write_bytes(plistlib.dumps(info))
PYARCHIVE
            print 'Developer ID archive: Build/ThunderGuard-Integrated.xcarchive'
            print 'Not a release: finish notarization and activation testing before installing.'
        fi
        exit 0
        ;;
    *) print -u2 'Usage: ./build-integrated.sh [--compile-only|--sign|--archive]'; exit 2 ;;
esac
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
