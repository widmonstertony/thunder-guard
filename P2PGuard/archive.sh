#!/bin/zsh
set -euo pipefail
cd "${0:A:h}/.."
: "${THUNDER_TEAM_ID:?Set the Developer ID team ID}"
: "${THUNDER_SIGNING_IDENTITY:?Set the Developer ID Application certificate name}"
: "${THUNDER_APP_PROFILE:?Set the host Developer ID profile path}"
: "${THUNDER_EXTENSION_PROFILE:?Set the extension Developer ID profile path}"
/usr/bin/python3 P2PGuard/build.py --team "$THUNDER_TEAM_ID"
/usr/bin/python3 Integration/sign.py --team "$THUNDER_TEAM_ID" --identity "$THUNDER_SIGNING_IDENTITY" \
    --app-profile "$THUNDER_APP_PROFILE" --extension-profile "$THUNDER_EXTENSION_PROFILE" \
    --host-entitlements Build/P2PGuard/App.entitlements --extension-entitlements Build/P2PGuard/Extension.entitlements \
    --source Build/P2PGuard/Unsigned/ThunderGuard.app --output Build/P2PGuard/Signed/ThunderGuard.app
/usr/bin/python3 - <<'PY'
import datetime, os, pathlib, plistlib, shutil
folder = pathlib.Path('Build/P2PGuard')
source = folder / 'Signed/ThunderGuard.app'
info = plistlib.loads((source / 'Contents/Info.plist').read_bytes())
product = 'TonTon P2PGuard'
archive = folder / f"{product}-{info['CFBundleShortVersionString']}.xcarchive"
application_path = f'Applications/{product}.app'
app = archive / 'Products' / application_path
shutil.copytree(source, app, symlinks=True)
(archive / 'Info.plist').write_bytes(plistlib.dumps({
    'ArchiveVersion': 2, 'CreationDate': datetime.datetime.now(datetime.timezone.utc).replace(tzinfo=None),
    'Name': product, 'SchemeName': product, 'ApplicationProperties': {
        'ApplicationPath': application_path,
        'Architectures': ['arm64', 'x86_64'], 'CFBundleIdentifier': info['CFBundleIdentifier'],
        'CFBundleShortVersionString': info['CFBundleShortVersionString'], 'CFBundleVersion': info['CFBundleVersion'],
        'SigningIdentity': os.environ['THUNDER_SIGNING_IDENTITY'], 'Team': os.environ['THUNDER_TEAM_ID'],
    },
}))
print(archive.resolve())
PY
