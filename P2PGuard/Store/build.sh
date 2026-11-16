#!/bin/bash
set -euo pipefail
here=$(cd -- "$(dirname -- "$0")" && pwd)
root=$(cd -- "$here/../.." && pwd)
build="$root/Build/P2PGuard/Store"
mkdir -p "$build"

python3 - "$root" <<'PY'
import json
from pathlib import Path
import subprocess
import sys

root = Path(sys.argv[1])
catalog = root / 'P2PGuard/Store/Generated/Assets.xcassets'
icon = catalog / 'AppIcon.appiconset'
icon.mkdir(parents=True, exist_ok=True)
info = dict(author='xcode', version=1)
(catalog / 'Contents.json').write_text(json.dumps(dict(info=info)))
images = []
for size in (16, 32, 128, 256, 512):
    for scale in (1, 2):
        name = f'icon-{size}@{scale}x.png'
        dim = str(size * scale)
        subprocess.run(['/usr/bin/sips', '-z', dim, dim, str(root / 'Assets/ThunderGuard-1024.png'),
                        '--out', str(icon / name)], check=True, stdout=subprocess.DEVNULL)
        images.append(dict(idiom='mac', size=f'{size}x{size}', scale=f'{scale}x', filename=name))
(icon / 'Contents.json').write_text(json.dumps(dict(info=info, images=images)))
PY

cd "$here"
xcodegen generate --spec project.yml
if [[ ${1:-} == --generate-only ]]; then exit; fi
team=()
if [[ -n ${PG_STORE_TEAM:-} ]]; then
    [[ $PG_STORE_TEAM =~ ^[A-Z0-9]{10}$ ]] || { echo 'Expected a ten-character Apple Developer team ID.' >&2; exit 2; }
    team+=("DEVELOPMENT_TEAM=$PG_STORE_TEAM")
fi
xcodebuild -project TonTonP2PGuardStore.xcodeproj -scheme TonTonP2PGuardStore \
    -configuration Release -destination 'generic/platform=macOS' -derivedDataPath "$build/Derived" \
    -archivePath "$build/TonTonP2PGuardStore-0.7.0-Unsigned.xcarchive" \
    CODE_SIGNING_ALLOWED=NO ONLY_ACTIVE_ARCH=NO ARCHS='arm64 x86_64' ${team[@]+"${team[@]}"} archive
