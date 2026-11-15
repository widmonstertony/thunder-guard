#!/usr/bin/env python3
"""Build the independent native app. Signing is a separate step."""
import argparse
import pathlib
import plistlib
import re
import shutil
import subprocess

HERE = pathlib.Path(__file__).resolve().parent
ROOT = HERE.parent
PREFIX = 'org.thunderguard.firewall'
APP = PREFIX + '.app'
EXTENSION = PREFIX + '.extension'


def plist(path, obj):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(plistlib.dumps(obj))


def bundle(path, name, title, identifier, kind, extra):
    (path / 'Contents/MacOS').mkdir(parents=True, exist_ok=True)
    plist(path / 'Contents/Info.plist', {
        'CFBundleDevelopmentRegion': 'zh_CN', 'CFBundleDisplayName': title,
        'CFBundleName': title, 'CFBundleExecutable': name, 'CFBundleIdentifier': identifier,
        'CFBundleInfoDictionaryVersion': '6.0', 'CFBundlePackageType': kind,
        'CFBundleVersion': '16', 'CFBundleShortVersionString': '0.6.3',
        'LSMinimumSystemVersion': '14.0', **extra,
    })
    return path / 'Contents/MacOS' / name


def call(*args):
    subprocess.run(list(map(str, args)), check=True)


def build(team):
    work = ROOT / 'Build/P2PGuard'
    app = work / 'Unsigned/ThunderGuard.app'
    filter_bundle = app / 'Contents/Library/SystemExtensions' / (EXTENSION + '.systemextension')
    if app.exists():
        shutil.rmtree(app)
    group = f'{team}.{PREFIX}'
    description = 'P2P 护栏需要网络过滤扩展来执行你为迅雷选择的拦截规则。'
    host = bundle(app, 'ThunderGuard', 'P2P 护栏', APP, 'APPL', {
        'NSPrincipalClass': 'NSApplication', 'CFBundleIconFile': 'P2PGuard',
        'NSSystemExtensionUsageDescription': description,
    })
    extension = bundle(filter_bundle, EXTENSION, 'P2P 护栏网络过滤器', EXTENSION, 'SYSX', {
        'NSSystemExtensionUsageDescription': description,
        'NetworkExtension': {'NEMachServiceName': f'{group}.service', 'NEProviderClasses': {
            'com.apple.networkextension.filter-data': 'PGFilterProvider'}},
    })
    resources = app / 'Contents/Resources'
    resources.mkdir()
    iconset = work / 'P2PGuard.iconset'
    iconset.mkdir(exist_ok=True)
    for size in (16, 32, 128, 256, 512):
        for suffix, pixels in (('', size), ('@2x', size * 2)):
            subprocess.run(['/usr/bin/sips', '-z', str(pixels), str(pixels), str(ROOT / 'Assets/ThunderGuard-1024.png'),
                            '--out', str(iconset / f'icon_{size}x{size}{suffix}.png')], stdout=subprocess.DEVNULL, check=True)
    call('/usr/bin/iconutil', '-c', 'icns', iconset, '-o', resources / 'P2PGuard.icns')
    shutil.copyfile(ROOT / 'LICENSE.md', resources / 'LICENSE.md')
    geography = ROOT / 'Build/Geography/Resources'
    if geography.is_dir():
        for filename in ('ip4ranges.bin', 'ip6ranges.bin', 'map-centers.json', 'Geography-NOTICE.txt'):
            shutil.copy2(geography / filename, resources / filename)
    common = {'com.apple.developer.networking.networkextension': ['content-filter-provider-systemextension'],
              'com.apple.security.application-groups': [group]}
    plist(work / 'App.entitlements', {**common, 'com.apple.developer.system-extension.install': True})
    plist(work / 'Extension.entitlements', common)
    for arch in ('arm64', 'x86_64'):
        target = arch + '-apple-macos14.0'
        call('/usr/bin/xcrun', 'swiftc', '-swift-version', '5', '-O', '-parse-as-library', '-target', target,
             '-module-cache-path', work / 'Modules', *sorted((HERE / 'App').glob('*.swift')),
             '-o', work / f'host-{arch}')
        call('/usr/bin/xcrun', 'clang', '-O2', '-fobjc-arc', '-fmodules', '-Wno-deprecated-declarations',
             f'-fmodules-cache-path={work / "Modules"}', '-target', target,
             HERE / 'Filter/Provider.m', HERE / 'Filter/PeerClassifier.c', HERE / 'Filter/EndpointPolicy.c',
             ROOT / 'Integration/ThunderPeerWire.c',
             '-framework', 'Foundation', '-framework', 'NetworkExtension', '-framework', 'Network',
             '-framework', 'Security', '-lbsm',
             '-o', work / f'filter-{arch}')
    for executable, kind in ((host, 'host'), (extension, 'filter')):
        call('/usr/bin/lipo', '-create', work / f'{kind}-arm64', work / f'{kind}-x86_64', '-output', executable)
    print(app)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--team', default='UNSIGNED00')
    args = parser.parse_args()
    if not re.fullmatch(r'[A-Z0-9]{10}', args.team):
        parser.error('Team ID must be ten uppercase letters or digits.')
    build(args.team)


if __name__ == '__main__':
    main()
