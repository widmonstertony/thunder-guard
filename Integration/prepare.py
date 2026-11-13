#!/usr/bin/env python3
"""Generate a source-integrated LuLu fork without changing the upstream snapshot.

Unsigned output is compile-only. It must never be installed as a working filter.
"""
import argparse
import hashlib
import json
import pathlib
import plistlib
import re
import shutil
import subprocess

REPO = pathlib.Path(__file__).resolve().parents[1]
PREFIX = 'org.thunderguard.firewall'
FILTER_ROOT = '/Library/Application Support/ThunderGuard/Firewall'


def replace_once(path, old, new):
    text = path.read_text()
    if text.count(old) != 1:
        raise RuntimeError(f'Upstream integration anchor changed: {path.name}: {old[:60]}')
    path.write_text(text.replace(old, new, 1))


def make_icon(directory):
    iconset = directory / 'ThunderGuard.iconset'
    iconset.mkdir()
    for size in [16, 32, 128, 256, 512]:
        for suffix, pixels in [('', size), ('@2x', size * 2)]:
            subprocess.run(['/usr/bin/sips', '-z', str(pixels), str(pixels),
                str(REPO / 'Assets/ThunderGuard-1024.png'), '--out',
                str(iconset / f'icon_{size}x{size}{suffix}.png')], check=True, stdout=subprocess.DEVNULL)
    subprocess.run(['/usr/bin/iconutil', '-c', 'icns', str(iconset), '-o',
                    str(directory / 'ThunderGuard.icns')], check=True)
    shutil.rmtree(iconset)


def generate(destination, team, identity):
    if not re.fullmatch(r'[A-Z0-9]{10}', team):
        raise ValueError('Team ID must contain exactly 10 uppercase letters/digits')
    if not re.fullmatch(r'Developer ID Application: [^"\\\n]+ \(' + team + r'\)', identity):
        raise ValueError('Use a Developer ID Application identity matching the team')
    if destination.exists():
        shutil.rmtree(destination)
    shutil.copytree(REPO / 'Vendor/LuLu/LuLu', destination)
    integration = destination / 'Integrated'
    integration.mkdir()
    # Use distinct identifiers and storage; never impersonate the signed upstream.
    for path in destination.rglob('*'):
        if path.suffix not in {'.m', '.h', '.plist', '.entitlements', '.xcscheme', '.pbxproj'}:
            continue
        text = path.read_text()
        text = text.replace('com.objective-see.lulu', PREFIX)
        text = text.replace('VBG97UB4TA', team)
        text = text.replace('Developer ID Application: Objective-See, LLC (' + team + ')', identity)
        text = text.replace('/Library/Objective-See/LuLu', FILTER_ROOT)
        text = text.replace('LuLu.app', 'ThunderGuard.app')
        text = text.replace('findProcesses(@"LuLu")', 'findProcesses(@"ThunderGuard")')
        path.write_text(text)
    # The fork starts at 0.5.0; retaining LuLu's >=2.0.0 check would reject it.
    replace_once(destination / 'Extension/XPCListener.m',
                 r'>= \"2.0.0\"', r'>= \"0.5.0\"')

    for name in ['IntegratedHost.swift', 'NativeBridge.h', 'NativeBridge.m', 'BridgingHeader.h']:
        shutil.copyfile(REPO / 'Integration' / name, integration / name)
    make_icon(integration)
    for name in ['NetworkDashboard.swift', 'DecisionStore.swift', 'ProtectionStore.swift',
                 'CloudMagnetView.swift', 'guard.py', 'network_snapshot.py']:
        text = (REPO / 'Sources' / name).read_text()
        text = text.replace('com.objective-see.lulu', PREFIX)
        text = text.replace('/Library/Objective-See/LuLu', FILTER_ROOT)
        text = text.replace('/Applications/LuLu.app', '/Applications/ThunderGuard.app')
        if name == 'NetworkDashboard.swift':
            # The native rule editor replaces the legacy external-app launcher.
            start = text.index('    private func openLuLuRules() {')
            end = text.index('\n    private func ', start + 1)
            text = text[:start] + text[end:]
        if name == 'ProtectionStore.swift':
            text = text.replace('let filterEnabled: Bool', 'var filterEnabled: Bool')
            text = text.replace('case .success(let value): snapshot = value; error = nil',
                'case .success(var value): value.filterEnabled = TGNativeBridge.filterEnabled(); snapshot = value; error = nil')
        (integration / name).write_text(text)

    delegate = destination / 'App/AppDelegate.m'
    replace_once(delegate, '#import "AppDelegate.h"',
        '#import "AppDelegate.h"\n#import "ThunderGuard-Swift.h"')
    replace_once(delegate, '        [self showPreferences:nil];',
        '        [[TGDashboardHost shared] show];')
    replace_once(delegate, '    //cleanup any expired/temp rules',
        '    if(YES == launchedByUser()) { [[TGDashboardHost shared] show]; }\n\n    //cleanup any expired/temp rules')
    # Avoid an upstream updater offering to replace this fork with LuLu.
    start = delegate.read_text().index('-(void)check4Update\n{')
    end = delegate.read_text().index('\n//quit button handler', start)
    text = delegate.read_text()
    delegate.write_text(text[:start] + '''-(void)check4Update
{
    [NSWorkspace.sharedWorkspace openURL:[NSURL URLWithString:@"https://github.com/widmonstertony/thunder-guard/releases"]];
}
''' + text[end:])
    # Automatic checks must not open a browser at login.
    replace_once(delegate, 'if( (YES != launchedByUser()) &&', 'if( NO && (YES != launchedByUser()) &&')
    # The menu's monitor action opens the embedded view, never a helper .app.
    status = destination / 'App/StatusBarItem.m'
    replace_once(status, '#import "consts.h"', '#import "consts.h"\n#import "ThunderGuard-Swift.h"')
    text = status.read_text()
    start = text.index('        case monitor:\n')
    end = text.index('        //quit\n', start)
    status.write_text(text[:start] + '''        case monitor:
            [[TGDashboardHost shared] show];
            break;

''' + text[end:])

    info_path = destination / 'App/Info.plist'
    info = plistlib.loads(info_path.read_bytes())
    info['CFBundleDisplayName'] = '迅雷护栏'
    info['CFBundleIconFile'] = 'ThunderGuard'
    info_path.write_bytes(plistlib.dumps(info))
    ext_info_path = destination / 'Extension/Info.plist'
    info = plistlib.loads(ext_info_path.read_bytes())
    info['CFBundleDisplayName'] = 'Thunder Guard Filter'
    info['NSSystemExtensionUsageDescription'] = '迅雷护栏需要启用内置网络过滤扩展来控制应用连接。'
    ext_info_path.write_bytes(plistlib.dumps(info))

    project_path = destination / 'LuLu.xcodeproj/project.pbxproj'
    project = json.loads(subprocess.check_output(['/usr/bin/plutil', '-convert', 'json', '-o', '-', str(project_path)]))
    objects = project['objects']
    app = next(
        value for value in objects.values() if value.get('isa') == 'PBXNativeTarget' and value.get('name') == 'LuLu')
    sources = next(objects[key] for key in app['buildPhases'] if objects[key]['isa'] == 'PBXSourcesBuildPhase')
    resources = next(objects[key] for key in app['buildPhases'] if objects[key]['isa'] == 'PBXResourcesBuildPhase')
    # No second .app, including the optional Netiquette utility, is bundled.
    resources['files'] = [key for key in resources['files'] if objects[key].get('fileRef') != 'CDC378C9250C83F100314064']
    group_id = hashlib.sha256(b'ThunderGuard.Integrated').hexdigest()[:24].upper()
    group = {'isa': 'PBXGroup', 'path': 'Integrated', 'sourceTree': '<group>', 'children': []}
    objects[group_id] = group
    objects[objects[project['rootObject']]['mainGroup']]['children'].append(group_id)
    for path in sorted(integration.iterdir()):
        if path.suffix == '.h':
            kind = 'sourcecode.c.h'
        elif path.suffix == '.m':
            kind = 'sourcecode.c.objc'
        elif path.suffix == '.swift':
            kind = 'sourcecode.swift'
        elif path.suffix == '.icns':
            kind = 'image.icns'
        else:
            kind = 'text.script.python'
        ref = hashlib.sha256(('ref.' + path.name).encode()).hexdigest()[:24].upper()
        build = hashlib.sha256(('build.' + path.name).encode()).hexdigest()[:24].upper()
        objects[ref] = {'isa': 'PBXFileReference', 'path': path.name, 'sourceTree': '<group>', 'lastKnownFileType': kind}
        group['children'].append(ref)
        if path.suffix != '.h':
            objects[build] = {'isa': 'PBXBuildFile', 'fileRef': ref}
            (sources if path.suffix in {'.m', '.swift'} else resources)['files'].append(build)
    for value in objects.values():
        if value.get('isa') != 'XCBuildConfiguration':
            continue
        settings = value['buildSettings']
        settings.update(DEVELOPMENT_TEAM=team, MACOSX_DEPLOYMENT_TARGET='14.0')
        if 'PRODUCT_BUNDLE_IDENTIFIER' not in settings:
            continue
        settings.update(CODE_SIGN_IDENTITY=identity, MARKETING_VERSION='0.5.0', CURRENT_PROJECT_VERSION='10',
                        PROVISIONING_PROFILE_SPECIFIER='', ENABLE_HARDENED_RUNTIME='YES')
        settings['DEVELOPMENT_TEAM[sdk=macosx*]'] = team
        settings['CODE_SIGN_IDENTITY[sdk=macosx*]'] = identity
        if settings['PRODUCT_BUNDLE_IDENTIFIER'] == PREFIX + '.app':
            settings.update(PRODUCT_NAME='ThunderGuard', PRODUCT_MODULE_NAME='ThunderGuard', SWIFT_VERSION='5.0',
                ASSETCATALOG_COMPILER_APPICON_NAME='',
                SWIFT_OBJC_BRIDGING_HEADER='Integrated/BridgingHeader.h',
                HEADER_SEARCH_PATHS=['$(inherited)', '$(SRCROOT)/App', '$(SRCROOT)/Shared', '$(SRCROOT)/Integrated'])
    # Embed the source-built extension on ordinary builds, not only archive.
    for key in app['buildPhases']:
        phase = objects[key]
        if phase.get('isa') == 'PBXCopyFilesBuildPhase':
            phase['buildActionMask'] = 2147483647
    project_path.write_bytes(plistlib.dumps(project, sort_keys=False))
    # Keep licensing and attribution beside generated sources.
    shutil.copyfile(REPO / 'Vendor/LuLu/LICENSE.md', destination / 'LuLu-LICENSE.md')
    shutil.copyfile(REPO / 'LICENSE.md', destination / 'ThunderGuard-LICENSE.md')
    return project_path.parent


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--team', default='UNSIGNED00')
    parser.add_argument('--identity', default='Developer ID Application: Unsigned source build (UNSIGNED00)')
    args = parser.parse_args()
    print(generate(REPO / 'Build/IntegratedSource', args.team, args.identity))
