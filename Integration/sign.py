#!/usr/bin/env python3
"""Sign the source-built app with separately validated Developer ID profiles.

Private keys remain in Keychain. The output still requires notarization before
installation; signing alone does not establish runtime filtering behavior.
"""
import argparse
import datetime
import hashlib
import pathlib
import plistlib
import re
import shutil
import subprocess

ROOT = pathlib.Path(__file__).resolve().parents[1]
PREFIX = 'org.thunderguard.firewall'


def run(*args):
    return subprocess.check_output(args)


def validate_profile(path, identifier, team, fingerprint, host):
    profile = plistlib.loads(run('/usr/bin/security', 'cms', '-D', '-i', str(path)))
    if profile.get('ExpirationDate') <= datetime.datetime.now(datetime.timezone.utc).replace(tzinfo=None):
        raise ValueError('Provisioning profile has expired')
    if profile.get('TeamIdentifier') != [team] or not profile.get('ProvisionsAllDevices'):
        raise ValueError('Expected an unrestricted Developer ID profile for this team')
    if fingerprint not in {hashlib.sha1(cert).hexdigest().upper() for cert in profile['DeveloperCertificates']}:
        raise ValueError('Profile does not authorize the selected signing certificate')
    rights = profile['Entitlements']
    if rights.get('com.apple.application-identifier') != team + '.' + identifier:
        raise ValueError('Profile does not match this bundle identifier')
    if rights.get('com.apple.developer.team-identifier') != team:
        raise ValueError('Profile entitlement team mismatch')
    if 'content-filter-provider-systemextension' not in rights.get('com.apple.developer.networking.networkextension', []):
        raise ValueError('Profile does not authorize a system content filter')
    if host and rights.get('com.apple.developer.system-extension.install') is not True:
        raise ValueError('Host profile does not authorize system extension installation')
    if rights.get('get-task-allow') or rights.get('com.apple.security.get-task-allow'):
        raise ValueError('A debug profile cannot be used for distribution')
    return rights


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--team', required=True)
    parser.add_argument('--identity', required=True)
    parser.add_argument('--app-profile', required=True, type=pathlib.Path)
    parser.add_argument('--extension-profile', required=True, type=pathlib.Path)
    parser.add_argument('--source', type=pathlib.Path,
        default=ROOT / 'Build/IntegratedDerived/Build/Products/Release/ThunderGuard.app')
    args = parser.parse_args()
    identities = run('/usr/bin/security', 'find-identity', '-v', '-p', 'codesigning').decode()
    fingerprint = next((match.group(1) for line in identities.splitlines()
        if '"' + args.identity + '"' in line and 'REVOKED' not in line
        and (match := re.search(r'\b([A-F0-9]{40})\b', line))), None)
    if not fingerprint:
        raise SystemExit('The selected certificate and private key are unavailable')
    validated = []
    for suffix, profile, host in [('app', args.app_profile, True),
                                  ('extension', args.extension_profile, False)]:
        rights = validate_profile(profile, PREFIX + '.' + suffix, args.team, fingerprint, host)
        validated.append((suffix, profile, rights))

    source = args.source.resolve()
    output = ROOT / 'Build/IntegratedSigned/ThunderGuard.app'
    if source == output.resolve():
        raise ValueError('The signing output must be separate from its source')
    if output.exists():
        shutil.rmtree(output)
    shutil.copytree(source, output, symlinks=True)
    extension = output / 'Contents/Library/SystemExtensions' / (PREFIX + '.extension.systemextension')
    # Sign inside out, without --deep; every executable bundle is accounted for.
    for suffix, profile, rights in reversed(validated):
        bundle = output if suffix == 'app' else extension
        info = plistlib.loads((bundle / 'Contents/Info.plist').read_bytes())
        if info['CFBundleIdentifier'] != PREFIX + '.' + suffix:
            raise ValueError('Compiled bundle identifier mismatch')
        entitlement_source = ROOT / 'Build/IntegratedSource' / ('App/App.entitlements' if suffix == 'app' else 'Extension/Extension.entitlements')
        entitlements = plistlib.loads(entitlement_source.read_text().replace('$(TeamIdentifierPrefix)', args.team + '.').encode())
        for key in ['com.apple.application-identifier', 'com.apple.developer.team-identifier']:
            entitlements[key] = rights[key]
        allowed_groups = rights.get('com.apple.security.application-groups', [])
        for group in entitlements.get('com.apple.security.application-groups', []):
            if not any(group == allowed or (allowed.endswith('.*') and group.startswith(allowed[:-1])) for allowed in allowed_groups):
                raise ValueError('Profile does not authorize the shared application group')
        entitlements_path = ROOT / 'Build/Signing' / (suffix + '-distribution.entitlements')
        entitlements_path.parent.mkdir(parents=True, exist_ok=True)
        entitlements_path.write_bytes(plistlib.dumps(entitlements))
        shutil.copyfile(profile, bundle / 'Contents/embedded.provisionprofile')
        subprocess.run(['/usr/bin/codesign', '--force', '--sign', fingerprint, '--options', 'runtime',
                        '--timestamp', '--entitlements', str(entitlements_path), str(bundle)], check=True)
        subprocess.run(['/usr/bin/codesign', '--verify', '--strict', '--verbose=2', str(bundle)], check=True)
    subprocess.run(['/usr/bin/codesign', '--verify', '--deep', '--strict', '--verbose=2', str(output)], check=True)
    print(output)
    print('Developer ID signed. Notarization and runtime acceptance remain required.')


if __name__ == '__main__':
    main()
