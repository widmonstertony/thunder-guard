#!/usr/bin/env python3
"""Thunder-only LuLu rule builder. Reads LuLu's archive; never writes its live files."""
import argparse
import datetime
import ipaddress
import json
import pathlib
import plistlib
import re
import shutil
import sqlite3
import subprocess
import sys
import urllib.parse
import uuid

ROOT = pathlib.Path('/Library/Objective-See/LuLu')
APP = pathlib.Path('/Applications/Thunder.app')
OUT = pathlib.Path.home() / 'Documents' / 'ThunderGuard'
STATE = pathlib.Path.home() / 'Library' / 'Application Support' / 'ThunderGuard'
TEAM = 'SXKSDVK696'
DEFAULT_CLOUD_HOSTS = ['vod3429-aliyun04-vip-lixian.xunlei.com']
UI_SERVICE_PORTS = {'static-xl9-ssl.xunlei.com': ('80',),
                    'images.client.vip.xunlei.com': ('80',),
                    'xfile2.a.88cdn.com': ('443',)}
RULES = ROOT / 'rules.plist'
TASK_DB = pathlib.Path.home() / 'Library/Application Support/Thunder/etm3/etm_map.db'
COMPONENTS = [
    APP / 'Contents/MacOS/Thunder',
    APP / 'Contents/XPCServices/DownloadService.xpc/Contents/MacOS/DownloadService',
    APP / 'Contents/Library/LoginItems/ThunderHelper.app/Contents/MacOS/ThunderHelper',
    APP / 'Contents/Library/LaunchServices/com.xunlei.Thunder.HelperTool',
    APP / 'Contents/Bundles/XLEmbeddedPlayer.app/Contents/MacOS/XLEmbeddedPlayer',
    pathlib.Path('/Library/PrivilegedHelperTools/com.xunlei.Thunder.HelperTool'),
]


def run(*args):
    return subprocess.run(args, capture_output=True, text=True, check=False)


def signed_components():
    found = []
    for path in COMPONENTS:
        if not path.is_file():
            continue
        check = run('/usr/bin/codesign', '--verify', '--strict', str(path))
        details = run('/usr/bin/codesign', '-dvv', str(path))
        info = details.stderr
        identifier = re.search(r'^Identifier=(.+)$', info, re.M)
        authority = re.search(r'^Authority=(Developer ID Application: Xunlei[^\n]+)$', info, re.M)
        team = re.search(r'^TeamIdentifier=(.+)$', info, re.M)
        if check.returncode or not identifier or not authority or not team or team.group(1) != TEAM:
            continue
        found.append({'path': str(path), 'id': identifier.group(1),
                      'authority': authority.group(1),
                      'key': f'{identifier.group(1)}:{authority.group(1)}'})
    return found


class Archive:
    def __init__(self, data):
        self.archive = plistlib.loads(data)
        self.objects = self.archive['$objects']
        self.memo = {}

    def get(self, value):
        if isinstance(value, plistlib.UID):
            index = value.data
            if index == 0:
                return None
            if index in self.memo:
                return self.memo[index]
            raw = self.objects[index]
            if not isinstance(raw, dict):
                self.memo[index] = raw
                return raw
            cls = self.objects[raw['$class'].data]['$classname'] if '$class' in raw else ''
            if cls in ('NSDictionary', 'NSMutableDictionary'):
                output = {}
                self.memo[index] = output
                for k, v in zip(raw['NS.keys'], raw['NS.objects']):
                    output[self.get(k)] = self.get(v)
                return output
            if cls in ('NSArray', 'NSMutableArray', 'NSSet', 'NSMutableSet'):
                output = []
                self.memo[index] = output
                output.extend(self.get(v) for v in raw['NS.objects'])
                return output
            if cls == 'NSDate':
                return datetime.datetime.fromtimestamp(raw['NS.time'] + 978307200,
                                                       datetime.timezone.utc).isoformat()
            if cls == 'Rule':
                output = {}
                self.memo[index] = output
                for k, v in raw.items():
                    if k != '$class':
                        output[k] = self.get(v)
                return output
            raise ValueError(f'Unsupported archive class: {cls}')
        return value

    def root(self):
        return self.get(self.archive['$top']['root'])


def as_export(archive):
    result = {}
    for key, group in archive.root().items():
        rules = []
        for rule in group.get('rules', []):
            if rule.get('pid') or rule.get('expiration'):
                continue
            item = {name: rule[name] for name in ('key', 'uuid', 'path', 'name',
                'endpointAddr', 'endpointPort', 'type', 'action') if rule.get(name) is not None}
            # LuLu's Objective-C toJSON emits 0 for a nil NSNumber scope.
            # Its importer requires the scope field even for old default rules.
            item['scope'] = int(rule.get('scope') or 0)
            item['isEndpointAddrRegex'] = int(rule.get('isEndpointAddrRegex') or 0)
            for name in ('endpointHost', 'isDisabled'):
                if rule.get(name) is not None:
                    item[name] = rule[name]
            if rule.get('csInfo'):
                item['csInfo'] = rule['csInfo']
            created = rule.get('creation')
            if created:
                parsed = datetime.datetime.fromisoformat(created)
                item['creation'] = parsed.strftime('%Y-%m-%dT%H:%M:%S%z')
            rules.append(item)
        if rules:
            result[key] = rules
    return result


def make_rule(component, address, port, action, address_type=0):
    info = {'signatureIdentifier': component['id'],
            'signatureAuthorities': [component['authority']],
            'signatureSigner': 3, 'signatureStatus': 0}
    return {'key': component['key'], 'uuid': str(uuid.uuid4()).upper(),
            'path': component['path'], 'name': pathlib.Path(component['path']).name,
            'endpointAddr': address, 'endpointPort': port,
            'isEndpointAddrRegex': address_type, 'type': 3, 'scope': 1,
            'action': action, 'csInfo': info,
            'creation': datetime.datetime.now().astimezone().strftime('%Y-%m-%dT%H:%M:%S%z')}


def valid_endpoint(value):
    value = value.strip().lower()
    if not value or len(value) > 253 or '*' in value or '/' in value:
        raise ValueError(f'Invalid endpoint: {value!r}')
    if value.startswith('.'):
        base = value[1:]
        if not base or ':' in base or not re.fullmatch(r'[a-z0-9.-]+', base) \
                or '..' in base or base.startswith('.') or base.endswith('.'):
            raise ValueError(f'Invalid endpoint: {value!r}')
        return value
    try:
        return str(ipaddress.ip_address(value))
    except ValueError:
        pass
    if not re.fullmatch(r'[a-z0-9.-]+', value) or '..' in value or value.startswith('.') or value.endswith('.'):
        raise ValueError(f'Invalid endpoint: {value!r}')
    return value


def rule_endpoint(value):
    if value.startswith('.'):
        # LuLu wraps regexes in ^(?:...)$: include the complete subdomain prefix.
        return r'(?:[a-zA-Z0-9-]+[.])*' + re.escape(value[1:]) + '$', 1
    return value, 0


def display_endpoint(rule):
    value = rule.get('endpointAddr', '')
    if rule.get('isEndpointAddrRegex') == 1:
        for prefix in (r'(^|\.)', r'(?:[a-zA-Z0-9-]+[.])*'):
            if value.startswith(prefix) and value.endswith('$'):
                base = value[len(prefix):-1].replace(r'\.', '.')
                if re.escape(base) == value[len(prefix):-1]:
                    return valid_endpoint('.' + base)
        return None
    return value if value not in ('', '*') else None


def dns_servers():
    output = run('/usr/sbin/scutil', '--dns').stdout
    servers = []
    for value in re.findall(r'^\s*nameserver\[\d+\]\s*:\s*(\S+)', output, re.M):
        try:
            address = str(ipaddress.ip_address(value))
        except ValueError:
            continue
        if address not in servers:
            servers.append(address)
    return servers


def valid_cloud_host(value):
    value = value.strip().lower()
    if not re.fullmatch(r'vod[0-9]+-[a-z0-9-]+-vip-lixian\.xunlei\.com', value):
        raise ValueError(f'Not a verified Xunlei cloud CDN hostname: {value!r}')
    return value


def active_cloud_hosts(db_path=TASK_DB):
    """Read only the CDN hostname for active cloud retrievals; never expose signed URLs."""
    if not db_path.is_file():
        return []
    hosts = set()
    try:
        with sqlite3.connect(db_path.as_uri() + '?mode=ro', uri=True, timeout=1) as db:
            rows = db.execute('SELECT create_param FROM etm_task WHERE state IN (1, 2) '
                              'ORDER BY create_time DESC LIMIT 100')
            for (raw,) in rows:
                try:
                    task = json.loads(raw)
                    if task.get('source') != 'cloud/getback':
                        continue
                    url = urllib.parse.urlsplit(task.get('url', ''))
                    if url.scheme != 'https' or url.port not in (None, 443):
                        continue
                    hosts.add(valid_cloud_host(url.hostname or ''))
                except (TypeError, ValueError, AttributeError):
                    continue
    except sqlite3.Error:
        return []
    return sorted(hosts)


def active_cloud_counters(db_path=TASK_DB):
    """Return Thunder's own transfer counters for active cloud retrieval tasks."""
    totals = {'origin': 0, 'p2p': 0, 'dcdn': 0}
    if not db_path.is_file():
        return totals
    try:
        with sqlite3.connect(db_path.as_uri() + '?mode=ro', uri=True, timeout=1) as db:
            rows = db.execute('SELECT create_param, origin_bytes, p2p_Bytes, dcdn_Bytes '
                              'FROM etm_task WHERE state IN (1, 2)')
            for raw, origin, p2p, dcdn in rows:
                try:
                    task = json.loads(raw)
                except (TypeError, ValueError):
                    continue
                if task.get('source') != 'cloud/getback':
                    continue
                totals['origin'] += max(0, origin or 0)
                totals['p2p'] += max(0, p2p or 0)
                totals['dcdn'] += max(0, dcdn or 0)
    except sqlite3.Error:
        return totals
    return totals


def resolve_cloud_host(host):
    try:
        result = subprocess.run(['/usr/bin/dscacheutil', '-q', 'host', '-a', 'name', host],
                                capture_output=True, text=True, timeout=3, check=False)
    except subprocess.TimeoutExpired as exc:
        raise RuntimeError(f'DNS lookup timed out for {host}') from exc
    addresses = {str(ipaddress.ip_address(value)) for value in
                 re.findall(r'^(?:ip_address|ipv6_address):\s*(\S+)', result.stdout, re.M)}
    if not addresses:
        raise RuntimeError(f'No addresses found for {host}')
    return sorted(addresses)


def prepare(endpoints, dns=None, cloud_hosts=None, resolver=None):
    endpoints = list(dict.fromkeys(endpoints + list(UI_SERVICE_PORTS)))
    if not RULES.is_file():
        raise FileNotFoundError('LuLu rules not initialized')
    components = signed_components()
    required = {'com.xunlei.Thunder', 'com.xunlei.DownloadService'}
    if not required.issubset({c['id'] for c in components}):
        raise RuntimeError('Main Thunder or DownloadService signature was not verified')
    dns = dns_servers() if dns is None else dns
    if not dns:
        raise RuntimeError('No system DNS servers found; cannot create working download rules')
    dns = list(dict.fromkeys(str(ipaddress.ip_address(value)) for value in dns))
    cloud_hosts = list(dict.fromkeys(valid_cloud_host(x) for x in (cloud_hosts or [])))
    resolver = resolver or resolve_cloud_host
    cloud_addresses = {}
    for host in cloud_hosts:
        cloud_addresses[host] = sorted({str(ipaddress.ip_address(ip)) for ip in resolver(host)})
        if not cloud_addresses[host]:
            raise RuntimeError(f'No addresses found for {host}')
    raw = RULES.read_bytes()
    rules = as_export(Archive(raw))
    keys = {c['key'] for c in components}
    # Remove every old rule for these signed binaries, including LuLu's auto-created
    # broad allow rules. Preserve all other apps and globals exactly as exported.
    for key in keys:
        rules.pop(key, None)
    for component in components:
        # LuLu prioritizes address:port matches over the fallback *:* block.
        items = [make_rule(component, '*', '*', 0)]
        if component['id'] in required:
            for server in dns:
                items.append(make_rule(component, server, '53', 1))
        if component['id'] == 'com.xunlei.Thunder':
            for endpoint in endpoints:
                address, address_type = rule_endpoint(endpoint)
                ports = UI_SERVICE_PORTS.get(endpoint, ('443',) if endpoint.startswith('.') else ('80', '443'))
                for port in ports:
                    items.append(make_rule(component, address, port, 1, address_type))
        if component['id'] == 'com.xunlei.DownloadService':
            for address in sorted({ip for values in cloud_addresses.values() for ip in values}):
                items.append(make_rule(component, address, '443', 1))
        rules[component['key']] = items
    OUT.mkdir(parents=True, exist_ok=True)
    timestamp = datetime.datetime.now().strftime('%Y%m%d-%H%M%S')
    backup = OUT / f'lulu-rules-before-{timestamp}.plist'
    output = OUT / f'LuLu-ThunderGuard-{timestamp}.json'
    backup.write_bytes(raw)
    output.write_text(json.dumps(rules, ensure_ascii=False, indent=2) + '\n')
    manifest = {'output': str(output), 'backup': str(backup),
                'componentIDs': [c['id'] for c in components],
                'allowEndpoints': endpoints, 'dnsServers': dns,
                'cloudHosts': cloud_hosts, 'cloudAddresses': cloud_addresses,
                'otherRuleGroupsPreserved': len(rules)-len(components)}
    manifest_text = json.dumps(manifest, ensure_ascii=False, indent=2)
    (OUT / 'last-build.json').write_text(manifest_text)
    STATE.mkdir(parents=True, exist_ok=True)
    (STATE / 'last-build.json').write_text(manifest_text)
    return manifest


def audit():
    extensions = run('/usr/bin/systemextensionsctl', 'list').stdout
    lulu_app = run('/usr/bin/pgrep', '-x', 'LuLu').returncode == 0
    lulu_provider = run('/usr/bin/pgrep', '-x', 'com.objective-see.lulu.extension').returncode == 0
    fw = run('/usr/libexec/ApplicationFirewall/socketfilterfw', '--getglobalstate').stdout
    inbound_main = run('/usr/libexec/ApplicationFirewall/socketfilterfw', '--getappblocked', str(APP)).stdout
    inbound_service = run('/usr/libexec/ApplicationFirewall/socketfilterfw', '--getappblocked',
                          str(APP / 'Contents/XPCServices/DownloadService.xpc')).stdout
    prefs = {}
    pref_file = ROOT / 'preferences.plist'
    if pref_file.is_file():
        prefs = plistlib.loads(pref_file.read_bytes())
        profile = prefs.get('currentProfile')
        if profile and pathlib.Path(profile, 'preferences.plist').is_file():
            prefs = plistlib.loads(pathlib.Path(profile, 'preferences.plist').read_bytes())
    live = as_export(Archive(RULES.read_bytes())) if RULES.exists() else {}
    components = signed_components()
    reports = []
    allow_endpoints = set()
    current_dns = dns_servers()
    dns_ok = bool(current_dns)
    try:
        manifest = json.loads((STATE / 'last-build.json').read_text())
        cloud_hosts = manifest.get('cloudHosts') or DEFAULT_CLOUD_HOSTS
    except (OSError, ValueError):
        cloud_hosts = DEFAULT_CLOUD_HOSTS
    active_hosts = active_cloud_hosts()
    active_counters = active_cloud_counters()
    cloud_hosts = list(dict.fromkeys(cloud_hosts + active_hosts))
    cloud_ok = bool(cloud_hosts)
    strict_cloud_only = False
    cloud_ips = set()
    for host in cloud_hosts:
        try:
            cloud_ips.update(resolve_cloud_host(valid_cloud_host(host)))
        except (OSError, ValueError, RuntimeError):
            cloud_ok = False
    for c in components:
        component_rules = live.get(c['key'], [])
        block = [r for r in component_rules if r.get('endpointAddr') == '*' and r.get('endpointPort') == '*' and r.get('action') == 0 and not r.get('isDisabled')]
        reports.append({'id': c['id'], 'fallbackBlock': bool(block)})
        if c['id'] in {'com.xunlei.Thunder', 'com.xunlei.DownloadService'}:
            allowed_dns = {r.get('endpointAddr') for r in component_rules
                           if r.get('endpointPort') == '53' and r.get('action') == 1
                           and not r.get('isDisabled')}
            dns_ok = dns_ok and set(current_dns).issubset(allowed_dns)
        if c['id'] == 'com.xunlei.DownloadService':
            allowed_cdn_ips = {r.get('endpointAddr') for r in component_rules
                               if r.get('endpointPort') == '443' and r.get('action') == 1
                               and not r.get('isDisabled')}
            cloud_ok = cloud_ok and bool(cloud_ips) and cloud_ips.issubset(allowed_cdn_ips)
            strict_cloud_only = bool(block) and not prefs.get('passiveMode', False) \
                and not prefs.get('useAllowList', False) and all(
                (r.get('endpointAddr'), r.get('endpointPort')) in
                ({(ip, '443') for ip in cloud_ips} | {(ip, '53') for ip in current_dns})
                for r in component_rules if r.get('action') == 1 and not r.get('isDisabled'))
        if c['id'] == 'com.xunlei.Thunder':
            allow_endpoints.update(display_endpoint(r) for r in component_rules
                if r.get('action') == 1 and not r.get('isDisabled')
                and r.get('endpointPort') in ('80', '443')
                and r.get('endpointAddr') not in ('*', None)
                and r.get('endpointAddr') not in cloud_ips)
    lulu_active = any('com.objective-see.lulu.extension' in line and
                      'activated enabled' in line for line in extensions.splitlines())
    return {'luluExtensionActive': lulu_active,
            'luluAppRunning': lulu_app,
            'luluProviderRunning': lulu_provider,
            'firewallOn': 'State = 1' in fw,
            'inboundMainBlocked': 'blocked' in inbound_main.lower(),
            'inboundServiceBlocked': 'blocked' in inbound_service.lower(),
            'components': reports,
            'allowEndpoints': sorted(x for x in allow_endpoints if x),
            'dnsServers': current_dns,
            'dnsExceptionsPresent': dns_ok,
            'cloudHosts': cloud_hosts,
            'activeCloudHosts': active_hosts,
            'activeCloudCounters': active_counters,
            'cloudExceptionsPresent': cloud_ok,
            'strictCloudOnly': strict_cloud_only,
            'globalAllowList': bool(prefs.get('useAllowList', False)),
            'localhostBypass': bool(prefs.get('allowLocalHost', False)),
            'passiveMode': bool(prefs.get('passiveMode', False)),
            'rulesFileExists': RULES.exists()}


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('command', choices=['audit', 'prepare'])
    parser.add_argument('--allow', action='append', default=[])
    parser.add_argument('--cloud-host', action='append', default=[])
    args = parser.parse_args()
    try:
        if args.command == 'audit':
            print(json.dumps(audit(), ensure_ascii=False, indent=2))
        else:
            endpoints = list(dict.fromkeys(valid_endpoint(x) for x in args.allow))
            print(json.dumps(prepare(endpoints, cloud_hosts=args.cloud_host), ensure_ascii=False, indent=2))
    except Exception as exc:
        print(f'{type(exc).__name__}: {exc}', file=sys.stderr)
        return 1
    return 0


if __name__ == '__main__':
    sys.exit(main())
