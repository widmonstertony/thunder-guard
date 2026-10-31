import importlib.util
import json
import pathlib
import plistlib
import re
import sqlite3
import tempfile
import unittest
from unittest import mock

SOURCE = pathlib.Path(__file__).resolve().parents[1] / 'Sources/guard.py'
spec = importlib.util.spec_from_file_location('guard', SOURCE)
guard = importlib.util.module_from_spec(spec)
spec.loader.exec_module(guard)


def fixture_archive():
    """Small LuLu-style keyed archive with an unrelated app rule."""
    u = plistlib.UID
    objects = [
        '$null',
        {'$class': u(2), 'NS.keys': [u(3)], 'NS.objects': [u(4)]},
        {'$classname': 'NSDictionary'},
        'unrelated:key',
        {'$class': u(2), 'NS.keys': [u(5)], 'NS.objects': [u(6)]},
        'rules',
        {'$class': u(7), 'NS.objects': [u(8)]},
        {'$classname': 'NSArray'},
        {'$class': u(9), 'key': 'unrelated:key', 'uuid': 'fixture-uuid',
         'path': '/Applications/Unrelated.app/Contents/MacOS/Unrelated',
         'name': 'Unrelated', 'endpointAddr': 'example.org',
         'endpointPort': '443', 'type': 3, 'scope': 1, 'action': 1},
        {'$classname': 'Rule'},
    ]
    return plistlib.dumps({'$objects': objects, '$top': {'root': u(1)}},
                          fmt=plistlib.FMT_BINARY)


class GuardTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = pathlib.Path(self.temp.name)
        self.rule_file = self.root / 'rules.plist'
        self.rule_file.write_bytes(fixture_archive())
        self.components = [
            {'key': f'{identifier}:Developer ID Application: Test',
             'id': identifier,
             'authority': 'Developer ID Application: Test',
             'path': f'/Applications/Thunder.app/{identifier}'}
            for identifier in ('com.xunlei.Thunder', 'com.xunlei.DownloadService')
        ]
        for patcher in (
            mock.patch.object(guard, 'RULES', self.rule_file),
            mock.patch.object(guard, 'OUT', self.root / 'out'),
            mock.patch.object(guard, 'STATE', self.root / 'state'),
            mock.patch.object(guard, 'signed_components', return_value=self.components),
        ):
            patcher.start()
            self.addCleanup(patcher.stop)

    def test_archive_round_trip_keeps_other_apps_and_required_fields(self):
        baseline = guard.as_export(guard.Archive(self.rule_file.read_bytes()))
        dns = ['100.100.100.100', 'fd7a:115c:a1e0::53']
        result = guard.prepare(['speed.cloudflare.com', '.xunlei.com'], dns=dns)
        generated = json.loads(pathlib.Path(result['output']).read_text())
        self.assertEqual(baseline['unrelated:key'], generated['unrelated:key'])
        for component in self.components:
            rules = generated[component['key']]
            self.assertEqual((rules[0]['endpointAddr'], rules[0]['endpointPort'], rules[0]['action']), ('*', '*', 0))
            expected = [(address, '53', 1) for address in dns]
            if component['id'] == 'com.xunlei.Thunder':
                expected += [('speed.cloudflare.com', '80', 1), ('speed.cloudflare.com', '443', 1),
                             (r'(?:[a-zA-Z0-9-]+[.])*xunlei\.com$', '443', 1)] + [(host, port, 1) for host, ports in guard.UI_SERVICE_PORTS.items() for port in ports]
            self.assertEqual([(r['endpointAddr'], r['endpointPort'], r['action']) for r in rules[1:]], expected)
            self.assertEqual([r['isEndpointAddrRegex'] for r in rules[1:]],
                             [0] * len(dns) + ([0, 0, 1, 0, 0, 0] if component['id'] == 'com.xunlei.Thunder' else []))
        for rules in generated.values():
            for rule in rules:
                for key in ('key', 'uuid', 'path', 'name', 'endpointAddr', 'endpointPort', 'type', 'scope', 'action'):
                    self.assertIn(key, rule)
        self.assertEqual(self.rule_file.read_bytes(), pathlib.Path(result['backup']).read_bytes())

    def test_domain_regex_matches_lulu_full_string_semantics(self):
        pattern, kind = guard.rule_endpoint('.xunlei.com')
        self.assertEqual(kind, 1)
        for host in ('xunlei.com', 'api-pan.xunlei.com', 'images.client.vip.xunlei.com'):
            self.assertIsNotNone(re.fullmatch(pattern, host))
        for host in ('evilxunlei.com', 'xunlei.com.evil.test', 'https://evil.test/xunlei.com'):
            self.assertIsNone(re.fullmatch(pattern, host))
        self.assertEqual(guard.display_endpoint({'endpointAddr': pattern, 'isEndpointAddrRegex': 1}), '.xunlei.com')

    def test_rejects_wildcard_and_path_injection(self):
        self.assertEqual(guard.valid_endpoint('2606:4700:7::da'), '2606:4700:7::da')
        self.assertEqual(guard.valid_endpoint('.xunlei.com'), '.xunlei.com')
        for value in ('*.xunlei.com', 'host/../../tmp', '1.2.3.4:443', 'example..com'):
            with self.assertRaises(ValueError):
                guard.valid_endpoint(value)

    def test_cloud_cdn_resolution_only_allows_exact_ips_on_443(self):
        host = 'vod3429-aliyun04-vip-lixian.xunlei.com'
        self.assertEqual(guard.valid_cloud_host(host), host)
        for other in ('hub5u.v6.phub.sandai.net', 'peer.xunlei.com',
                      'vod3429-aliyun04-vip-lixian.xunlei.com.evil.test'):
            with self.assertRaises(ValueError):
                guard.valid_cloud_host(other)
        result = guard.prepare([], dns=['100.100.100.100'], cloud_hosts=[host],
                               resolver=lambda _: ['111.63.172.45', '240e:940:a03:a00::1'])
        generated = json.loads(pathlib.Path(result['output']).read_text())
        service = self.components[1]
        allowed = {(r['endpointAddr'], r['endpointPort']) for r in generated[service['key']]
                   if r['action'] == 1}
        self.assertIn(('111.63.172.45', '443'), allowed)
        self.assertIn(('240e:940:a03:a00::1', '443'), allowed)
        self.assertNotIn(('*', '1500'), allowed)
        self.assertNotIn(('111.63.172.45', '80'), allowed)
        self.assertNotIn(('speed.cloudflare.com', '443'), allowed)
        self.assertNotIn((r'(?:[a-zA-Z0-9-]+[.])*xunlei\.com$', '443'), allowed)

    def test_active_cloud_hosts_ignores_peer_urls_and_private_link_parameters(self):
        db_path = self.root / 'tasks.db'
        with sqlite3.connect(db_path) as db:
            db.execute('CREATE TABLE etm_task (state INTEGER, create_time INTEGER, create_param TEXT, '
                       'origin_bytes INTEGER, p2p_Bytes INTEGER, dcdn_Bytes INTEGER)')
            tasks = [
                (1, 3, {'source': 'cloud/getback', 'url': 'https://vod0418-z01-vip-lixian.xunlei.com/download?token=secret'}),
                (1, 2, {'source': 'cloud/getback', 'url': 'https://peer.example.com/download'}),
                (1, 1, {'source': 'url', 'url': 'https://vod0999-z01-vip-lixian.xunlei.com/download'}),
            ]
            db.executemany('INSERT INTO etm_task VALUES (?, ?, ?, ?, ?, ?)',
                           [(state, created, json.dumps(task), 100, 0, 0)
                            for state, created, task in tasks])
        self.assertEqual(guard.active_cloud_hosts(db_path),
                         ['vod0418-z01-vip-lixian.xunlei.com'])
        self.assertEqual(guard.active_cloud_counters(db_path),
                         {'origin': 200, 'p2p': 0, 'dcdn': 0})


if __name__ == '__main__':
    unittest.main()
