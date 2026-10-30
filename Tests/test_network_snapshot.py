import importlib.util
import pathlib
import unittest

SOURCE = pathlib.Path(__file__).resolve().parents[1] / 'Sources/network_snapshot.py'
spec = importlib.util.spec_from_file_location('network_snapshot', SOURCE)
snapshot = importlib.util.module_from_spec(spec)
spec.loader.exec_module(snapshot)

CSV = '''time,,interface,state,bytes_in,bytes_out,extra,
10:00:00,Thunder.123,,,1000,2000,,
10:00:00,tcp4 127.0.0.1:5000<->*:*,lo0,Listen,,,,
10:00:00,tcp4 192.168.1.2:5000<->116.132.223.85:443,en1,Established,700,300,,
10:00:00,tcp6 fe80::1%en1.5100<->240e:940:a03:a00::1.443,en1,Established,200,50,,
10:00:00,udp4 192.168.1.2:5123<->192.168.1.5:1500,en1,,100,20,,
10:00:00,Another.App.456,,,25,30,,
10:00:00,tcp4 127.0.0.1:22<->127.0.0.1:6000,lo0,Established,25,30,,
'''


class SnapshotTests(unittest.TestCase):
    def test_process_connection_and_scope(self):
        apps = snapshot.parse_nettop(CSV)['apps']
        self.assertEqual([(app['pid'], app['name']) for app in apps],
                         [(123, 'Thunder'), (456, 'Another.App')])
        flows = apps[0]['connections']
        self.assertEqual(len(flows), 3)
        self.assertEqual((flows[0]['remote'], flows[0]['port'], flows[0]['scope']),
                         ('116.132.223.85', '443', 'internet'))
        self.assertEqual((flows[1]['remote'], flows[1]['port']),
                         ('240e:940:a03:a00::1', '443'))
        self.assertEqual((flows[2]['remote'], flows[2]['scope']),
                         ('192.168.1.5', 'local'))
        self.assertEqual(apps[1]['connections'][0]['scope'], 'loopback')

    def test_non_numeric_counters_and_incomplete_rows(self):
        data = 'time,,interface,state,bytes_in,bytes_out,\n10:00:00,App.3,,,bad,7,\n10:00:00,tcp4 1.2.3.4:1<->8.8.8.8:53,en1,,5,,\n10:00:00,bad\n'
        app = snapshot.parse_nettop(data)['apps'][0]
        self.assertEqual((app['received'], app['sent']), (0, 7))
        self.assertEqual((app['connections'][0]['received'], app['connections'][0]['sent']), (5, 0))


if __name__ == '__main__':
    unittest.main()
