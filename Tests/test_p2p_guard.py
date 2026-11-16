import pathlib
import subprocess
import tempfile
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]


class P2PGuardTests(unittest.TestCase):
    def test_store_feed_keeps_recent_bt_directions_despite_ip_denial_pressure(self):
        with tempfile.TemporaryDirectory() as temp:
            exe = pathlib.Path(temp) / 'store-feed'
            subprocess.run(['clang', '-fobjc-arc', '-Wall', '-Wextra', '-Werror',
                            str(ROOT / 'P2PGuard/Store/StoreFeed.m'), str(ROOT / 'Tests/test_store_feed.m'),
                            '-framework', 'Foundation', '-o', str(exe)], check=True)
            subprocess.run([str(exe)], check=True, cwd=temp)

    def test_network_rates_handle_interface_changes_and_sleep_gaps(self):
        with tempfile.TemporaryDirectory() as temp:
            exe = pathlib.Path(temp) / 'network-meter'
            subprocess.run(['swiftc', '-parse-as-library', '-module-cache-path', str(pathlib.Path(temp) / 'Modules'),
                            str(ROOT / 'P2PGuard/App/NetworkMeter.swift'),
                            str(ROOT / 'Tests/test_network_meter.swift'), '-o', str(exe)], check=True)
            subprocess.run([str(exe)], check=True, cwd=temp)

    def test_app_policy_migrates_and_round_trips_exceptions(self):
        with tempfile.TemporaryDirectory() as temp:
            exe = pathlib.Path(temp) / 'guard-policy'
            subprocess.run(['swiftc', '-parse-as-library', '-module-cache-path', str(pathlib.Path(temp) / 'Modules'),
                            str(ROOT / 'P2PGuard/App/GuardPolicy.swift'),
                            str(ROOT / 'Tests/test_app_policy.swift'), '-o', str(exe)], check=True)
            subprocess.run([str(exe)], check=True, cwd=temp)

    def test_web_and_metadata_pass_but_peer_file_messages_block(self):
        folder = ROOT / 'P2PGuard/Filter'
        with tempfile.TemporaryDirectory() as temp:
            exe = pathlib.Path(temp) / 'classifier'
            subprocess.run(['clang', '-std=c11', '-Wall', '-Wextra', '-Werror',
                            '-fsanitize=address,undefined', '-I', str(folder),
                            str(folder / 'PeerClassifier.c'), str(ROOT / 'Tests/test_p2p_classifier.c'),
                            '-o', str(exe)], check=True)
            subprocess.run([str(exe)], check=True, cwd=temp)

    def test_numeric_endpoints_and_fragmented_web_hostnames(self):
        folder = ROOT / 'P2PGuard/Filter'
        with tempfile.TemporaryDirectory() as temp:
            exe = pathlib.Path(temp) / 'endpoint-policy'
            subprocess.run(['clang', '-std=c11', '-Wall', '-Wextra', '-Werror',
                            '-fsanitize=address,undefined', '-I', str(folder),
                            str(folder / 'EndpointPolicy.c'), str(ROOT / 'Tests/test_endpoint_policy.c'),
                            '-o', str(exe)], check=True)
            subprocess.run([str(exe)], check=True, cwd=temp)

    def test_ip_only_provider_distinguishes_services_and_raw_peers(self):
        folder = ROOT / 'P2PGuard/Filter'
        with tempfile.TemporaryDirectory() as temp:
            exe = pathlib.Path(temp) / 'endpoint-provider'
            subprocess.run(['clang', '-fobjc-arc', '-Wno-deprecated-declarations', '-I', str(folder),
                            str(ROOT / 'Tests/test_p2p_endpoint_provider.m'), str(folder / 'PeerClassifier.c'),
                            str(folder / 'EndpointPolicy.c'), str(ROOT / 'Integration/ThunderPeerWire.c'),
                            '-framework', 'Foundation', '-framework', 'NetworkExtension',
                            '-framework', 'Network', '-framework', 'Security', '-lbsm', '-o', str(exe)], check=True)
            subprocess.run([str(exe)], check=True, cwd=temp)
