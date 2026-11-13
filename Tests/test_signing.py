import datetime
import hashlib
import importlib.util
import pathlib
import plistlib
import unittest
from unittest import mock

ROOT = pathlib.Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('integrated_sign', ROOT / 'Integration/sign.py')
signing = importlib.util.module_from_spec(spec)
spec.loader.exec_module(signing)


class ProfileValidationTests(unittest.TestCase):
    def profile(self):
        return dict(ExpirationDate=datetime.datetime.now() + datetime.timedelta(days=30),
            TeamIdentifier=['TESTTEAM01'], ProvisionsAllDevices=True,
            DeveloperCertificates=[b'certificate fixture'], Entitlements={
                'com.apple.application-identifier': 'TESTTEAM01.org.thunderguard.firewall.app',
                'com.apple.developer.team-identifier': 'TESTTEAM01',
                'com.apple.developer.networking.networkextension': ['content-filter-provider-systemextension'],
                'com.apple.developer.system-extension.install': True})

    def validate(self, profile, fingerprint=None):
        with mock.patch.object(signing, 'run', return_value=plistlib.dumps(profile)):
            return signing.validate_profile(pathlib.Path('fixture'), 'org.thunderguard.firewall.app',
                'TESTTEAM01', fingerprint or hashlib.sha1(b'certificate fixture').hexdigest().upper(), True)

    def test_distribution_profile_is_accepted(self):
        self.assertTrue(self.validate(self.profile())['com.apple.developer.system-extension.install'])

    def test_unrelated_or_debug_profiles_are_rejected(self):
        for mutate in [
            lambda p: p.update(TeamIdentifier=['OTHERTEAM0']),
            lambda p: p.update(ProvisionsAllDevices=False),
            lambda p: p.update(ExpirationDate=datetime.datetime(2000, 1, 1)),
            lambda p: p['Entitlements'].update({'com.apple.application-identifier': 'TESTTEAM01.other.app'}),
            lambda p: p['Entitlements'].update({'com.apple.security.get-task-allow': True}),
            lambda p: p['Entitlements'].pop('com.apple.developer.system-extension.install'),
            lambda p: p['Entitlements'].update({'com.apple.developer.networking.networkextension': ['packet-tunnel-provider']}),
        ]:
            profile = self.profile()
            mutate(profile)
            with self.subTest(profile=profile), self.assertRaises(ValueError):
                self.validate(profile)
        with self.assertRaises(ValueError):
            self.validate(self.profile(), '0' * 40)


if __name__ == '__main__':
    unittest.main()
