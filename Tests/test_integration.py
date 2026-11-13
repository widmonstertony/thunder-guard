import importlib.util
import pathlib
import plistlib
import tempfile
import unittest
from unittest import mock

ROOT = pathlib.Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('integrated_prepare', ROOT / 'Integration/prepare.py')
prepare = importlib.util.module_from_spec(spec)
spec.loader.exec_module(prepare)


class IntegrationTests(unittest.TestCase):
    def test_generated_fork_has_one_app_and_its_own_identity(self):
        # Structural regression test; the actual Xcode build checks compilation.
        with tempfile.TemporaryDirectory() as temp, \
             mock.patch.object(prepare, 'make_icon', side_effect=lambda path: (path / 'ThunderGuard.icns').write_bytes(b'fixture')):
            destination = pathlib.Path(temp) / 'source'
            project_path = prepare.generate(destination, 'TESTTEAM01',
                'Developer ID Application: Test Publisher (TESTTEAM01)')
            project = plistlib.loads((project_path / 'project.pbxproj').read_bytes())
            objects = project['objects']
            targets = [obj for obj in objects.values() if obj.get('isa') == 'PBXNativeTarget']
            self.assertEqual(len(targets), 2)
            attributes = objects[project['rootObject']]['attributes']['TargetAttributes']
            for key, target in objects.items():
                if target.get('isa') == 'PBXNativeTarget':
                    self.assertEqual(attributes[key]['SystemCapabilities']['com.apple.NetworkExtensions']['enabled'], 1)
            app = next(obj for obj in targets if obj['name'] == 'LuLu')
            configurations = objects[app['buildConfigurationList']]['buildConfigurations']
            for config in configurations:
                settings = objects[config]['buildSettings']
                self.assertEqual(settings['PRODUCT_NAME'], 'ThunderGuard')
                self.assertEqual(settings['PRODUCT_BUNDLE_IDENTIFIER'], prepare.PREFIX + '.app')
                self.assertEqual(settings['DEVELOPMENT_TEAM'], 'TESTTEAM01')
            phases = [objects[key] for key in app['buildPhases']]
            resources = next(p for p in phases if p['isa'] == 'PBXResourcesBuildPhase')
            resource_refs = [objects[objects[key]['fileRef']] for key in resources['files']]
            self.assertFalse(any(ref.get('path', '').endswith('.app') for ref in resource_refs))
            self.assertTrue(any(ref.get('path') == 'ThunderGuard.icns' for ref in resource_refs))
            consts = (destination / 'Shared/consts.h').read_text()
            self.assertIn(prepare.FILTER_ROOT, consts)
            self.assertIn('Test Publisher (TESTTEAM01)', consts)
            self.assertNotIn('VBG97UB4TA', consts)
            self.assertNotIn('com.objective-see.lulu', consts)
            listener = (destination / 'Extension/XPCListener.m').read_text()
            self.assertIn('anchor apple generic', listener)
            self.assertIn('CS_RUNTIME', listener)
            self.assertIn(r'>= \"0.5.0\"', listener)
            self.assertNotIn(r'>= \"2.0.0\"', listener)
            configure = (destination / 'App/Configure.m').read_text()
            self.assertNotIn('findProcesses(@"LuLu")', configure)
            status = (destination / 'App/StatusBarItem.m').read_text()
            monitor = status[status.index('        case monitor:'):status.index('        //quit\n')]
            self.assertIn('TGDashboardHost', monitor)
            self.assertNotIn('launchApplication', monitor)
            generated_host = (destination / 'Integrated/NetworkDashboard.swift').read_text()
            self.assertNotIn('openApplication(at:', generated_host)
            delegate = (destination / 'App/AppDelegate.m').read_text()
            self.assertIn('[[TGDashboardHost shared] show]', delegate)
            self.assertIn('ACTION_DEACTIVATE', delegate)

    def test_invalid_publisher_identity_is_rejected_before_copying(self):
        with tempfile.TemporaryDirectory() as temp:
            destination = pathlib.Path(temp) / 'source'
            with self.assertRaises(ValueError):
                prepare.generate(destination, 'TESTTEAM01',
                    'Developer ID Application: Wrong Team (OTHERTEAM0)')
            self.assertFalse(destination.exists())


if __name__ == '__main__':
    unittest.main()
