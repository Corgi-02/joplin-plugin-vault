import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from vault.core import Layout, VaultError
from vault.paths import default_joplin_exe, discover_profiles, initial_paths


class PathDiscoveryTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='jpv-path-test-')
        self.root = Path(self.temp.name)
        self.current_home = self.root / 'new-computer/new-user'
        self.current_home.mkdir(parents=True)
        self.home_patch = patch('vault.paths.Path.home', return_value=self.current_home)
        self.environment_patch = patch.dict('os.environ', {}, clear=True)
        self.registry_patch = patch('vault.paths.registry_executables', return_value=[])
        self.home_patch.start(); self.environment_patch.start(); self.registry = self.registry_patch.start()
        self.addCleanup(self.temp.cleanup)
        self.addCleanup(self.home_patch.stop)
        self.addCleanup(self.environment_patch.stop)
        self.addCleanup(self.registry_patch.stop)

    def initialized(self, directory):
        directory.mkdir(parents=True, exist_ok=True)
        (directory / 'database.sqlite').touch()
        return str(directory.resolve())

    def executable(self, directory):
        directory.mkdir(parents=True, exist_ok=True)
        exe = directory / 'Joplin.exe'; exe.touch()
        return str(exe.resolve())

    def test_no_installation_leaves_both_fields_empty(self):
        self.assertEqual(initial_paths({}), ('', '', []))

    def test_current_user_profile_and_registered_custom_install_are_discovered(self):
        profile = self.initialized(self.current_home / '.config/joplin-desktop')
        exe = self.executable(self.root / 'custom-disk/Applications/Joplin')
        self.registry.return_value = [str(self.root / 'uninstalled/Joplin.exe'), exe]
        selected, program, choices = initial_paths({})
        self.assertEqual((selected, program), (profile, exe))
        self.assertIn(('Default', profile), choices)

    def test_migrated_preferences_use_new_computer_paths(self):
        current = self.initialized(self.current_home / '.config/joplin-desktop')
        exe = self.executable(self.root / 'new-install')
        self.registry.return_value = [exe]
        selected, program, _ = initial_paths({'profile': str(self.root/'old-user/.config/joplin-desktop'),
                                             'joplin_exe': str(self.root/'old-install/Joplin.exe')})
        self.assertEqual((selected, program), (current, exe))

    def test_migrated_preferences_without_local_installation_are_cleared(self):
        self.assertEqual(initial_paths({'profile': str(self.root/'old-user'),
                                        'joplin_exe': str(self.root/'old-install/Joplin.exe')}), ('', '', []))

    def test_existing_manual_custom_paths_are_preserved(self):
        custom = self.initialized(self.root / 'manual-profile')
        exe = self.executable(self.root / 'manual-install')
        self.initialized(self.current_home / '.config/joplin-desktop')
        selected, program, choices = initial_paths({'profile': custom, 'joplin_exe': exe})
        self.assertEqual((selected, program), (custom, exe))
        self.assertEqual(choices[0][1], custom)

    def test_standard_install_paths_require_an_actual_executable_file(self):
        with patch.dict('os.environ', {'LOCALAPPDATA': str(self.root/'Local'), 'ProgramFiles': str(self.root/'Programs')}):
            fake = self.root/'Local/Programs/Joplin/Joplin.exe'; fake.mkdir(parents=True)
            self.assertEqual(default_joplin_exe(), '')
            exe = self.executable(self.root/'Programs/Joplin')
            self.assertEqual(default_joplin_exe(), exe)

    def test_only_initialized_profiles_are_offered_and_active_profile_is_first(self):
        root = self.current_home / '.config/joplin-desktop'
        default = self.initialized(root)
        active = self.initialized(root/'profile-work')
        (root/'profiles.json').write_text(json.dumps({'currentProfileId': 'work', 'profiles': [
            {'id': 'default', 'name': 'Default'}, {'id': 'missing'}, {'id': '../outside'}, {'id': 'work', 'name': 'Work'}]}))
        self.assertEqual(discover_profiles(), [('Work', active), ('Default', default)])

    def test_malformed_profile_index_does_not_prevent_startup(self):
        root = self.current_home / '.config/joplin-desktop'
        default = self.initialized(root)
        for invalid in ['broken json', '[]', '{"profiles": null}']:
            with self.subTest(invalid=invalid):
                (root/'profiles.json').write_text(invalid)
                self.assertEqual(discover_profiles(), [('Default', default)])

    def test_portable_profile_next_to_selected_program_is_discovered(self):
        exe = self.executable(self.root/'portable')
        portable = self.initialized(self.root/'portable/JoplinProfile')
        self.initialized(self.current_home/'.config/joplin-desktop')
        self.assertEqual(initial_paths({'joplin_exe': exe})[0], portable)

    def test_empty_profile_is_not_interpreted_as_working_directory(self):
        for value in ['', '   ', None]:
            with self.subTest(value=value), self.assertRaisesRegex(VaultError, '配置目录'):
                Layout.discover(value)


if __name__ == '__main__': unittest.main()
