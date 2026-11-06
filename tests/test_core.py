import contextlib
import io
import json
import os
import sqlite3
import tarfile
import tempfile
import unittest
import zipfile
from pathlib import Path
from unittest.mock import patch

from vault.core import Engine, Layout, VaultError, atomic_json, inventory, digest
from vault.preferences import protect


def package(path, plugin_id='test.example', version='1.0.0'):
    path.parent.mkdir(parents=True, exist_ok=True)
    with tarfile.open(path, 'w') as archive:
        data = json.dumps({'id': plugin_id, 'version': version, 'name': plugin_id}).encode()
        item = tarfile.TarInfo('manifest.json'); item.size = len(data)
        archive.addfile(item, io.BytesIO(data))
        data = b'console.log("fixture")'
        item = tarfile.TarInfo('index.js'); item.size = len(data)
        archive.addfile(item, io.BytesIO(data))


def profile(path, value='source', plugin_id='test.example'):
    path.mkdir(parents=True)
    conn = sqlite3.connect(path / 'database.sqlite')
    conn.executescript('CREATE TABLE settings(key TEXT PRIMARY KEY,value TEXT); CREATE TABLE notes(id TEXT PRIMARY KEY,body TEXT);')
    conn.executemany('INSERT INTO settings VALUES (?,?)', [('plugin-' + plugin_id + '.value', value),
                    ('plugins.states', json.dumps({plugin_id: {'enabled': False, 'deleted': False}})), ('sync.target', '42')])
    conn.execute('INSERT INTO notes VALUES (?,?)', ('real-note', 'Never overwrite my notes: ' + value))
    conn.commit(); conn.close()
    atomic_json(path / 'settings.json', {'sync.5.path': 'https://keep.example/notes/', 'api.token': 'keep-target-token',
                                        'plugin-' + plugin_id + '.fileOption': value, 'ui.layout': 'target-specific'})
    package(path / 'plugins' / (plugin_id + '.jpl'), plugin_id)
    data = path / 'plugin-data' / plugin_id
    data.mkdir(parents=True)
    (data / 'preferences.json').write_text(json.dumps({'value': value}), encoding='utf-8')
    return path


def database(path):
    with contextlib.closing(sqlite3.connect(path / 'database.sqlite')) as conn:
        return dict(conn.execute('SELECT key,value FROM settings')), list(conn.execute('SELECT * FROM notes'))


class CoreTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='jpv-test-')
        self.root = Path(self.temp.name)
        self.source = profile(self.root / 'source')
        self.target = profile(self.root / 'target', 'target', 'target.extra')
        self.engine = Engine(guard=lambda: None)

    def tearDown(self): self.temp.cleanup()

    def test_full_roundtrip_preserves_notes_and_non_plugin_settings(self):
        saved = self.engine.backup(self.source, self.root / 'backups')
        before_settings, before_notes = database(self.target)
        preview = self.engine.preview(saved, self.target)
        self.assertEqual(preview['install'], ['test.example'])
        self.assertEqual(preview['remove'], ['target.extra'])
        result = self.engine.restore(saved, self.target, self.root / 'recovery', expected_hash=preview['archive_sha256'])
        after_settings, after_notes = database(self.target)
        self.assertEqual(before_notes, after_notes)
        self.assertEqual(after_settings['sync.target'], before_settings['sync.target'])
        self.assertEqual(after_settings['plugin-test.example.value'], 'source')
        self.assertNotIn('plugin-target.extra.value', after_settings)
        config = json.loads((self.target / 'settings.json').read_text())
        self.assertEqual(config['api.token'], 'keep-target-token')
        self.assertEqual(config['plugin-test.example.fileOption'], 'source')
        self.assertNotIn('plugin-target.extra.fileOption', config)
        self.assertFalse(json.loads(after_settings['plugins.states'])['test.example']['enabled'])
        self.assertTrue((self.target / 'plugins/test.example.jpl').exists())
        self.assertFalse((self.target / 'plugins/target.extra.jpl').exists())
        self.assertEqual(json.loads((self.target / 'plugin-data/test.example/preferences.json').read_text())['value'], 'source')
        self.assertTrue(Path(result['recovery_backup']).exists())

    def test_encrypted_roundtrip_and_wrong_password(self):
        saved = self.engine.backup(self.source, self.root / 'backups', '复杂 password 123')
        self.assertEqual(saved.suffix, '.enc')
        self.assertNotIn(b'test.example', saved.read_bytes())
        with self.assertRaises(VaultError): self.engine.preview(saved, self.target, 'wrong')
        preview = self.engine.preview(saved, self.target, '复杂 password 123')
        self.engine.restore(saved, self.target, self.root / 'recovery', '复杂 password 123', expected_hash=preview['archive_sha256'])
        self.assertEqual(database(self.target)[0]['plugin-test.example.value'], 'source')

    def test_encryption_tamper_is_rejected(self):
        saved = self.engine.backup(self.source, self.root / 'backups', 'password123')
        data = bytearray(saved.read_bytes()); data[-20] ^= 1; saved.write_bytes(data)
        with self.assertRaises(VaultError): self.engine.preview(saved, self.target, 'password123')

    def test_failed_restore_rolls_back_files_database_and_json(self):
        saved = self.engine.backup(self.source, self.root / 'backups')
        before = database(self.target)
        old_config = (self.target / 'settings.json').read_bytes()
        old_jpl = (self.target / 'plugins/target.extra.jpl').read_bytes()
        def fail(): raise RuntimeError('injected failure')
        with self.assertRaisesRegex(RuntimeError, 'injected'):
            self.engine.restore(saved, self.target, self.root / 'recovery', fault=fail)
        self.assertEqual(database(self.target), before)
        self.assertEqual((self.target / 'settings.json').read_bytes(), old_config)
        self.assertEqual((self.target / 'plugins/target.extra.jpl').read_bytes(), old_jpl)
        self.assertFalse((self.target / 'plugin-vault-recovery.json').exists())

    def test_archive_change_after_preview_is_rejected(self):
        saved = self.engine.backup(self.source, self.root / 'backups')
        preview = self.engine.preview(saved, self.target)
        with saved.open('ab') as f: f.write(b'changed')
        before = database(self.target)
        with self.assertRaises(VaultError):
            self.engine.restore(saved, self.target, self.root / 'recovery', expected_hash=preview['archive_sha256'])
        self.assertEqual(database(self.target), before)

    def test_preview_hash_matches_verified_copy_when_original_changes(self):
        saved = self.engine.backup(self.source, self.root / 'backups')
        original_hash = digest(saved)

        def change_original(frozen):
            with saved.open('ab') as stream:
                stream.write(b'changed during preview')
            return digest(frozen)

        with patch('vault.core.digest', side_effect=change_original):
            preview = self.engine.preview(saved, self.target)
        self.assertEqual(preview['archive_sha256'], original_hash)
        before = database(self.target)
        with self.assertRaisesRegex(VaultError, '预览后发生变化'):
            self.engine.restore(saved, self.target, self.root / 'recovery', expected_hash=preview['archive_sha256'])
        self.assertEqual(database(self.target), before)

    def test_malformed_manifest_is_rejected_before_target_changes(self):
        saved = self.engine.backup(self.source, self.root / 'backups')
        with zipfile.ZipFile(saved) as source:
            original = json.loads(source.read('manifest.json'))
        cases = [[], {**original, 'settings_database': []}, {**original, 'settings_files': []},
                 {**original, 'settings_files': {'profile': []}}, {**original, 'plugins': [None]},
                 {**original, 'plugins': [{**original['plugins'][0], 'id': 123}]},
                 {**original, 'files': {name: None for name in original['files']}},
                 {**original, 'warnings': [None]}]
        before = database(self.target)
        for index, manifest in enumerate(cases):
            with self.subTest(index=index):
                malformed = self.root / 'malformed.zip'
                with zipfile.ZipFile(saved) as source, zipfile.ZipFile(malformed, 'w') as target:
                    for item in source.infolist():
                        target.writestr(item.filename, json.dumps(manifest) if item.filename == 'manifest.json' else source.read(item.filename))
                with self.assertRaises(VaultError):
                    self.engine.restore(malformed, self.target, self.root / 'recovery')
                self.assertEqual(database(self.target), before)
                self.assertFalse((self.root / 'recovery').exists())

    def test_traversal_archive_cannot_escape(self):
        saved = self.engine.backup(self.source, self.root / 'backups')
        evil = self.root / 'evil.zip'
        with zipfile.ZipFile(saved) as src, zipfile.ZipFile(evil, 'w') as dst:
            for item in src.infolist(): dst.writestr(item.filename, src.read(item.filename))
            dst.writestr('../escape.txt', 'no')
        with self.assertRaises(VaultError): self.engine.restore(evil, self.target, self.root / 'recovery')
        self.assertFalse((self.root / 'escape.txt').exists())

    def test_corrupted_payload_rejected_before_changes(self):
        saved = self.engine.backup(self.source, self.root / 'backups')
        evil = self.root / 'bad.zip'
        with zipfile.ZipFile(saved) as src, zipfile.ZipFile(evil, 'w') as dst:
            for item in src.infolist(): dst.writestr(item.filename, b'bad' if item.filename.endswith('.jpl') else src.read(item.filename))
        before = database(self.target)
        with self.assertRaises(VaultError): self.engine.restore(evil, self.target, self.root / 'recovery')
        self.assertEqual(database(self.target), before)

    def test_foreign_settings_in_manifest_are_rejected(self):
        saved = self.engine.backup(self.source, self.root / 'backups')
        evil = self.root / 'bad-settings.zip'
        with zipfile.ZipFile(saved) as src, zipfile.ZipFile(evil, 'w') as dst:
            for item in src.infolist():
                data = src.read(item.filename)
                if item.filename == 'manifest.json':
                    meta = json.loads(data); meta['settings_database']['api.token'] = 'attack'; data = json.dumps(meta)
                dst.writestr(item.filename, data)
        with self.assertRaises(VaultError): self.engine.preview(evil, self.target)

    def test_builtin_packages_are_saved_and_user_package_takes_precedence(self):
        exe = self.root / 'install/Joplin.exe'; exe.parent.mkdir()
        package(exe.parent / 'resources/build/defaultPlugins/test.builtin.jpl', 'test.builtin')
        package(exe.parent / 'resources/build/defaultPlugins/test.example.jpl', 'test.example', '0.9.0')
        manifest, _ = inventory(Layout.discover(self.source), str(exe))
        self.assertEqual(len(manifest['plugins']), 2)
        self.assertEqual(next(x for x in manifest['plugins'] if x['id'] == 'test.example')['version'], '1.0.0')

    def test_backup_inside_plugin_data_is_rejected(self):
        with self.assertRaises(VaultError): self.engine.backup(self.source, self.source / 'plugin-data/backups')

    def test_running_joplin_guard_prevents_write(self):
        def guard(): raise VaultError('running')
        with self.assertRaises(VaultError): Engine(guard).backup(self.source, self.root / 'backups')
        self.assertFalse((self.root / 'backups').exists())

    def test_another_instance_cannot_backup_while_restore_holds_profile_lock(self):
        other = Engine(guard=lambda: None)
        with self.engine.operation(self.source):
            with self.assertRaisesRegex(VaultError, '另一个'):
                other.backup(self.source, self.root / 'backups')
        self.assertTrue(other.backup(self.source, self.root / 'backups').exists())

    def test_recover_interrupted_restore_from_automatic_snapshot(self):
        recovery = self.engine.backup(self.target, self.root / 'recovery')
        (self.target / 'plugins/target.extra.jpl').write_bytes(b'partial-broken-package')
        with contextlib.closing(sqlite3.connect(self.target / 'database.sqlite')) as conn:
            conn.execute("UPDATE settings SET value='partial' WHERE key='plugin-target.extra.value'")
            conn.commit()
        atomic_json(self.target / 'plugin-vault-recovery.json', {'status': 'applying', 'recovery_backup': str(recovery)})
        self.engine.recover_interrupted(self.target)
        self.assertEqual(database(self.target)[0]['plugin-target.extra.value'], 'target')
        self.assertFalse((self.target / 'plugin-vault-recovery.json').exists())

    def test_subprofile_shares_packages_but_preserves_other_profile_database(self):
        parent = self.root / 'multi'; parent.mkdir()
        atomic_json(parent / 'profiles.json', {'version': 2, 'profiles': []})
        sub = profile(parent / 'profile-abc', 'sub')
        (sub / 'plugins').rename(parent / 'plugins')
        layout = Layout.discover(sub)
        self.assertEqual(layout.root, parent)
        saved = self.engine.backup(sub, self.root / 'backups')
        self.assertTrue(self.engine.preview(saved, sub)['shared_plugins'])

    @unittest.skipUnless(os.name == 'nt', 'Windows DPAPI')
    def test_remembered_password_is_windows_protected(self):
        encrypted = protect('not-a-real-password 复杂'.encode())
        self.assertNotIn(b'not-a-real-password', encrypted)
        self.assertEqual(protect(encrypted, True).decode(), 'not-a-real-password 复杂')


if __name__ == '__main__': unittest.main()
