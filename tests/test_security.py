import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock, patch

from vault.security import (MARKER, cleanup_workspaces, legacy_workspaces, private_workspace,
                            redact_log, stale_workspaces)
from vault.ui import App


class SecurityTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='jpv-security-test-')
        self.root = Path(self.temp.name)
        self.local = self.root / 'local'
        self.local.mkdir()
        self.root_patch = patch('vault.security.temp_root', return_value=self.local)
        self.root_patch.start()
        self.addCleanup(self.temp.cleanup)
        self.addCleanup(self.root_patch.stop)

    def abandoned(self, name='jpv-backup-abcdefgh'):
        folder = self.local / name
        folder.mkdir()
        (folder / '.jpv-workspace').write_bytes(MARKER)
        (folder / 'active.lock').write_bytes(b'0')
        (folder / 'snapshot.zip').write_bytes(b'fixture plaintext')
        return folder

    def test_cleanup_preserves_active_workspace_and_recovery_artifacts(self):
        abandoned = self.abandoned()
        recovery = self.local / '.jpv-swap-fixture'
        recovery.mkdir()
        journal = self.local / 'plugin-vault-recovery.json'
        journal.write_text('{}')
        with private_workspace('restore') as active:
            (active / 'stage').mkdir()
            self.assertEqual(stale_workspaces(), [abandoned])
            self.assertEqual(cleanup_workspaces([active, abandoned, recovery]), (1, 2))
            self.assertTrue(active.exists())
            self.assertTrue(journal.exists())
            self.assertTrue(recovery.exists())
        self.assertFalse(active.exists())

    def test_cleanup_rejects_unmarked_and_outside_directories(self):
        unmarked = self.local / 'jpv-verify-abcdefgh'
        unmarked.mkdir()
        (unmarked / 'keep').write_text('keep')
        outside = self.root / 'jpv-preview-abcdefgh'
        outside.mkdir()
        self.assertEqual(cleanup_workspaces([unmarked, outside]), (0, 2))
        self.assertTrue((unmarked / 'keep').exists())
        self.assertTrue(outside.exists())

    def test_killed_process_leaves_detectable_cleanable_workspace(self):
        script = """
import os
from pathlib import Path
from vault import security
security.temp_root = lambda: Path(os.environ['JPV_TEST_TEMP_ROOT'])
with security.private_workspace('verify') as folder:
    (folder / 'decrypted.zip').write_bytes(b'fixture plaintext')
    print(folder.name, flush=True)
    import time
    time.sleep(30)
"""
        child = subprocess.Popen([sys.executable, '-B', '-c', script], stdout=subprocess.PIPE,
                                 text=True, env={**os.environ, 'JPV_TEST_TEMP_ROOT': str(self.local)})
        try:
            name = child.stdout.readline().strip()
            self.assertTrue(name.startswith('jpv-verify-'))
            self.assertEqual(stale_workspaces(), [])
            child.kill()
            child.wait(timeout=10)
            stale = stale_workspaces()
            self.assertEqual([p.name for p in stale], [name])
            self.assertEqual(cleanup_workspaces(stale), (1, 0))
        finally:
            if child.poll() is None:
                child.kill()
            child.wait(timeout=10)
            child.stdout.close()

    def test_legacy_directories_are_reported_without_deletion(self):
        backup = self.root / 'backups'
        backup.mkdir()
        legacy = backup / 'jpv-backup-abcdefgh'
        legacy.mkdir()
        with patch('vault.security.tempfile.gettempdir', return_value=str(self.local)):
            self.assertEqual(legacy_workspaces(str(backup)), [legacy])
        self.assertTrue(legacy.exists())

    def test_persisted_logs_redact_paths_and_server_urls(self):
        app = App.__new__(App)
        app.home = self.root
        app.log_box, app.status = Mock(), Mock()
        app.log("失败：'C:\\Users\\fixture user\\VaultData\\backup.enc'；https://fixture-user:fixture-secret@example.invalid/dav/；继续")
        persisted = (self.root / 'operations.log').read_text(encoding='utf-8')
        for value in ['fixture user', 'fixture-user', 'fixture-secret', 'example.invalid']:
            self.assertNotIn(value, persisted)
        self.assertIn('[本地路径]', persisted)
        self.assertIn('[服务器地址]', persisted)
        self.assertNotIn('private-share', redact_log(r'失败：\\private-share\user\file'))

    def backup_app(self, allow_plain=False):
        value = lambda item: SimpleNamespace(get=lambda: item)
        app = App.__new__(App)
        app.password, app.confirm_password = value(''), value('')
        app.plain_backup, app.upload = value(allow_plain), value(False)
        app.profile, app.folder, app.exe = value('fixture-profile'), value('fixture-backups'), value('')
        app.engine, app.save_preferences, app.submit, app.log = Mock(), Mock(), Mock(), Mock()
        return app

    def test_plain_backup_requires_checkbox_and_confirmation(self):
        app = self.backup_app()
        with patch('vault.ui.messagebox.showerror') as error, patch('vault.ui.messagebox.askyesno') as confirm:
            app.backup()
            error.assert_called_once()
            confirm.assert_not_called()
            app.submit.assert_not_called()
        app = self.backup_app(True)
        with patch('vault.ui.messagebox.askyesno', return_value=False) as confirm:
            app.backup()
            confirm.assert_called_once()
            app.submit.assert_not_called()
        with patch('vault.ui.messagebox.askyesno', return_value=True):
            app.backup()
            app.submit.assert_called_once()
            app.submit.call_args.args[1]()
            self.assertTrue(app.engine.backup.call_args.kwargs['allow_unencrypted'])

    def test_scheduled_backup_cannot_use_plaintext_opt_in(self):
        app = self.backup_app(True)
        with patch('vault.ui.messagebox.askyesno') as confirm:
            app.backup(scheduled=True)
        confirm.assert_not_called()
        app.submit.assert_not_called()
        app.log.assert_called_once()

    def test_commit_scanner_checks_index_and_never_prints_secret_values(self):
        repo = self.root / 'repo'
        repo.mkdir()
        scanner = Path(__file__).resolve().parents[1] / 'scripts/check_secrets.py'
        subprocess.run(['git', 'init', '-q', str(repo)], check=True)
        suspicious = 'ghp_' + 'x' * 36
        (repo / 'main.py').write_text("token = '" + suspicious + "'", encoding='utf-8')
        subprocess.run(['git', '-C', str(repo), 'add', 'main.py'], check=True)
        # Editing the working copy after staging must not bypass the check.
        (repo / 'main.py').write_text('print("safe")', encoding='utf-8')
        result = subprocess.run([sys.executable, '-B', str(scanner)], cwd=repo, capture_output=True, text=True)
        self.assertEqual(result.returncode, 1)
        self.assertIn('GitHub token', result.stdout)
        self.assertNotIn(suspicious, result.stdout + result.stderr)
        subprocess.run(['git', '-C', str(repo), 'add', 'main.py'], check=True)
        result = subprocess.run([sys.executable, '-B', str(scanner), '--all'], cwd=repo, capture_output=True, text=True)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        (repo / 'database.sqlite').write_bytes(b'fixture')
        subprocess.run(['git', '-C', str(repo), 'add', 'database.sqlite'], check=True)
        result = subprocess.run([sys.executable, '-B', str(scanner)], cwd=repo, capture_output=True, text=True)
        self.assertEqual(result.returncode, 1)
        self.assertIn('runtime data', result.stdout)


if __name__ == '__main__':
    unittest.main()
