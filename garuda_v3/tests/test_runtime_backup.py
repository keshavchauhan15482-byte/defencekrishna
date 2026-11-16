import errno
import json
import os
from pathlib import Path
import sqlite3
import tempfile
import threading
import unittest
from unittest.mock import patch

from garuda_v3.runtime_backup import backup_runtime, restore_runtime, read_key
from garuda_v3.security import PolicyStore


class RuntimeBackupTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.runtime = self.root/'live'
        self.archive = self.root/'snapshot.enc'
        self.key = self.root/'backup.key'
        self.key.write_bytes(os.urandom(32));self.key.chmod(0o600)
        self.store = PolicyStore(self.runtime, key='s'*40, allowed_cidrs=['198.51.100.0/24'], enforce=True)
        self.addCleanup(self.store.close)
        self.store.propose('198.51.100.2', 900, 'reviewed incident fixture')

    def backup(self):
        return backup_runtime(self.runtime, self.archive, self.key, 'customer-a')

    def restore(self, tenant='customer-a', key=None):
        return restore_runtime(self.archive, self.root/'restored', key or self.key, tenant)

    def test_encrypted_round_trip_revokes_policies_and_preserves_audit(self):
        report = self.backup()
        self.assertEqual(report['event_count'], 1)
        content = self.archive.read_bytes()
        self.assertNotIn(b'SQLite format', content)
        self.assertNotIn(b'198.51.100.2', content)
        self.assertEqual(self.archive.stat().st_mode & 0o777, 0o600)
        result = self.restore()
        self.assertEqual(result['policies_reactivated'], 0)
        restored = PolicyStore(self.root/'restored', key='n'*40, allowed_cidrs=['198.51.100.0/24'], enforce=True)
        try:
            self.assertTrue(restored.verify())
            self.assertEqual(restored.active(), [])
            actions = [json.loads(row[0])['action'] for row in restored.db.execute('SELECT payload FROM events ORDER BY id')]
            self.assertEqual(actions, ['operator_containment', 'offline_restore_shadow_only'])
            self.assertEqual(json.loads(json.loads((self.root/'restored/policy.json').read_text())['payload'])['policies'], [])
        finally:
            restored.close()
        self.assertFalse((self.root/'restored/access.json').exists())
        self.assertFalse((self.root/'restored/restore.incomplete').exists())
        self.assertEqual(len(self.store.active()), 1)  # original runtime untouched

    def test_wrong_key_and_cross_tenant_restore_rejected_before_creation(self):
        self.backup()
        wrong = self.root/'wrong.key'
        wrong.write_bytes(os.urandom(32));wrong.chmod(0o600)
        for tenant, key in (('customer-b', self.key), ('customer-a', wrong)):
            with self.assertRaises(ValueError):
                self.restore(tenant, key)
            self.assertFalse((self.root/'restored').exists())

    def test_modified_ciphertext_rejected(self):
        self.backup()
        content = bytearray(self.archive.read_bytes());content[-1] ^= 1
        self.archive.write_bytes(content)
        with self.assertRaises(ValueError):
            self.restore()
        self.assertFalse((self.root/'restored').exists())

    def test_existing_archive_and_restore_directory_never_overwritten(self):
        self.backup()
        original = self.archive.read_bytes()
        with self.assertRaises(FileExistsError):
            self.backup()
        self.assertEqual(self.archive.read_bytes(), original)
        (self.root/'restored').mkdir()
        with self.assertRaises(FileExistsError):
            self.restore()

    def test_backup_publication_failure_leaves_no_partial_archive(self):
        with patch('garuda_v3.runtime_backup.os.link', side_effect=OSError(errno.ENOSPC, 'simulated disk full')):
            with self.assertRaises(OSError):
                self.backup()
        self.assertFalse(self.archive.exists())
        self.assertEqual(list(self.root.glob('.krishna-backup-*')), [])
        self.assertTrue(self.store.verify())

    def test_corrupt_audit_not_backed_up(self):
        self.store.db.execute("UPDATE events SET payload='invalid' WHERE id=1");self.store.db.commit()
        with self.assertRaises(ValueError):
            self.backup()
        self.assertFalse(self.archive.exists())

    def test_key_permissions_length_and_symlink_rejected(self):
        self.key.chmod(0o644)
        with self.assertRaises(ValueError):
            read_key(self.key)
        self.key.chmod(0o600);self.key.write_bytes(b'short')
        with self.assertRaises(ValueError):
            read_key(self.key)
        link = self.root/'key-link';link.symlink_to(self.key)
        with self.assertRaises((ValueError, OSError)):
            read_key(link)

    def test_backup_cannot_be_written_inside_live_runtime(self):
        with self.assertRaises(ValueError):
            backup_runtime(self.runtime, self.runtime/'backup.enc', self.key, 'customer-a')

    def test_online_wal_snapshot_is_consistent(self):
        self.store.db.execute('PRAGMA journal_mode=WAL')
        errors = []
        def writer():
            try:
                for i in range(3, 20):
                    self.store.propose('198.51.100.'+str(i), 900, 'concurrent WAL fixture')
            except Exception as exc:
                errors.append(exc)
        thread = threading.Thread(target=writer)
        thread.start()
        try:
            self.backup()
        finally:
            thread.join(timeout=10)
        self.assertFalse(thread.is_alive())
        self.assertEqual(errors, [])
        result = self.restore()
        self.assertGreaterEqual(result['original_event_count'], 1)

    def test_failed_restore_marker_blocks_runtime_startup(self):
        self.backup()
        original_connect = sqlite3.connect
        def connect(database, *args, **kwargs):
            if str(database).endswith('restored/audit.sqlite'):
                raise OSError(errno.ENOSPC, 'simulated restore disk full')
            return original_connect(database, *args, **kwargs)
        with patch('garuda_v3.runtime_backup.sqlite3.connect', side_effect=connect):
            with self.assertRaises(OSError):
                self.restore()
        self.assertTrue((self.root/'restored/restore.incomplete').exists())
        from garuda_v3.server import App
        with self.assertRaisesRegex(ValueError, 'Incomplete restore'):
            App('unused-artifacts', self.root/'restored', 'r'*40, 'o'*40)


if __name__ == '__main__':
    unittest.main()
