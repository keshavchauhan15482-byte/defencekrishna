import json
import os
from pathlib import Path
import subprocess
import sqlite3
import sys
import tempfile
import unittest
from unittest.mock import patch

from garuda_v3.security import PolicyStore


class CrashSafetyTests(unittest.TestCase):
    def test_crash_after_commit_does_not_activate_policy_on_restart(self):
        code = '''
import os,sys
from garuda_v3.security import PolicyStore
store=PolicyStore(sys.argv[1],key='k'*40,allowed_cidrs=['198.51.100.0/24'],enforce=True)
store.publish=lambda: os._exit(23)
store.propose('198.51.100.2',900,'isolated crash fixture')
'''
        with tempfile.TemporaryDirectory() as folder:
            result = subprocess.run([sys.executable, '-c', code, folder], timeout=15, capture_output=True)
            self.assertEqual(result.returncode, 23)
            store = PolicyStore(folder, key='k'*40, allowed_cidrs=['198.51.100.0/24'], enforce=True)
            try:
                self.assertEqual(store.active(), [])
                envelope = json.loads((Path(folder)/'policy.json').read_text())
                self.assertEqual(json.loads(envelope['payload'])['policies'], [])
                self.assertTrue(store.verify())
            finally:
                store.close()

    def test_graceful_restart_requires_policy_reapproval(self):
        with tempfile.TemporaryDirectory() as folder:
            store = PolicyStore(folder, key='k'*40, allowed_cidrs=['198.51.100.0/24'], enforce=True)
            store.propose('198.51.100.2',900,'isolated restart fixture');store.close()
            reopened = PolicyStore(folder, key='k'*40, allowed_cidrs=['198.51.100.0/24'], enforce=True)
            try:
                self.assertEqual(reopened.active(), [])
                self.assertTrue(reopened.verify())
            finally:
                reopened.close()

    def test_publication_failure_latches_safe_mode(self):
        with tempfile.TemporaryDirectory() as folder:
            store = PolicyStore(folder, key='k'*40, allowed_cidrs=['198.51.100.0/24'], enforce=True)
            try:
                with patch('garuda_v3.security.os.replace', side_effect=OSError('simulated full disk')):
                    with self.assertRaises(OSError):
                        store.propose('198.51.100.2',900,'isolated disk fault fixture')
                self.assertTrue(store.publication_error)
                with self.assertRaises(ValueError):
                    store.propose('198.51.100.3',900,'must not silently resume')
                store.publish()
                envelope = json.loads((Path(folder)/'policy.json').read_text())
                self.assertEqual(json.loads(envelope['payload'])['policies'], [])
                self.assertTrue(store.publication_error)  # restart/review required
            finally:
                store.close()

    def test_database_write_failure_rolls_back_and_latches(self):
        with tempfile.TemporaryDirectory() as folder:
            store = PolicyStore(folder,key='k'*40,allowed_cidrs=['198.51.100.0/24'],enforce=True)
            try:
                store.db.execute("CREATE TRIGGER deny_policy BEFORE INSERT ON policies BEGIN SELECT RAISE(ABORT,'test disk fault'); END")
                with self.assertRaises(sqlite3.Error):
                    store.propose('198.51.100.2',900,'isolated database fault')
                self.assertTrue(store.publication_error)
                self.assertEqual(store.active(), [])
                self.assertTrue(store.verify())
            finally:
                store.close()

    def test_replay_rate_gate_precedes_inference(self):
        import http.client
        import threading
        from types import SimpleNamespace
        from garuda_v3.integrated_server import IntegratedHandler
        from garuda_v3.server import Server
        server=Server(('127.0.0.1',0),SimpleNamespace(rate_ok=lambda scope: False))
        server.RequestHandlerClass=IntegratedHandler
        thread=threading.Thread(target=server.serve_forever,daemon=True);thread.start()
        try:
            conn=http.client.HTTPConnection('127.0.0.1',server.server_port,timeout=3)
            conn.request('GET','/bridge/replay');response=conn.getresponse()
            self.assertEqual(response.status,429);response.read();conn.close()
        finally:
            server.shutdown();server.server_close();thread.join(timeout=3)


if __name__ == '__main__':
    unittest.main()
