import os
from pathlib import Path
import selectors
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

from garuda_v3.runtime_lease import RuntimeLease


@unittest.skipUnless(os.name=='posix','Pilot ownership currently supports POSIX')
class RuntimeLeaseTests(unittest.TestCase):
    def test_duplicate_owner_rejected_then_close_releases(self):
        with tempfile.TemporaryDirectory() as folder:
            owner=RuntimeLease(folder)
            try:
                with self.assertRaises(ValueError):RuntimeLease(folder)
            finally:owner.close()
            owner=RuntimeLease(folder);owner.close()

    def test_actual_child_kill_releases_os_lock(self):
        code="from garuda_v3.runtime_lease import RuntimeLease; import sys,time; lease=RuntimeLease(sys.argv[1]); print('ready',flush=True); time.sleep(30)"
        with tempfile.TemporaryDirectory() as folder:
            child=subprocess.Popen([sys.executable,'-c',code,folder],stdout=subprocess.PIPE,stderr=subprocess.DEVNULL)
            try:
                with selectors.DefaultSelector() as selector:
                    selector.register(child.stdout,selectors.EVENT_READ)
                    self.assertTrue(selector.select(timeout=10))
                    self.assertEqual(child.stdout.readline(),b'ready\n')
                with self.assertRaises(ValueError):RuntimeLease(folder)
                child.kill();child.wait(timeout=5)
                owner=RuntimeLease(folder);owner.close()
            finally:
                if child.poll() is None:child.kill();child.wait(timeout=5)
                child.stdout.close()

    def test_symlink_lock_is_rejected(self):
        with tempfile.TemporaryDirectory() as folder:
            (Path(folder)/'target').touch()
            (Path(folder)/'instance.lock').symlink_to(Path(folder)/'target')
            with self.assertRaises((OSError,ValueError)):RuntimeLease(folder)

    def test_failed_app_start_releases_runtime_lease(self):
        from garuda_v3.server import App
        from garuda_v3.integrated_server import IntegratedApp
        artifacts=Path(__file__).resolve().parents[1]/'artifacts/residual_run'
        with tempfile.TemporaryDirectory() as folder, patch.dict(os.environ,{'GARUDA_DEPLOYMENT_PROFILE':'pilot'}):
            with patch('garuda_v3.server.ResponseCoordinator',side_effect=RuntimeError('fixture')):
                with self.assertRaises(RuntimeError):App(artifacts,folder,'r'*40,'o'*40)
            with patch('garuda_v3.integrated_server.V15EvidenceBridge',side_effect=RuntimeError('fixture')):
                with self.assertRaises(RuntimeError):IntegratedApp(artifacts,folder,'r'*40,'o'*40)
            app=App(artifacts,folder,'r'*40,'o'*40)
            app.policy.close()
