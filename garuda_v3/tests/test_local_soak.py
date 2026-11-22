import os
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

from garuda_v3.local_soak import resources, run_soak


class LocalSoakTests(unittest.TestCase):
    def test_invalid_run_bounds_fail_before_starting_process(self):
        with patch.dict(os.environ, {'GARUDA_DEPLOYMENT_PROFILE': 'pilot'}):
            for seconds, workers in ((0,4),(float('nan'),4),(float('inf'),4),(86401,4),(10,0),(10,9)):
                with self.assertRaises(ValueError):
                    run_soak('unused', seconds, workers)

    def test_requires_explicit_pilot_profile(self):
        with patch.dict(os.environ, {'GARUDA_DEPLOYMENT_PROFILE': 'local'}):
            with self.assertRaises(ValueError):
                run_soak('unused', 10, 1)

    @unittest.skipUnless(Path('/proc/self/status').exists(), 'Linux-only live resource measurements')
    def test_resource_measurements_are_real_and_finite(self):
        value=resources(os.getpid())
        self.assertGreater(value['rss_kib'],0)
        self.assertGreaterEqual(value['threads'],1)
        self.assertGreater(value['fd_count'],0)
        self.assertGreaterEqual(value['cpu_seconds'],0)

    def test_missing_process_is_unavailable_not_zero_usage(self):
        self.assertIsNone(resources(-1))

    def test_cli_preserves_failure_evidence(self):
        with tempfile.TemporaryDirectory() as folder:
            output=Path(folder)/'failure.json'
            env=dict(os.environ,GARUDA_DEPLOYMENT_PROFILE='pilot')
            result=subprocess.run([sys.executable,'-m','garuda_v3.local_soak','--seconds','9','--output',str(output)],
                env=env,capture_output=True,timeout=15)
            self.assertEqual(result.returncode,1)
            report=json.loads(output.read_text())
            self.assertEqual(report['status'],'FAIL')
            self.assertEqual(report['error_type'],'ValueError')

    def test_cli_cannot_overwrite_existing_report(self):
        with tempfile.TemporaryDirectory() as folder:
            output=Path(folder)/'existing.json';output.write_text('preserve')
            result=subprocess.run([sys.executable,'-m','garuda_v3.local_soak','--seconds','9','--output',str(output)],
                env=dict(os.environ,GARUDA_DEPLOYMENT_PROFILE='pilot'),capture_output=True,timeout=15)
            self.assertNotEqual(result.returncode,0)
            self.assertEqual(output.read_text(),'preserve')
