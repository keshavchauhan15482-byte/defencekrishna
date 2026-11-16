import http.client
import os
from pathlib import Path
import tempfile
import threading
from concurrent.futures import ThreadPoolExecutor
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from garuda_v3.operations import OperationalMetrics, readiness
from garuda_v3.server import Handler, Server


class OperationsTests(unittest.TestCase):
    def test_disk_full_and_audit_failure_are_not_ready(self):
        app = SimpleNamespace(policy=SimpleNamespace(verify=lambda: True, folder=Path(tempfile.gettempdir())))
        with patch('garuda_v3.operations.shutil.disk_usage', return_value=SimpleNamespace(free=0)):
            self.assertEqual(readiness(app)['status'], 'not_ready')
        with patch('garuda_v3.operations.shutil.disk_usage', side_effect=OSError('unavailable')):
            self.assertEqual(readiness(app)['status'], 'not_ready')
        app.policy.verify=lambda: False
        self.assertFalse(readiness(app)['audit_integrity'])

    def test_bounded_metrics_and_invalid_disk_budget(self):
        with patch.dict(os.environ, {'GARUDA_MIN_FREE_BYTES': '0'}):
            with self.assertRaises(ValueError):
                OperationalMetrics()
        metrics = OperationalMetrics()
        for code in (200, 401, 503):
            metrics.begin();metrics.finish(code, 8)
        metrics.reject_capacity()
        result = metrics.snapshot()
        self.assertEqual(result['completed'], 3)
        self.assertEqual(result['in_flight'], 0)
        self.assertEqual(sum(result['latency_bucket_counts']), 3)
        self.assertEqual(result['capacity_rejections'], 1)
        self.assertEqual(result['status_classes']['5xx'], 1)

    def test_real_http_bounded_concurrency_and_metrics_auth(self):
        metrics = OperationalMetrics()
        app = SimpleNamespace(deployment_profile='local', operations=metrics,
            role=lambda token: 'viewer' if token=='reader' else None, rate_ok=lambda role: True)
        server = Server(('127.0.0.1', 0), app)
        thread = threading.Thread(target=server.serve_forever, daemon=True);thread.start()
        def request(index):
            conn = http.client.HTTPConnection('127.0.0.1', server.server_port, timeout=5)
            conn.request('GET', '/api/operations', headers={'Authorization': 'Bearer reader'} if index else {})
            response=conn.getresponse();status=response.status;response.read();conn.close()
            return status
        try:
            with ThreadPoolExecutor(max_workers=8) as pool:
                statuses = list(pool.map(request, range(80)))
            self.assertEqual(statuses.count(401), 1)
            self.assertEqual(statuses.count(200), 79)
            # Wait for handler finalizers without assuming client read == completion.
            server.shutdown();thread.join(timeout=3)
            result = metrics.snapshot()
            self.assertEqual(result['completed'], 80)
            self.assertEqual(result['in_flight'], 0)
            self.assertEqual(sum(result['latency_bucket_counts']), 80)
        finally:
            server.shutdown();server.server_close();thread.join(timeout=3)


if __name__ == '__main__':
    unittest.main()
