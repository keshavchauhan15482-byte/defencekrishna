"""Bounded localhost pilot/recovery rehearsal; never a production load benchmark."""
import argparse
from collections import Counter
from concurrent.futures import ThreadPoolExecutor
import contextlib
import http.client
import io
import json
import os
from pathlib import Path
import secrets
import statistics
import tempfile
import threading
import time

from .integrated_server import IntegratedApp, IntegratedHandler
from .runtime_backup import backup_runtime, restore_runtime
from .security import PolicyStore
from .server import Server


def rehearse(artifacts, requests=40, workers=4):
    if not 2 <= requests <= 50 or not 1 <= workers <= 8:
        raise ValueError('Bounded rehearsal: 2..50 requests, 1..8 workers')
    if os.environ.get('GARUDA_DEPLOYMENT_PROFILE') != 'pilot':
        raise ValueError('Run explicitly with GARUDA_DEPLOYMENT_PROFILE=pilot')
    # No real customer runtime, tokens, enforcement keys or remote targets used.
    with tempfile.TemporaryDirectory(prefix='krishna-pilot-rehearsal-') as folder:
        root = Path(folder)
        reader, operator = secrets.token_urlsafe(32), secrets.token_urlsafe(32)
        app = IntegratedApp(artifacts, root/'live', reader, operator)
        server = Server(('127.0.0.1', 0), app)
        server.RequestHandlerClass = IntegratedHandler
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        def request(path, token=None):
            conn = http.client.HTTPConnection('127.0.0.1', server.server_port, timeout=10)
            started = time.perf_counter()
            try:
                conn.request('GET', path, headers={'Authorization': 'Bearer '+token} if token else {})
                response = conn.getresponse()
                body = response.read()
                return response.status, (time.perf_counter()-started)*1000, body
            finally:
                conn.close()
        try:
            with contextlib.redirect_stderr(io.StringIO()):
                denied = request('/console.html')[0]
                replay_status, _, replay_raw = request('/bridge/replay', reader)
                replay = json.loads(replay_raw)
                if denied != 401 or replay_status != 200 or replay.get('forecast', {}).get('automatic_containment') is not False:
                    raise RuntimeError('Authentication/recorded shadow replay gate failed')
                began = time.perf_counter()
                with ThreadPoolExecutor(max_workers=workers) as pool:
                    responses = list(pool.map(lambda i: request('/api/readiness' if i % 2 else '/api/operations', reader), range(requests)))
                elapsed = time.perf_counter()-began
                if any(status != 200 for status, _, _ in responses):
                    raise RuntimeError('Local operational HTTP rehearsal failed')
                key = root/'backup.key'
                with os.fdopen(os.open(key, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600), 'wb') as stream:
                    stream.write(os.urandom(32))
                began_backup = time.perf_counter()
                backup = backup_runtime(root/'live', root/'snapshot.enc', key, 'local-rehearsal')
                backup_ms = (time.perf_counter()-began_backup)*1000
                began_restore = time.perf_counter()
                restore = restore_runtime(root/'snapshot.enc', root/'restored', key, 'local-rehearsal')
                restore_ms = (time.perf_counter()-began_restore)*1000
                recovered = PolicyStore(root/'restored')
                try:
                    recovery_ok = recovered.verify() and not recovered.active()
                finally:
                    recovered.close()
                if not recovery_ok:
                    raise RuntimeError('Restored audit/policy gate failed')
                latencies = sorted(value for _, value, _ in responses)
                report = dict(schema='krishna-pilot-rehearsal-v1', created_unix=time.time(),
                    scope='bounded localhost integration and recovery smoke, NOT enterprise capacity or forecast accuracy',
                    production_traffic=False, model_sha256=app.service.model_hash,
                    unauthenticated_console_status=denied, recorded_shadow_replay_status=replay_status,
                    automatic_containment=False,
                    http=dict(requests=requests, workers=workers, duration_seconds=round(elapsed, 4),
                        statuses=dict(Counter(str(s) for s, _, _ in responses)),
                        median_latency_ms=round(statistics.median(latencies), 3),
                        p95_latency_ms=round(latencies[max(0, int(.95*len(latencies)+.999)-1)], 3)),
                    recovery=dict(encrypted_archive_bytes=backup['bytes'], original_events=backup['event_count'],
                        backup_ms=round(backup_ms, 3), restore_ms=round(restore_ms, 3),
                        restored_audit_integrity=recovery_ok, policies_reactivated=restore['policies_reactivated'],
                        credentials_restored=restore['credentials_restored']),
                    operations=app.operations.snapshot())
                return report
        finally:
            server.shutdown();server.server_close();thread.join(timeout=3);app.policy.close()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--artifacts', default='garuda_v3/artifacts/residual_run')
    parser.add_argument('--output', required=True, help='New JSON report path; never overwritten')
    parser.add_argument('--requests', type=int, default=40)
    parser.add_argument('--workers', type=int, default=4)
    args = parser.parse_args()
    report = rehearse(args.artifacts, args.requests, args.workers)
    with os.fdopen(os.open(args.output, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600), 'w') as stream:
        json.dump(report, stream, indent=2, sort_keys=True)
        stream.write('\n')
    print(json.dumps(report, sort_keys=True))


if __name__ == '__main__':
    main()
