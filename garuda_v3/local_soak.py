"""Private localhost endurance runner with real child-process crash/restart.

Synthetic upload fixtures and recorded replay exercise software only. This is
not attack efficacy, incident forecasting, or enterprise capacity certification.
"""
import argparse
from collections import Counter, deque
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
import http.client
import hashlib
import json
import math
import multiprocessing
import os
from pathlib import Path
import secrets
import sys
import tempfile
import time


def _serve(connection, artifacts, runtime, reader, operator):
    # Avoid unbounded captured logs, and keep fixture inference CPU reproducible.
    with open(os.devnull, 'w') as sink:
        os.dup2(sink.fileno(), 2)
    for name in ('OPENBLAS_NUM_THREADS', 'OMP_NUM_THREADS', 'MKL_NUM_THREADS'):
        os.environ[name] = '1'
    from .integrated_server import IntegratedApp, IntegratedHandler
    from .server import Server
    try:
        app = IntegratedApp(artifacts, runtime, reader, operator)
        server = Server(('127.0.0.1', 0), app)
        server.RequestHandlerClass = IntegratedHandler
        import numpy as np
        connection.send(dict(port=server.server_port, model_sha256=app.service.model_hash,
            runtime_versions=dict(python=sys.version.split()[0],numpy=np.__version__)))
        connection.close()
        try:
            server.serve_forever()
        finally:
            server.server_close();app.policy.close()
    except Exception as exc:
        try:connection.send(dict(error=type(exc).__name__))
        except (OSError, EOFError):pass
        raise


def _start(artifacts, runtime, reader, operator):
    context = multiprocessing.get_context('spawn')
    incoming, outgoing = context.Pipe(duplex=False)
    process = context.Process(target=_serve, args=(outgoing, artifacts, runtime, reader, operator))
    process.start();outgoing.close()
    try:
        if not incoming.poll(30):
            raise RuntimeError('Isolated child startup timed out')
        message = incoming.recv()
        if 'error' in message:
            raise RuntimeError('Isolated child startup failed: '+message['error'])
        return process, message
    except BaseException:
        _stop(process)
        raise
    finally:
        incoming.close()


def _stop(process, abrupt=False):
    if process.is_alive():
        process.kill() if abrupt else process.terminate()
    process.join(timeout=5)
    if process.is_alive():
        process.kill();process.join(timeout=5)


def resources(pid):
    """Actual child resources on Linux; unsupported hosts return unavailable."""
    try:
        status = {}
        for line in Path(f'/proc/{pid}/status').read_text().splitlines():
            if ':' in line:
                key, value = line.split(':', 1);status[key] = value.strip()
        raw = Path(f'/proc/{pid}/stat').read_text()
        fields = raw[raw.rfind(')')+2:].split()
        return dict(rss_kib=int(status['VmRSS'].split()[0]), threads=int(status['Threads']),
            fd_count=len(list(Path(f'/proc/{pid}/fd').iterdir())),
            cpu_seconds=(int(fields[11])+int(fields[12]))/os.sysconf('SC_CLK_TCK'))
    except (OSError, ValueError, KeyError, IndexError):
        return None


def request(port, path, token, body=None):
    connection = http.client.HTTPConnection('127.0.0.1', port, timeout=10)
    started = time.perf_counter()
    try:
        connection.request('POST' if body is not None else 'GET', path, body=body,
            headers={'Authorization': 'Bearer '+token})
        response = connection.getresponse()
        content = response.read()
        return response.status, (time.perf_counter()-started)*1000, content
    finally:
        connection.close()


def run_soak(artifacts, seconds=300, workers=4):
    if os.environ.get('GARUDA_DEPLOYMENT_PROFILE') != 'pilot':
        raise ValueError('Explicit GARUDA_DEPLOYMENT_PROFILE=pilot required')
    if not math.isfinite(seconds) or not 10 <= seconds <= 86400 or not 1 <= workers <= 8:
        raise ValueError('Use 10..86400 seconds and 1..8 workers')
    from .runtime_backup import backup_runtime, restore_runtime
    from .security import PolicyStore
    source_names=('server.py','integrated_server.py','security.py','operations.py',
        'runtime_lease.py','console_routes.py','local_soak.py')
    def source_hashes():
        return {name:hashlib.sha256((Path(__file__).parent/name).read_bytes()).hexdigest() for name in source_names}
    frozen_sources=source_hashes()
    # Same small, explicitly synthetic fixture as the upload regression contract.
    csv = ('Timestamp,Flow Duration,Protocol,Dst Port\n'+''.join(
        f'{datetime.fromtimestamp(1700000000+i*10, timezone.utc).isoformat()},1,6,80\n' for i in range(24))).encode()
    statuses, actions = Counter(), Counter()
    timings = deque(maxlen=4096)
    failure_examples = deque(maxlen=8)
    samples = deque(maxlen=720)
    segments = []
    unexpected = 0
    def record(action, status, latency):
        statuses[str(status)] += 1;actions[action] += 1;timings.append(latency)
    with tempfile.TemporaryDirectory(prefix='krishna-local-soak-') as folder:
        root = Path(folder);reader, operator = secrets.token_urlsafe(32), secrets.token_urlsafe(32)
        process, hello = _start(str(Path(artifacts).resolve()), str(root/'runtime'), reader, operator)
        expected_model = hello['model_sha256']
        started = time.monotonic();tick = 0;restarted = False;segment = None
        def new_segment():
            nonlocal segment
            segment = dict(index=len(segments), samples=0, rss_start_kib=None, rss_peak_kib=0,
                rss_end_kib=None, warm_rss_kib=None, max_threads=0, max_fds=0, cpu_seconds_sampled=0)
            segments.append(segment)
        new_segment()
        def sample(elapsed):
            value = resources(process.pid)
            if value:
                segment['samples'] += 1
                if segment['rss_start_kib'] is None:segment['rss_start_kib']=value['rss_kib']
                if segment['samples'] >= 10 and segment['warm_rss_kib'] is None:segment['warm_rss_kib']=value['rss_kib']
                segment['rss_peak_kib']=max(segment['rss_peak_kib'],value['rss_kib'])
                segment['rss_end_kib']=value['rss_kib']
                segment['max_threads']=max(segment['max_threads'],value['threads'])
                segment['max_fds']=max(segment['max_fds'],value['fd_count'])
                segment['cpu_seconds_sampled']=value['cpu_seconds']
                samples.append(dict(elapsed_seconds=round(elapsed,3),segment=segment['index'],**value))
        try:
            with ThreadPoolExecutor(max_workers=workers) as pool:
                while time.monotonic()-started < seconds:
                    elapsed = time.monotonic()-started
                    if not process.is_alive():raise RuntimeError('Isolated runtime exited unexpectedly')
                    # Abruptly kill ONLY our child, between requests. Dedicated
                    # regression separately kills between policy commit/publication.
                    if not restarted and elapsed >= seconds/2:
                        sample(elapsed);_stop(process, abrupt=True)
                        process, hello = _start(str(Path(artifacts).resolve()),str(root/'runtime'),reader,operator)
                        if hello['model_sha256'] != expected_model:raise RuntimeError('Checkpoint changed across restart')
                        status, latency, raw = request(hello['port'],'/api/status',reader)
                        record('restart_status',status,latency)
                        restored_status=json.loads(raw)
                        if status != 200 or restored_status.get('policies') or restored_status.get('enforcement_enabled'):
                            raise RuntimeError('Restart safety gate failed')
                        restarted=True;new_segment()
                    paths=['/bridge/status']*(workers-1)+['/health']
                    for status,latency,_ in pool.map(lambda path: request(hello['port'],path,reader), paths):
                        record('operational_get',status,latency)
                        if status != 200:unexpected+=1
                    if tick % 5 == 0:
                        status,latency,raw=request(hello['port'],'/bridge/replay',reader)
                        record('recorded_replay',status,latency)
                        if status != 200 or json.loads(raw).get('forecast',{}).get('automatic_containment') is not False:
                            unexpected+=1;failure_examples.append('recorded shadow replay did not pass')
                    if tick % 20 == 0:
                        status,latency,raw=request(hello['port'],'/bridge/analyze?kind=csv',operator,csv)
                        record('synthetic_csv_upload',status,latency)
                        uploaded=json.loads(raw)
                        forecasts=uploaded.get('forecasts',[])
                        finite=all(math.isfinite(float(point['malicious_flow_probability'])) for forecast in forecasts for point in forecast.get('trajectory',[]))
                        if status != 200 or not forecasts or not finite or uploaded.get('automatic_containment') is not False:
                            unexpected+=1;failure_examples.append('synthetic advisory upload did not pass')
                    if tick % 15 == 0:
                        status,latency,_=request(hello['port'],'/api/readiness',reader)
                        record('readiness',status,latency)
                        if status != 200:unexpected+=1
                    sample(elapsed);tick+=1
                    delay=min(started+tick-time.monotonic(),started+seconds-time.monotonic())
                    if delay > 0:time.sleep(min(delay,1))
            elapsed=time.monotonic()-started
            sample(elapsed)
            key=root/'backup.key'
            with os.fdopen(os.open(key,os.O_CREAT|os.O_EXCL|os.O_WRONLY,0o600),'wb') as stream:stream.write(os.urandom(32))
            backup=backup_runtime(root/'runtime',root/'snapshot.enc',key,'local-soak')
            restore=restore_runtime(root/'snapshot.enc',root/'restored',key,'local-soak')
            recovered=PolicyStore(root/'restored')
            try:recovery_ok=recovered.verify() and not recovered.active()
            finally:recovered.close()
            for item in segments:
                baseline=item['warm_rss_kib'] if item['warm_rss_kib'] is not None else item['rss_start_kib']
                item['rss_growth_kib']=None if baseline is None else item['rss_end_kib']-baseline
            # These are explicit development smoke thresholds, not customer SLAs.
            resource_gate=all(item['samples']>0 and item['rss_growth_kib']<=32768 and item['max_threads']<=24 and item['max_fds']<=128 for item in segments)
            latencies=sorted(timings)
            sources_unchanged=source_hashes()==frozen_sources
            passed=bool(not unexpected and restarted and recovery_ok and resource_gate and sources_unchanged)
            return dict(schema='krishna-local-soak-v1',status='PASS' if passed else 'FAIL',
                scope='local software endurance run; actual duration below, NOT enterprise capacity or forecasting evidence',
                created_unix=time.time(),duration_seconds=round(elapsed,3),requested_seconds=seconds,workers=workers,
                runtime_boundary_source_hashes=frozen_sources,runtime_sources_unchanged=sources_unchanged,
                runtime_versions=hello['runtime_versions'],
                model_sha256=expected_model,synthetic_upload_fixture=True,recorded_replay=True,public_listener=False,
                http=dict(statuses=dict(statuses),actions=dict(actions),unexpected=unexpected,
                    latency_sample_capacity=4096,latency_samples=len(latencies),
                    median_ms=round(latencies[len(latencies)//2],3),p95_ms=round(latencies[math.ceil(.95*len(latencies))-1],3)),
                abrupt_child_restart_passed=restarted,resource_gate_passed=resource_gate,resource_segments=segments,
                resource_samples=list(samples),failure_examples=list(failure_examples),
                recovery=dict(audit_integrity=recovery_ok,backup_events=backup['event_count'],policies_reactivated=restore['policies_reactivated']),
                limits=dict(resource_sample_capacity=720,warmup_samples=10,max_rss_growth_kib=32768,max_threads=24,max_fds=128),
                production_traffic=False,automatic_enforcement=False)
        finally:
            _stop(process)


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--artifacts',default='garuda_v3/artifacts/residual_run')
    parser.add_argument('--seconds',type=float,default=300)
    parser.add_argument('--workers',type=int,default=4)
    parser.add_argument('--output',required=True)
    args=parser.parse_args()
    try:
        report=run_soak(args.artifacts,args.seconds,args.workers)
    except (Exception, KeyboardInterrupt) as exc:
        report=dict(schema='krishna-local-soak-v1',status='FAIL',error_type=type(exc).__name__,
            scope='runner interrupted/failed; no successful soak evidence',created_unix=time.time(),
            requested_seconds=args.seconds,workers=args.workers,automatic_enforcement=False)
    with os.fdopen(os.open(args.output,os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600),'w') as stream:
        json.dump(report,stream,indent=2,sort_keys=True);stream.write('\n')
    summary={key:value for key,value in report.items() if key!='resource_samples'}
    print(json.dumps(summary,sort_keys=True),flush=True)
    if report['status']!='PASS':raise SystemExit(1)


if __name__=='__main__':main()
