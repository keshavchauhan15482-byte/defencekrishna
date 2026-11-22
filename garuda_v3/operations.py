"""Bounded, low-cardinality local operational metrics, never attack accuracy."""
import os
import shutil
import sqlite3
import threading
import time


class OperationalMetrics:
    BOUNDS_MS = (5, 20, 100, 500, 2000)

    def __init__(self):
        self.lock = threading.Lock()
        self.started = time.monotonic()
        self.in_flight = 0
        self.completed = 0
        self.latency_sum_ms = 0.0
        self.latency_max_ms = 0.0
        self.buckets = [0] * (len(self.BOUNDS_MS) + 1)
        self.codes = {name: 0 for name in ('2xx', '3xx', '4xx', '5xx', 'other')}
        self.capacity_rejections = 0
        self.min_free_bytes = int(os.environ.get('GARUDA_MIN_FREE_BYTES', str(64*1024*1024)))
        if not 1024*1024 <= self.min_free_bytes <= 1024**4:
            raise ValueError('GARUDA_MIN_FREE_BYTES must be 1 MiB..1 TiB')

    def begin(self):
        with self.lock:
            self.in_flight += 1

    def finish(self, status, duration_ms):
        with self.lock:
            self.in_flight -= 1
            self.completed += 1
            self.latency_sum_ms += duration_ms
            self.latency_max_ms = max(self.latency_max_ms, duration_ms)
            label = str(status//100)+'xx'
            self.codes[label if label in self.codes else 'other'] += 1
            bucket = next((i for i, bound in enumerate(self.BOUNDS_MS) if duration_ms <= bound), len(self.BOUNDS_MS))
            self.buckets[bucket] += 1

    def reject_capacity(self):
        with self.lock:
            self.capacity_rejections += 1

    def snapshot(self):
        with self.lock:
            return dict(scope='HTTP operations only; not detection or forecasting metrics',
                uptime_seconds=round(time.monotonic()-self.started, 3), completed=self.completed,
                in_flight=self.in_flight, status_classes=dict(self.codes),
                capacity_rejections=self.capacity_rejections,
                latency_sum_ms=round(self.latency_sum_ms, 3), latency_max_ms=round(self.latency_max_ms, 3),
                latency_bucket_upper_ms=list(self.BOUNDS_MS)+[None],
                latency_bucket_counts=list(self.buckets), histogram_cumulative=False)


def readiness(app):
    try:
        integrity = app.policy.verify()
    except (OSError, sqlite3.Error, ValueError):
        integrity = False
    minimum = getattr(getattr(app, 'operations', None), 'min_free_bytes', 64*1024*1024)
    try:
        free = shutil.disk_usage(app.policy.folder).free
        space_ok = free >= minimum
    except (OSError, AttributeError):
        free, space_ok = None, False
    publication_ok = not getattr(app.policy, 'publication_error', False)
    ready = bool(integrity and space_ok and publication_ok)
    return dict(status='ready' if ready else 'not_ready', audit_integrity=bool(integrity),
        runtime_space_ok=space_ok, runtime_free_bytes=free, minimum_free_bytes=minimum,
        policy_publication_ok=publication_ok,
        profile=getattr(app, 'deployment_profile', 'local'),
        scope='loaded local runtime, audit, publication fault and free space only; not gateway, freshness, model qualification or enterprise certification')
