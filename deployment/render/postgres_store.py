"""Durable PostgreSQL store for authenticated *advisory* live forecast metadata.

Separate from immutable training artifacts and model weights. Does not ingest
packet payloads, source IPs, or promote new observations into model training.
"""
from __future__ import annotations

import json
import threading
import time
from urllib.parse import urlsplit

from garuda_v3.live_feed import LiveFeed, LiveFeedError


class PostgresEventStore:
    def __init__(self, database_url: str, sensor_token: str, connect=None, clock=None):
        if not isinstance(database_url, str) or urlsplit(database_url).scheme not in ("postgres", "postgresql"):
            raise ValueError("Valid DATABASE_URL (postgresql://...) is required")
        self._clock = clock or time.time
        self._token = sensor_token
        self._lock = threading.Lock()
        if connect is None:
            import psycopg
            connect = psycopg.connect
        self._connect = connect
        self._dsn = database_url
        self._initialize()

    def _initialize(self):
        with self._connect(self._dsn) as conn:
            with conn.cursor() as cur:
                cur.execute("""
                    CREATE TABLE IF NOT EXISTS krishna_live_forecasts (
                        id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
                        capture_sha256 TEXT NOT NULL,
                        model_sha256 TEXT NOT NULL,
                        received_at DOUBLE PRECISION NOT NULL,
                        cutoff_epoch_seconds DOUBLE PRECISION NOT NULL,
                        event_json JSONB NOT NULL,
                        UNIQUE(capture_sha256, model_sha256)
                    )
                """)
                cur.execute("""
                    CREATE INDEX IF NOT EXISTS krishna_live_forecasts_received
                    ON krishna_live_forecasts (received_at DESC)
                """)

    def _validated_event(self, payload):
        # Validate against the existing strict contract using the SAME clock
        # before any database write, including retries of older data.
        validator = LiveFeed(self._token, clock=self._clock)
        return validator.append(payload)

    def accept(self, payload):
        event = self._validated_event(payload)
        with self._lock, self._connect(self._dsn) as conn:
            with conn.cursor() as cur:
                cur.execute("""
                    INSERT INTO krishna_live_forecasts (
                        capture_sha256, model_sha256, received_at,
                        cutoff_epoch_seconds, event_json
                    )
                    VALUES (%s, %s, %s, %s, %s::jsonb)
                    ON CONFLICT (capture_sha256,model_sha256) DO NOTHING
                    RETURNING id
                """, (
                    event["capture_sha256"], event["model_sha256"],
                    event["received_at"], event["cutoff_epoch_seconds"],
                    json.dumps(event, allow_nan=False),
                ))
                inserted = cur.fetchone()
                if inserted:
                    event["id"] = inserted[0]
                    cur.execute("""
                        UPDATE krishna_live_forecasts
                        SET event_json = %s::jsonb
                        WHERE id = %s
                    """, (json.dumps(event, allow_nan=False), event["id"]))
                    return event

                cur.execute("""
                    SELECT id, event_json
                    FROM krishna_live_forecasts
                    WHERE capture_sha256 = %s AND model_sha256 = %s
                """, (event["capture_sha256"], event["model_sha256"]))
                existing = cur.fetchone()
                if existing is None:
                    raise LiveFeedError("Concurrent capture receipt unavailable")
                old = existing[1] if isinstance(existing[1], dict) else json.loads(existing[1])
                # Repeated delivery is idempotent only if the *same* validated
                # prediction is being re-sent. Never rewrite historical data.
                keys = ("capture_sha256", "model_sha256", "cutoff_epoch_seconds",
                        "trajectory", "alert", "supported",
                        "automatic_containment", "operating_mode")
                if any(old.get(k) != event.get(k) for k in keys):
                    raise LiveFeedError("Conflicting source/model provenance")
                return old

    def snapshot(self, after=0):
        if isinstance(after, bool) or not isinstance(after, int) or not 0 <= after <= 9007199254740991:
            raise LiveFeedError("Invalid cursor")
        with self._connect(self._dsn) as conn:
            with conn.cursor() as cur:
                cur.execute("""
                    SELECT id,received_at FROM krishna_live_forecasts
                    ORDER BY id DESC LIMIT 1
                """)
                latest = cur.fetchone()
                cur.execute("SELECT id FROM krishna_live_forecasts ORDER BY id ASC LIMIT 1")
                earliest = cur.fetchone()
                cur.execute("""
                    SELECT event_json FROM krishna_live_forecasts
                    WHERE id > %s ORDER BY id ASC LIMIT 128
                """, (after,))
                result = cur.fetchall()
        now = self._clock()
        age = max(0, now - float(latest[1])) if latest else None
        state = ("waiting" if latest is None else
                 "stale" if age > LiveFeed.STALE_AFTER else "near_live")
        events = [
            data[0] if isinstance(data[0], dict) else json.loads(data[0])
            for data in result
        ]
        return {
            "state": state, "source": "completed_capture_shadow",
            "stream": "bounded_polling_postgresql",
            "automatic_containment": False,
            "cursor": int(latest[0]) if latest else 0,
            "events": events,
            "sensor_age_seconds": round(age, 1) if age is not None else None,
            "gap": bool(earliest and after > 0 and after < int(earliest[0]) - 1),
        }
