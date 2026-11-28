"""Durable PostgreSQL store for authenticated *advisory* live forecast metadata.

Separate from immutable training artifacts and model weights. Does not ingest
packet payloads, source IPs, or promote new observations into model training.
"""
from __future__ import annotations

import json
import re
import threading
import time
from urllib.parse import urlsplit

from garuda_v3.live_feed import LiveFeed, LiveFeedError
from deployment.render.observed_index import observed_index
from deployment.render.http_forecast import forecast as forecast_http

FIXTURE_REASONS = {"ARJUNA": ["DEMO_HOSPITAL_AVAILABILITY","DEMO_DDOS_BURST","DEMO_PORT_SCAN","DEMO_SYN_FLOOD","SQLI_SIGNATURE","XSS_SIGNATURE","TRAVERSAL_SIGNATURE","COMMAND_SIGNATURE","HISTORICAL_DANGER_PATTERN","UNSPECIFIED_RULE"],"KRISHNA": ["DEMO_HOSPITAL_ANOMALY","DEMO_C2_BEACON","DEMO_DNS_TUNNEL","STRUCTURAL_ANOMALY_REVIEW","HISTORICAL_STRUCTURE_REVIEW","UNSPECIFIED_RULE"],"SUDARSHAN": ["DEMO_HOSPITAL_PRIVATE","DEMO_EXFIL_SPIKE","DEMO_LATERAL_SMB","FIXTURE_SCOPE_DENIED","UNSPECIFIED_RULE"]}


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
                cur.execute("""
                    CREATE TABLE IF NOT EXISTS krishna_site_activity_events (
                        id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
                        request_uuid TEXT NOT NULL UNIQUE,
                        observed_at DOUBLE PRECISION NOT NULL,
                        kind TEXT NOT NULL CHECK (kind = 'page_load')
                    )
                """)
                cur.execute("""
                    CREATE INDEX IF NOT EXISTS krishna_site_activity_at
                    ON krishna_site_activity_events (observed_at DESC)
                """)
                cur.execute("""
                    CREATE TABLE IF NOT EXISTS krishna_sensor_heartbeat (
                        singleton SMALLINT PRIMARY KEY CHECK (singleton = 1),
                        seen_at DOUBLE PRECISION NOT NULL,
                        state TEXT NOT NULL CHECK (state IN ('capturing','processing')),
                        capture_seconds INTEGER NOT NULL,
                        model_sha256 TEXT NOT NULL
                    )
                """)

                cur.execute("""
                    CREATE TABLE IF NOT EXISTS krishna_fixture_denial_buckets (
                        minute_epoch BIGINT NOT NULL,
                        lane TEXT NOT NULL CHECK (lane IN ('ARJUNA','KRISHNA','SUDARSHAN')),
                        denials INTEGER NOT NULL CHECK (denials BETWEEN 1 AND 120),
                        last_at DOUBLE PRECISION NOT NULL,
                        PRIMARY KEY(minute_epoch,lane)
                    )
                """)

                cur.execute("""
                    CREATE TABLE IF NOT EXISTS krishna_fixture_receipts (
                        id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
                        request_uuid TEXT NOT NULL UNIQUE,
                        observed_at DOUBLE PRECISION NOT NULL,
                        lane TEXT NOT NULL,
                        reason TEXT NOT NULL
                    )
                """)
                cur.execute("""
                    CREATE INDEX IF NOT EXISTS krishna_fixture_receipts_time
                    ON krishna_fixture_receipts(observed_at DESC)
                """)

                cur.execute("""
                    CREATE TABLE IF NOT EXISTS krishna_demo_pattern_memory (
                        lane TEXT NOT NULL CHECK (lane IN ('ARJUNA','KRISHNA','SUDARSHAN')),
                        reason TEXT NOT NULL,
                        confirmations INTEGER NOT NULL CHECK (confirmations BETWEEN 1 AND 8),
                        last_seen DOUBLE PRECISION NOT NULL,
                        PRIMARY KEY(lane,reason)
                    )
                """)

                # Serialize with receipt writes while recovering retained
                # observations. Max, not addition, makes restarts idempotent.
                cur.execute("LOCK TABLE krishna_fixture_receipts IN SHARE ROW EXCLUSIVE MODE")
                cur.execute("""
                    SELECT lane,reason,LEAST(COUNT(*),8)::INTEGER,MAX(observed_at)
                    FROM krishna_fixture_receipts GROUP BY lane,reason
                """)
                for lane,reason,count,last in cur.fetchall():
                    if lane not in FIXTURE_REASONS or reason not in FIXTURE_REASONS[lane] or reason=="UNSPECIFIED_RULE":
                        continue
                    cur.execute("""
                        INSERT INTO krishna_demo_pattern_memory(lane,reason,confirmations,last_seen)
                        VALUES(%s,%s,%s,%s)
                        ON CONFLICT(lane,reason) DO UPDATE SET
                        confirmations=GREATEST(krishna_demo_pattern_memory.confirmations,EXCLUDED.confirmations),
                        last_seen=GREATEST(krishna_demo_pattern_memory.last_seen,EXCLUDED.last_seen)
                    """,(lane,reason,count,last))

    def pattern_memory_snapshot(self):
        with self._connect(self._dsn) as conn:
            with conn.cursor() as cur:
                cur.execute("SELECT lane,reason,confirmations,last_seen FROM krishna_demo_pattern_memory ORDER BY last_seen DESC,lane,reason")
                rows=cur.fetchall()
        from deployment.render.pattern_memory import summarize
        return summarize(rows,FIXTURE_REASONS,self._clock())

    def record_fixture_denial(self, event):
        if (not isinstance(event,dict) or not ((event.get("schema")=="fixture-denial-v1" and set(event)=={"schema","request_uuid","lane"}) or (event.get("schema")=="fixture-denial-v2" and set(event)=={"schema","request_uuid","lane","reason"}))
                or not isinstance(event["lane"],str) or event["lane"] not in FIXTURE_REASONS
                or event.get("reason","UNSPECIFIED_RULE") not in FIXTURE_REASONS[event["lane"]]
                or not isinstance(event["request_uuid"],str)
                or not re.fullmatch(r"[a-f0-9]{8}(?:-[a-f0-9]{4}){3}-[a-f0-9]{12}",event["request_uuid"])):
            raise LiveFeedError("Invalid fixture decision")
        now=self._clock()
        minute=int(now//60)*60
        with self._connect(self._dsn) as conn:
            with conn.cursor() as cur:
                cur.execute("DELETE FROM krishna_fixture_receipts WHERE observed_at < %s",(now-3600,))
                cur.execute("""
                    INSERT INTO krishna_fixture_receipts(request_uuid,observed_at,lane,reason)
                    VALUES(%s,%s,%s,%s) ON CONFLICT(request_uuid) DO NOTHING RETURNING id
                """,(event["request_uuid"],now,event["lane"],event.get("reason","UNSPECIFIED_RULE")))
                if cur.fetchone() is None:
                    return {"accepted":True,"scope":"synthetic_fixture_denials_only"}
                reason=event.get("reason","UNSPECIFIED_RULE")
                if reason!="UNSPECIFIED_RULE":
                    cur.execute("""
                        INSERT INTO krishna_demo_pattern_memory(lane,reason,confirmations,last_seen)
                        VALUES(%s,%s,1,%s)
                        ON CONFLICT(lane,reason) DO UPDATE SET
                        confirmations=LEAST(8,krishna_demo_pattern_memory.confirmations+1),
                        last_seen=GREATEST(krishna_demo_pattern_memory.last_seen,EXCLUDED.last_seen)
                    """,(event["lane"],reason,now))
                cur.execute("DELETE FROM krishna_fixture_denial_buckets WHERE minute_epoch < %s",(minute-3600,))
                cur.execute("""
                    INSERT INTO krishna_fixture_denial_buckets(minute_epoch,lane,denials,last_at)
                    VALUES(%s,%s,1,%s)
                    ON CONFLICT(minute_epoch,lane) DO UPDATE SET
                    denials=LEAST(120,krishna_fixture_denial_buckets.denials+1),
                    last_at=GREATEST(krishna_fixture_denial_buckets.last_at,EXCLUDED.last_at)
                """,(minute,event["lane"],now))
        return {"accepted":True,"scope":"synthetic_fixture_denials_only"}

    def fixture_receipts_snapshot(self):
        now=self._clock()
        with self._connect(self._dsn) as conn:
            with conn.cursor() as cur:
                cur.execute("""
                    SELECT id,observed_at,lane,reason,COUNT(*) OVER () FROM krishna_fixture_receipts
                    WHERE observed_at >= %s AND observed_at <= %s
                    ORDER BY id DESC LIMIT 12
                """,(now-1800,now))
                rows=cur.fetchall()
        return {"source":"server_recorded_fixture_denials","events":[
            {"id":int(i),"observed_at":float(at),"lane":lane,"reason":reason,
             "decision":"DENY","status":403,"event_prediction_probability":None}
            for i,at,lane,reason,total in rows if lane in FIXTURE_REASONS and reason in FIXTURE_REASONS[lane]],
            "observed_at":now,"scope":"synthetic_fixture_only","automatic_containment":False,
            "recorded_denials_30m":int(rows[0][4]) if rows else 0}

    def fixture_risk_snapshot(self, activity):
        now=self._clock()
        with self._connect(self._dsn) as conn:
            with conn.cursor() as cur:
                cur.execute("""
                    SELECT COALESCE(SUM(denials),0),MAX(last_at)
                    FROM krishna_fixture_denial_buckets
                    WHERE minute_epoch >= %s AND last_at > %s
                """,(int(now//60)*60-240,now-300))
                count,latest=cur.fetchone()
        age=max(0,now-float(latest)) if latest is not None else None
        n=int(count)
        return {"source":"observed_fixture_http_index","score":observed_index(activity["requests_5m"],n,age),
                "denials_recent_minute_buckets":n,"requests_5m":activity["requests_5m"],
                "observed_at":now,"is_prediction":False,"automatic_containment":False}

    def http_forecast_snapshot(self):
        now=self._clock()
        closed=int(now//60)*60
        with self._connect(self._dsn) as conn:
            with conn.cursor() as cur:
                cur.execute("SELECT MIN(observed_at) FROM krishna_site_activity_events")
                first=cur.fetchone()[0]
                cur.execute("""
                    SELECT (FLOOR(observed_at / 60)::bigint * 60), COUNT(*)
                    FROM krishna_site_activity_events
                    WHERE observed_at >= %s AND observed_at < %s
                    GROUP BY 1 ORDER BY 1
                """,(closed-3600,closed))
                pages=cur.fetchall()
                cur.execute("""
                    SELECT minute_epoch, SUM(denials), MAX(last_at)
                    FROM krishna_fixture_denial_buckets
                    WHERE minute_epoch >= %s AND last_at > %s
                    GROUP BY minute_epoch ORDER BY minute_epoch
                """,(closed-240,now-300))
                denials=cur.fetchall()
        return forecast_http(now,first,pages,denials)

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

    def record_site_request(self, event):
        """Persist one actually received first-party site request, not a model forecast.

        No IP, user agent, cookie, referrer, arbitrary request data or device ID
        is collected. A generated request UUID is for idempotent transport only.
        """
        if (not isinstance(event, dict) or
                set(event) != {"schema", "kind", "request_uuid"} or
                event.get("schema") != "krishna-site-activity-v1" or
                event.get("kind") != "page_load" or
                not isinstance(event.get("request_uuid"), str) or
                not re.fullmatch(r"[a-f0-9]{8}(?:-[a-f0-9]{4}){3}-[a-f0-9]{12}", event["request_uuid"])):
            raise LiveFeedError("Only anonymous first-party page_load records are permitted")
        observed = self._clock()
        with self._connect(self._dsn) as conn:
            with conn.cursor() as cur:
                cur.execute("""
                    INSERT INTO krishna_site_activity_events
                        (request_uuid, observed_at, kind)
                    VALUES (%s, %s, 'page_load')
                    ON CONFLICT (request_uuid) DO NOTHING RETURNING id
                """, (event["request_uuid"], observed))
                result = cur.fetchone()
        return {"accepted": True, "stored": bool(result), "mode": "HTTP_ACTIVITY_ONLY"}

    def site_activity_snapshot(self):
        """Read-only, aggregate actual HTTP request counts (not unique users)."""
        now = self._clock()
        with self._connect(self._dsn) as conn:
            with conn.cursor() as cur:
                cur.execute("""
                    SELECT COUNT(*)::bigint,
                           COUNT(*) FILTER (WHERE observed_at >= %s)::bigint,
                           MAX(observed_at),
                           COUNT(*) FILTER (WHERE observed_at >= %s)::bigint,
                           COUNT(*) FILTER (WHERE observed_at >= %s AND observed_at < %s)::bigint
                    FROM krishna_site_activity_events
                """, (now - 86400, now - 300, now - 600, now - 300))
                count, day_count, latest, recent, prior = cur.fetchone()
        return {
            "source": "first_party_page_requests",
            "description": "Observed page-load requests; not unique visitors or network attacks",
            "total_requests": int(count),
            "requests_24h": int(day_count),
            "requests_5m": int(recent),
            "requests_previous_5m": int(prior),
            "last_request_at": float(latest) if latest is not None else None,
            "is_model_input": False,
            "automatic_containment": False,
        }

    def record_sensor_heartbeat(self, event):
        """Declare actual on-host capture process liveness, never a forecast."""
        import re
        if (not isinstance(event, dict) or set(event) != {
            "schema", "kind", "state", "capture_seconds", "model_sha256"
        } or event.get("schema") != "krishna-sensor-heartbeat-v1"
                or event.get("kind") != "heartbeat"
                or event.get("state") not in ("capturing", "processing")
                or type(event.get("capture_seconds")) is not int
                or not 90 <= event["capture_seconds"] <= 600
                or not isinstance(event.get("model_sha256"), str)
                or not re.fullmatch(r"[0-9a-fA-F]{64}", event["model_sha256"])):
            raise LiveFeedError("Unsupported packet sensor heartbeat")
        now = self._clock()
        with self._connect(self._dsn) as conn:
            with conn.cursor() as cur:
                cur.execute("""
                    INSERT INTO krishna_sensor_heartbeat (
                        singleton, seen_at, state, capture_seconds, model_sha256
                    ) VALUES (1,%s,%s,%s,%s)
                    ON CONFLICT (singleton) DO UPDATE SET
                        seen_at=EXCLUDED.seen_at,
                        state=EXCLUDED.state,
                        capture_seconds=EXCLUDED.capture_seconds,
                        model_sha256=EXCLUDED.model_sha256
                """, (now, event["state"], event["capture_seconds"],
                      event["model_sha256"].lower()))
        return {"accepted": True, "mode": "SHADOW_CAPTURE_HEARTBEAT"}

    def sensor_status_snapshot(self):
        with self._connect(self._dsn) as conn:
            with conn.cursor() as cur:
                cur.execute("""
                    SELECT seen_at,state,capture_seconds
                    FROM krishna_sensor_heartbeat
                    WHERE singleton=1
                """)
                row = cur.fetchone()
        if row is None:
            return {
                "state": "absent", "sensor_age_seconds": None,
                "capture_seconds": None, "source": "authenticated_sensor_heartbeat"
            }
        age = max(0, self._clock() - float(row[0]))
        return {
            "state": "stale" if age > 90 else row[1],
            "sensor_age_seconds": round(age, 1),
            "capture_seconds": int(row[2]),
            "source": "authenticated_sensor_heartbeat",
        }
