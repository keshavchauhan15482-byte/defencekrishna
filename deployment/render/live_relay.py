"""Authenticated metadata-only Garuda sensor relay for Render.

Includes private on-demand graph inference; not an ingress packet sensor or WAF.
Only bounded shadow evidence is accepted. Secrets are never returned to browsers.
Render terminates external TLS; this process listens on the platform PORT.
"""
from __future__ import annotations

import collections
import hmac
import json
import os
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlsplit

from garuda_v3.live_feed import LiveFeed, LiveFeedError
from deployment.render.cloud_inference import CloudInference, MAX_GRAPH_BYTES

MAX_BODY = 8192
MAX_CURSOR = 9007199254740991


class RelayState:
    def __init__(self, sensor_token: str, viewer_token: str, store=None, activity_token=''):
        self.feed = LiveFeed(sensor_token)
        self.store = store
        self.cloud_inference = CloudInference()
        if not viewer_token or not 32 <= len(viewer_token) <= 256:
            raise ValueError("RENDER_VIEWER_TOKEN must be 32..256 characters")
        if any(ord(c) < 33 or ord(c) > 126 for c in viewer_token):
            raise ValueError("RENDER_VIEWER_TOKEN must be non-whitespace ASCII")
        if hmac.compare_digest(sensor_token, viewer_token):
            raise ValueError("Sensor and viewer tokens must be independent")
        if not self.feed.enabled:
            raise ValueError("GARUDA_LIVE_SENSOR_TOKEN must be configured")
        if activity_token and (not 32 <= len(activity_token) <= 256 or
                any(ord(c) < 33 or ord(c) > 126 for c in activity_token)):
            raise ValueError("RENDER_ACTIVITY_TOKEN must be a strong non-whitespace ASCII secret")
        if activity_token and (hmac.compare_digest(activity_token, viewer_token) or
                               hmac.compare_digest(activity_token, sensor_token)):
            raise ValueError("Activity token must be independent of sensor and viewer tokens")
        self.activity_token = activity_token
        self._activity_times = collections.deque()
        self._activity_lock = threading.Lock()
        self.viewer_token = viewer_token
        self._ingest_lock = threading.Lock()
        self._rate_lock = threading.Lock()
        self._sensor_times = collections.deque()

    def authorized_viewer(self, header: str):
        return (isinstance(header, str) and header.startswith("Bearer ") and
                hmac.compare_digest(header[7:], self.viewer_token))

    def authorized_activity(self, header):
        return (bool(self.activity_token) and isinstance(header, str) and
                header.startswith("Bearer ") and
                hmac.compare_digest(header[7:], self.activity_token))

    def activity_rate_ok(self):
        # Global small pilot quota; do not collect identifying client metadata.
        with self._activity_lock:
            now = time.monotonic()
            while self._activity_times and self._activity_times[0] < now - 60:
                self._activity_times.popleft()
            if len(self._activity_times) >= 120:
                return False
            self._activity_times.append(now)
            return True

    def sensor_rate_ok(self):
        with self._rate_lock:
            now = time.monotonic()
            while self._sensor_times and self._sensor_times[0] < now - 60:
                self._sensor_times.popleft()
            if len(self._sensor_times) >= 60:
                return False
            self._sensor_times.append(now)
            return True

    def accept(self, payload):
        if self.store is not None:
            return self.store.accept(payload)
        with self._ingest_lock:
            # Idempotency for network retries within the bounded memory horizon.
            if isinstance(payload, dict):
                source = payload.get("capture_sha256")
                model = payload.get("model_sha256")
                if isinstance(source, str) and isinstance(model, str):
                    for item in self.feed.snapshot()["events"]:
                        if (item["capture_sha256"] == source.lower() and
                                item["model_sha256"] == model.lower()):
                            # Independently validate every retry, including
                            # timestamp freshness, bounded fields and scores.
                            validation = LiveFeed("validation-only-secret-" + "x" * 32)
                            candidate = validation.append(payload)
                            keys = ("capture_sha256", "model_sha256",
                                    "cutoff_epoch_seconds", "trajectory",
                                    "alert", "supported")
                            if all(candidate[key] == item[key] for key in keys):
                                return dict(item)
                            raise LiveFeedError("Conflicting capture provenance")
            return self.feed.append(payload)

    def events(self, after: int):
        result = self.store.snapshot(after) if self.store is not None else self.feed.snapshot(after)
        # Never return capture SHA, model SHA, host addresses or raw inputs.
        result["events"] = [{
            key: item[key] for key in (
                "id", "kind", "source", "received_at", "cutoff_epoch_seconds",
                "trajectory", "score", "alert", "supported", "operating_mode",
                "automatic_containment", "verified_precompromise"
            )
        } for item in result["events"]]
        if self.store is not None:
            result["site_activity"] = self.store.site_activity_snapshot()
            result["sensor_status"] = self.store.sensor_status_snapshot()
            if hasattr(self.store,"fixture_risk_snapshot"):
                result["fixture_risk"] = self.store.fixture_risk_snapshot(result["site_activity"])
            if hasattr(self.store,"fixture_receipts_snapshot"):
                try:
                    result["fixture_receipts"] = self.store.fixture_receipts_snapshot()
                except Exception:
                    result["fixture_receipts"] = None
            if hasattr(self.store,"http_forecast_snapshot"):
                try:
                    result["http_forecast"] = self.store.http_forecast_snapshot()
                except Exception:
                    result["http_forecast"] = None
            if hasattr(self.store,"pattern_memory_snapshot"):
                try:
                    result["pattern_memory"]=self.store.pattern_memory_snapshot()
                except Exception:
                    result["pattern_memory"]=None
            result["packet_runtime"] = self.cloud_inference.status()
            result["packet_replay"] = self.cloud_inference.historical_state()
        return result


class RelayHandler(BaseHTTPRequestHandler):
    server_version = "KrishnaLiveRelay/1"
    protocol_version = "HTTP/1.0"  # close each response; no unread-body reuse

    def log_message(self, _format, *_args):
        # No source IP, query, tokens, hashes or payloads in application logs.
        pass

    def reply(self, status, payload):
        raw = json.dumps(payload, allow_nan=False, separators=(",", ":")).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(raw)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Cross-Origin-Resource-Policy", "same-origin")
        self.send_header("Content-Security-Policy", "default-src 'none'")
        self.send_header("Referrer-Policy", "no-referrer")
        self.end_headers()
        self.wfile.write(raw)

    def reply_homepage(self):
        """Human-readable health landing page, not a public inference route."""
        try:
            sensor = self.server.state.store.snapshot(0)["state"] if self.server.state.store else "waiting"
            healthy = True
        except Exception:
            sensor = "unavailable"
            healthy = False
        details = {
            "waiting": "Awaiting an authorized network capture sensor",
            "near_live": "Recent authenticated model capture received",
            "stale": "Model sensor has not sent a recent capture",
            "unavailable": "Persistent storage unavailable",
            "disabled": "Capture sensor not configured",
        }
        message = details.get(sensor, "Sensor state unavailable")
        page = (
            '<!doctype html><html lang="en"><head><meta charset="utf-8">'
            '<meta name="viewport" content="width=device-width,initial-scale=1">'
            '<title>Krishna Defence System | Backend</title>'
            '<style>body{margin:0;min-height:100vh;display:grid;place-items:center;'
            'background:#0b0f16;color:#edf3fc;font:16px/1.6 system-ui,Arial,sans-serif}'
            'main{width:min(560px,90vw);padding:36px;border:1px solid #344052;'
            'border-radius:18px;background:#151b25}h1{margin:0;color:#fca36f}'
            'p{color:#b8c5d3}a{color:#8bb8ff}small{color:#9bacbf}'
            '.ok{color:#7ce8af}</style></head><body><main>'
            '<small>KRISHNA DEFENCE SYSTEM · AUTHENTICATED TELEMETRY RELAY</small>'
            '<h1>Backend ' + ('online' if healthy else 'unavailable') + '</h1>'
            '<p class="ok">Python API: ' + ('online' if healthy else 'storage check failed') + '</p>'
            '<p>PostgreSQL: ' + ('connected' if healthy else 'unavailable') + '</p>'
            '<p>Garuda AI sensor: ' + message + '</p>'
            '<p>Original trained model runs only on an authorized capture sensor. '
            'This relay does not publicly expose packet contents, prediction inference, or '
            'automatic blocking.</p>'
            '<p><a href="https://krishna-defence-system.vercel.app/">'
            'Open Krishna Defence dashboard</a></p>'
            '<small>Read-only health: /health · Sensor and viewer routes require authentication.</small>'
            '</main></body></html>'
        ).encode("utf-8")
        self.send_response(200 if healthy else 503)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(page)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("X-Frame-Options", "DENY")
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header("Content-Security-Policy",
                         "default-src 'none'; style-src 'unsafe-inline'; base-uri 'none'")
        self.end_headers()
        self.wfile.write(page)

    def do_OPTIONS(self):
        self.reply(405, {"error": "Cross-origin browser requests unsupported"})

    def do_GET(self):
        url = urlsplit(self.path)
        if url.path in ("/", "/status") and not url.query:
            return self.reply_homepage()
        if url.path == "/health" and not url.query:
            if self.server.state.store is not None:
                try:
                    self.server.state.store.snapshot(0)
                except Exception:
                    return self.reply(503, {"status": "unavailable", "service": "persistent_telemetry"})
            return self.reply(200, {"status": "ready", "service": "advisory_telemetry_relay"})
        if url.path == "/api/cloud-inference/status" and not url.query:
            if not self.server.state.authorized_viewer(self.headers.get("Authorization", "")):
                return self.reply(401, {"error": "Viewer authorization required"})
            return self.reply(200, self.server.state.cloud_inference.status())
        if url.path == "/api/sensor/verify" and not url.query:
            # A no-write, authenticated sensor-token check. A Mac can test
            # its locally held credential BEFORE privileged packet capture.
            if not self.server.state.feed.authorized(self.headers.get("Authorization", "")):
                return self.reply(401, {"error": "Sensor authorization required"})
            if not self.server.state.sensor_rate_ok():
                return self.reply(429, {"error": "Sensor quota exceeded"})
            return self.reply(200, {
                "authorized": True, "mode": "SHADOW_ONLY",
                "packet_capture": "local_authorized_host_only",
            })
        if url.path != "/api/live/events":
            return self.reply(404, {"error": "Unknown endpoint"})
        if not self.server.state.authorized_viewer(self.headers.get("Authorization", "")):
            return self.reply(401, {"error": "Viewer authorization required"})
        params = parse_qs(url.query, keep_blank_values=True)
        if set(params) - {"after"} or len(params.get("after", ["0"])) != 1:
            return self.reply(422, {"error": "Invalid event cursor"})
        cursor = params.get("after", ["0"])[0]
        if not cursor.isascii() or not cursor.isdecimal() or len(cursor) > 16:
            return self.reply(422, {"error": "Invalid event cursor"})
        value = int(cursor)
        if value > MAX_CURSOR:
            return self.reply(422, {"error": "Invalid event cursor"})
        try:
            feed = self.server.state.events(value)
        except Exception:
            return self.reply(503, {"error": "Persistent telemetry storage unavailable"})
        return self.reply(200, feed)

    def _handle_site_activity(self):
        # Browser never sees this token: only Vercel's trusted serverless
        # relay uses it, and cannot trigger any forecast or blocking policy.
        if not self.server.state.authorized_activity(self.headers.get("Authorization", "")):
            return self.reply(401, {"error": "Private activity gateway credential required"})
        if not self.server.state.activity_rate_ok():
            return self.reply(429, {"error": "Activity ingest quota exceeded"})
        if self.headers.get("Content-Type", "").split(";")[0].strip().lower() != "application/json":
            return self.reply(415, {"error": "Activity JSON required"})
        sizes = self.headers.get_all("Content-Length", [])
        if (self.headers.get("Transfer-Encoding") or len(sizes) != 1 or
                not sizes[0].isascii() or not sizes[0].isdecimal() or
                len(sizes[0]) > 5 or not 0 < int(sizes[0]) <= 512):
            self.close_connection = True
            return self.reply(413, {"error": "Activity record must be 1..512 bytes"})
        try:
            raw = self.rfile.read(int(sizes[0]))
            if len(raw) != int(sizes[0]):
                raise ValueError("Incomplete activity record")
            if self.server.state.store is None:
                return self.reply(503, {"error": "Persistent activity storage not configured"})
            result = self.server.state.store.record_site_request(json.loads(raw.decode("utf-8")))
        except (ValueError, TypeError, LiveFeedError, UnicodeDecodeError):
            return self.reply(422, {"error": "Unsupported activity record"})
        except Exception:
            return self.reply(503, {"error": "Activity storage unavailable"})
        return self.reply(202, result)

    def _handle_sensor_heartbeat(self):
        if not self.server.state.feed.authorized(self.headers.get("Authorization", "")):
            return self.reply(401, {"error": "Sensor authorization required"})
        if not self.server.state.sensor_rate_ok():
            return self.reply(429, {"error": "Sensor quota exceeded"})
        if self.headers.get("Content-Type", "").split(";")[0].strip().lower() != "application/json":
            return self.reply(415, {"error": "JSON required"})
        sizes = self.headers.get_all("Content-Length", [])
        if (self.headers.get("Transfer-Encoding") or len(sizes) != 1 or
                not sizes[0].isascii() or not sizes[0].isdecimal() or
                len(sizes[0]) > 5 or not 0 < int(sizes[0]) <= 512):
            self.close_connection = True
            return self.reply(413, {"error": "Heartbeat must be 1..512 bytes"})
        try:
            raw = self.rfile.read(int(sizes[0]))
            if len(raw) != int(sizes[0]):
                raise ValueError("Incomplete sensor heartbeat")
            if self.server.state.store is None:
                return self.reply(503, {"error": "Persistent storage unavailable"})
            receipt = self.server.state.store.record_sensor_heartbeat(json.loads(raw.decode("utf-8")))
        except (ValueError, LiveFeedError, UnicodeDecodeError, TypeError):
            return self.reply(422, {"error": "Invalid or unsupported sensor heartbeat"})
        except Exception:
            return self.reply(503, {"error": "Persistent sensor status storage unavailable"})
        return self.reply(202, receipt)

    def _handle_fixture_decision(self):
        if not self.server.state.authorized_activity(self.headers.get("Authorization","")):
            return self.reply(401,{"error":"Private gateway required"})
        if not self.server.state.activity_rate_ok():
            return self.reply(429,{"error":"Telemetry quota exceeded"})
        if self.headers.get("Content-Type","").split(";")[0].strip().lower()!="application/json":
            return self.reply(415,{"error":"JSON required"})
        sizes=self.headers.get_all("Content-Length",[])
        if (self.headers.get("Transfer-Encoding") or len(sizes)!=1 or not sizes[0].isascii()
                or not sizes[0].isdecimal() or len(sizes[0])>3 or not 0<int(sizes[0])<=512):
            self.close_connection=True
            return self.reply(413,{"error":"Bounded decision required"})
        try:
            raw=self.rfile.read(int(sizes[0]))
            if len(raw)!=int(sizes[0]):raise ValueError("Incomplete decision")
            if self.server.state.store is None:return self.reply(503,{"error":"Storage unavailable"})
            return self.reply(202,self.server.state.store.record_fixture_denial(json.loads(raw.decode("utf-8"))))
        except (ValueError,TypeError,LiveFeedError,UnicodeDecodeError,RecursionError):
            return self.reply(422,{"error":"Invalid decision"})
        except Exception:
            return self.reply(503,{"error":"Storage unavailable"})

    def _handle_cloud_graph(self):
        if not self.server.state.feed.authorized(self.headers.get("Authorization", "")):
            return self.reply(401, {"error": "Sensor authorization required"})
        if not self.server.state.sensor_rate_ok():
            return self.reply(429, {"error": "Sensor quota exceeded"})
        if self.headers.get("Content-Type", "").split(";")[0].strip().lower() != "application/json":
            return self.reply(415, {"error": "JSON required"})
        sizes=self.headers.get_all("Content-Length", [])
        if (self.headers.get("Transfer-Encoding") or len(sizes)!=1 or not sizes[0].isascii()
                or not sizes[0].isdecimal() or len(sizes[0])>6 or not 0<int(sizes[0])<=MAX_GRAPH_BYTES):
            self.close_connection=True
            return self.reply(413, {"error": "Bounded graph required"})
        try:
            raw=self.rfile.read(int(sizes[0]))
            if len(raw)!=int(sizes[0]):
                raise ValueError("Incomplete graph")
            result=self.server.state.cloud_inference.predict(json.loads(raw.decode("utf-8")))
        except (ValueError, KeyError, TypeError, UnicodeDecodeError, OverflowError, RecursionError):
            return self.reply(422, {"error": "Invalid, incomplete or stale observed graph"})
        except Exception:
            return self.reply(503, {"error": "Cloud inference unavailable"})
        if result.get("status")!="forecast":
            return self.reply(422, result)
        # Keep cloud results private until independent source/continuity
        # evidence and dashboard integration are verified. No policy action.
        return self.reply(200, result)

    def do_POST(self):
        if self.path=="/api/fixture-decisions/ingest":
            return self._handle_fixture_decision()
        if self.path=="/api/cloud-inference/graph":
            return self._handle_cloud_graph()
        if urlsplit(self.path).path == "/api/sensor/heartbeat":
            return self._handle_sensor_heartbeat()
        if urlsplit(self.path).path == "/api/site-activity/ingest":
            return self._handle_site_activity()
        if urlsplit(self.path).path != "/api/live/ingest":
            return self.reply(404, {"error": "Unknown endpoint"})
        if not self.server.state.feed.authorized(self.headers.get("Authorization", "")):
            return self.reply(401, {"error": "Sensor authorization required"})
        if not self.server.state.sensor_rate_ok():
            return self.reply(429, {"error": "Sensor quota exceeded"})
        if self.headers.get("Content-Type", "").split(";")[0].strip().lower() != "application/json":
            return self.reply(415, {"error": "JSON required"})
        sizes = self.headers.get_all("Content-Length", [])
        if self.headers.get("Transfer-Encoding") or len(sizes) != 1 or not sizes[0].isascii() or not sizes[0].isdecimal():
            self.close_connection = True
            return self.reply(411, {"error": "Bounded Content-Length required"})
        length = int(sizes[0]) if len(sizes[0]) < 8 else MAX_BODY + 1
        if not 0 < length <= MAX_BODY:
            self.close_connection = True
            return self.reply(413, {"error": "Sensor payload exceeds limit"})
        try:
            raw = self.rfile.read(length)
            if len(raw) != length:
                raise ValueError("Incomplete sensor event")
            data = json.loads(raw.decode("utf-8"))
            event = self.server.state.accept(data)
        except (ValueError, TypeError, LiveFeedError, UnicodeDecodeError):
            return self.reply(422, {"error": "Malformed, conflicting or stale sensor event"})
        except Exception:
            return self.reply(503, {"error": "Persistent telemetry storage unavailable"})
        return self.reply(202, {"accepted": True, "event_id": event["id"],
                                "mode": "SHADOW_ONLY", "automatic_containment": False})


class RelayServer(ThreadingHTTPServer):
    daemon_threads = True

    def __init__(self, address, state):
        super().__init__(address, RelayHandler)
        self.state = state


def main():
    sensor = os.environ.get("GARUDA_LIVE_SENSOR_TOKEN", "")
    viewer = os.environ.get("RENDER_VIEWER_TOKEN", "")
    database_url = os.environ.get("DATABASE_URL", "")
    if not database_url:
        raise RuntimeError("DATABASE_URL required: do not deploy RAM-only history")
    from deployment.render.postgres_store import PostgresEventStore
    store = PostgresEventStore(database_url, sensor)
    state = RelayState(sensor, viewer, store=store, activity_token=os.environ.get("RENDER_ACTIVITY_TOKEN", ""))
    port = int(os.environ.get("PORT", "10000"))
    if not 1 <= port <= 65535:
        raise ValueError("PORT out of range")
    server = RelayServer(("0.0.0.0", port), state)
    print("Krishna advisory relay ready: persistent PostgreSQL metadata and private on-demand inference. No policy action.", flush=True)
    try:
        server.serve_forever()
    finally:
        server.server_close()


if __name__ == "__main__":
    main()
