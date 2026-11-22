"""Authenticated metadata-only Garuda sensor relay for Render.

Not an AI inference host, packet sensor, WAF, or production multi-tenant service.
Only bounded shadow evidence is accepted. Secrets are never returned to browsers.
Render terminates external TLS; this process listens on the platform PORT.
"""
from __future__ import annotations

import hmac
import json
import os
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlsplit

from garuda_v3.live_feed import LiveFeed, LiveFeedError

MAX_BODY = 8192
MAX_CURSOR = 9007199254740991


class RelayState:
    def __init__(self, sensor_token: str, viewer_token: str):
        self.feed = LiveFeed(sensor_token)
        if not viewer_token or not 32 <= len(viewer_token) <= 256:
            raise ValueError("RENDER_VIEWER_TOKEN must be 32..256 characters")
        if any(ord(c) < 33 or ord(c) > 126 for c in viewer_token):
            raise ValueError("RENDER_VIEWER_TOKEN must be non-whitespace ASCII")
        if hmac.compare_digest(sensor_token, viewer_token):
            raise ValueError("Sensor and viewer tokens must be independent")
        if not self.feed.enabled:
            raise ValueError("GARUDA_LIVE_SENSOR_TOKEN must be configured")
        self.viewer_token = viewer_token
        self._ingest_lock = threading.Lock()

    def authorized_viewer(self, header: str):
        return (isinstance(header, str) and header.startswith("Bearer ") and
                hmac.compare_digest(header[7:], self.viewer_token))

    def accept(self, payload):
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
        result = self.feed.snapshot(after)
        # Never return capture SHA, model SHA, host addresses or raw inputs.
        result["events"] = [{
            key: item[key] for key in (
                "id", "kind", "source", "received_at", "cutoff_epoch_seconds",
                "trajectory", "score", "alert", "supported", "operating_mode",
                "automatic_containment", "verified_precompromise"
            )
        } for item in result["events"]]
        return result


class RelayHandler(BaseHTTPRequestHandler):
    server_version = "KrishnaLiveRelay/1"
    protocol_version = "HTTP/1.1"

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

    def do_OPTIONS(self):
        self.reply(405, {"error": "Cross-origin browser requests unsupported"})

    def do_GET(self):
        url = urlsplit(self.path)
        if url.path == "/health" and not url.query:
            return self.reply(200, {"status": "ready", "service": "advisory_telemetry_relay"})
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
        return self.reply(200, self.server.state.events(value))

    def do_POST(self):
        if urlsplit(self.path).path != "/api/live/ingest":
            return self.reply(404, {"error": "Unknown endpoint"})
        if not self.server.state.feed.authorized(self.headers.get("Authorization", "")):
            return self.reply(401, {"error": "Sensor authorization required"})
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
    state = RelayState(sensor, viewer)
    port = int(os.environ.get("PORT", "10000"))
    if not 1 <= port <= 65535:
        raise ValueError("PORT out of range")
    server = RelayServer(("0.0.0.0", port), state)
    print("Krishna advisory relay ready: /health. No model inference or policy action.", flush=True)
    try:
        server.serve_forever()
    finally:
        server.server_close()


if __name__ == "__main__":
    main()
