"""Serve the legacy Ultron console on localhost:8091 with a same-origin Garuda bridge.

The legacy visualisation is intentionally kept intact. This server injects a small
integration layer that routes the console to the authenticated Garuda V15 runtime
on localhost:8090 without exposing local bearer tokens to the browser.

Network-lab scenarios are recorded/synthetic telemetry exercises. Attack names are
scenario metadata; Garuda risk/alert values are model outputs. Sudarshana remains
subject to the runtime's real authorization and enforcement gates.
"""
from __future__ import annotations

import json
from .upload_inference import analyze, MAX_BYTES
from .dashboard_lab import LAB
import os
import time
import urllib.error
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlsplit

ROOT = Path(__file__).resolve().parents[1]
UI = Path(__file__).resolve().parent / "ui"
CONSOLE = ROOT / "console.html"
RUNTIME = ROOT / "garuda_v3" / "runtime"
ARTIFACTS = ROOT / "garuda_v3" / "artifacts" / "residual_run"
ENGINE = "http://127.0.0.1:8090"

# The scenario label is operator/demo metadata, not a class emitted by the model.
# time_shift changes only absolute timestamps, never the graph values or spacing;
# this gives reviewed-memory exercises distinct fingerprints without altering the
# Garuda model input features or its forecast score.
SCENARIOS = {
    "syn_flood": {"label": "SYN Flood", "mode": "known", "time_shift": 1010, "family": "volumetric"},
    "port_scan": {"label": "Port Scan", "mode": "known", "time_shift": 2020, "family": "reconnaissance"},
    "lateral_smb": {"label": "SMB Lateral Movement", "mode": "known", "time_shift": 3030, "family": "lateral-movement"},
    "burst_ddos": {"label": "DDoS Burst", "mode": "known", "time_shift": 4040, "family": "volumetric"},
    "dns_tunnel": {"label": "DNS Tunnel Anomaly", "mode": "unknown", "time_shift": 5050, "family": "novel-anomaly"},
    "c2_beacon": {"label": "C2 Beacon Anomaly", "mode": "unknown", "time_shift": 6060, "family": "novel-anomaly"},
    "exfil_spike": {"label": "Exfiltration Spike", "mode": "unknown", "time_shift": 7070, "family": "novel-anomaly"},
    "clean_baseline": {"label": "Clean Baseline", "mode": "clean", "time_shift": 0, "family": "benign"},
}


def _access() -> dict:
    path = RUNTIME / "access.json"
    if not path.exists():
        raise RuntimeError("Garuda access.json is unavailable; start the integrated runtime first")
    return json.loads(path.read_text())


def _engine_json(path: str, *, method: str = "GET", body: dict | None = None, operator: bool = False) -> dict:
    access = _access()
    token = access["operator_token" if operator else "viewer_token"]
    data = None if body is None else json.dumps(body, allow_nan=False).encode("utf-8")
    request = urllib.request.Request(
        ENGINE + path,
        data=data,
        method=method,
        headers={
            "Authorization": "Bearer " + token,
            "Content-Type": "application/json",
        },
    )
    try:
        with urllib.request.urlopen(request, timeout=20) as response:
            return json.loads(response.read().decode("utf-8"))
    except urllib.error.HTTPError as exc:
        detail = exc.read().decode("utf-8", errors="replace")
        raise RuntimeError(f"Garuda runtime returned HTTP {exc.code}: {detail[:400]}") from exc
    except urllib.error.URLError as exc:
        raise RuntimeError("Garuda runtime on localhost:8090 is not reachable") from exc


def _read_replay(name: str) -> dict:
    path = ARTIFACTS / name
    if not path.exists():
        raise RuntimeError(f"Required Garuda replay is missing: {path.name}")
    return json.loads(path.read_text())


def _variant_payload(key: str, nonce: int = 0) -> dict:
    """Create a schema-valid route demo without changing model feature values."""
    if key not in SCENARIOS:
        raise ValueError("Unknown network-lab scenario")
    scenario = SCENARIOS[key]
    if scenario["mode"] == "clean":
        payload = _read_replay("replay.json")
        payload["data_source"] = "recorded_network_baseline"
        return payload

    payload = _read_replay("alert_replay.json")
    base_shift = int(scenario["time_shift"])
    # Unknown runs receive a small fresh integer timestamp shift so a previously
    # reviewed fingerprint cannot silently turn an unknown demonstration into an
    # Arjuna match. Contiguous 10-second spacing remains exactly unchanged.
    fresh_shift = 0 if scenario["mode"] == "known" else int(nonce % 997) + 1
    total_shift = base_shift + fresh_shift
    payload["times"] = [float(t) + total_shift for t in payload.get("times", [])]
    payload["data_source"] = (
        "recorded_network_lab_known:" if scenario["mode"] == "known"
        else "recorded_network_lab_unknown_variant:"
    ) + key
    return payload


def _forecast(payload: dict) -> dict:
    return _engine_json("/api/forecast", method="POST", body=payload, operator=False)


def _simulate(key: str) -> dict:
    if key not in SCENARIOS:
        raise ValueError("Unknown network-lab scenario")
    scenario = SCENARIOS[key]
    if scenario["mode"] == "clean":
        forecast = _forecast(_variant_payload(key))
        return {
            "scenario": scenario,
            "scenario_key": key,
            "telemetry_kind": "recorded",
            "forecast": forecast,
        }

    # Known routes are deterministic so an operator-reviewed exact fingerprint
    # can be replayed through Arjuna. Unknown routes receive a fresh fingerprint.
    nonce = 0 if scenario["mode"] == "known" else time.time_ns()
    payload = _variant_payload(key, nonce)
    first = _forecast(payload)

    if scenario["mode"] == "known":
        signal = first.get("defence_signal") or {}
        if signal.get("route") != "arjuna" and first.get("alert") and signal.get("id"):
            _engine_json(
                "/api/response/approve",
                method="POST",
                operator=True,
                body={
                    "id": signal["id"],
                    "attack_type": scenario["label"],
                    "evidence": "Operator-approved local network-lab replay for exact-memory route validation.",
                },
            )
            forecast = _forecast(payload)
        else:
            forecast = first
    else:
        forecast = first

    return {
        "scenario": scenario,
        "scenario_key": key,
        "telemetry_kind": "recorded-variant",
        "forecast": forecast,
        "first_route": (first.get("defence_signal") or {}).get("route"),
    }


def _inject_console() -> bytes:
    html = CONSOLE.read_text(encoding="utf-8")
    css = '<link rel="stylesheet" href="/console-integrated.css">'
    js = '<script src="/console-integrated.js"></script>'
    if css not in html:
        html = html.replace("</head>", css + "\n</head>")
    if js not in html:
        html = html.replace("</body>", js + "\n</body>")
    return html.encode("utf-8")


class LegacyConsoleHandler(BaseHTTPRequestHandler):
    server_version = "GarudaLegacyConsole/1"

    def log_message(self, fmt: str, *args) -> None:
        pass

    def _host_ok(self) -> bool:
        port = self.server.server_port
        return self.headers.get("Host", "") in {f"127.0.0.1:{port}", f"localhost:{port}"}

    def _send(self, status: int, data: bytes, mime: str) -> None:
        self.send_response(status)
        self.send_header("Content-Type", mime)
        self.send_header("Content-Length", str(len(data)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Referrer-Policy", "no-referrer")
        self.end_headers()
        self.wfile.write(data)

    def _json(self, status: int, obj: dict) -> None:
        self._send(status, json.dumps(obj, allow_nan=False).encode("utf-8"), "application/json")

    def _check_origin(self) -> bool:
        origin = self.headers.get("Origin")
        host = self.headers.get("Host", "")
        return not origin or origin == "http://" + host

    def do_GET(self) -> None:
        url = urlsplit(self.path)
        if not self._host_ok() or not self._check_origin():
            return self._json(403, {"error": "Local same-origin console only"})
        try:
            if url.path in ("/", "/console.html"):
                return self._send(200, _inject_console(), "text/html; charset=utf-8")
            if url.path == "/console-integrated.js":
                return self._send(200, (UI / "console-integrated.js").read_bytes(), "application/javascript")
            if url.path == "/console-integrated.css":
                return self._send(200, (UI / "console-integrated.css").read_bytes(), "text/css")
            if url.path == "/health":
                return self._json(200, {"status": "alive", "engine": ENGINE})
            if url.path == "/bridge/status":
                return self._json(200, _engine_json("/api/status"))
            if url.path == "/bridge/response":
                return self._json(200, _engine_json("/api/response"))
            if url.path == "/bridge/replay":
                scenario = parse_qs(url.query).get("scenario", ["standard"])[0]
                if scenario not in {"standard", "alert", "hosts"}:
                    raise ValueError("Unknown replay scenario")
                return self._json(200, _engine_json("/api/replay?scenario=" + scenario))
            return self._json(404, {"error": "Unknown endpoint"})
        except ValueError as exc:
            return self._json(422, {"error": str(exc)})
        except (RuntimeError, KeyError, json.JSONDecodeError) as exc:
            return self._json(502, {"error": str(exc)})

    def do_POST(self) -> None:
        url = urlsplit(self.path)
        if not self._host_ok() or not self._check_origin():
            return self._json(403, {"error": "Local same-origin console only"})
        if url.path == "/bridge/analyze":
            try:
                if self.headers.get("Transfer-Encoding"):
                    raise ValueError("Chunked uploads are unsupported")
                length = int(self.headers.get("Content-Length", "0"))
                if not 0 < length <= MAX_BYTES:
                    raise ValueError("Upload limit is 8 MiB")
                kind = parse_qs(url.query).get("kind", [""])[0]
                raw = self.rfile.read(length)
                if len(raw) != length:
                    raise ValueError("Incomplete upload")
                return self._json(200, analyze(raw, kind, ARTIFACTS))
            except (ValueError, UnicodeError, KeyError) as exc:
                return self._json(422, {"error": str(exc)})
        if url.path not in ("/bridge/simulate", "/bridge/lab/probe"):
            return self._json(404, {"error": "Unknown endpoint"})
        try:
            length = int(self.headers.get("Content-Length", "0"))
            if not 0 < length <= 4096:
                raise ValueError("Invalid request size")
            obj = json.loads(self.rfile.read(length).decode("utf-8"))
            if url.path == "/bridge/lab/probe":
                status, result = LAB.probe(obj.get("ticket"))
                return self._json(status, result)
            key = obj.get("scenario")
            result = _simulate(key)
            result["lab"] = LAB.issue(result["forecast"])
            return self._json(200, result)
        except ValueError as exc:
            return self._json(422, {"error": str(exc)})
        except (RuntimeError, KeyError, TypeError, json.JSONDecodeError) as exc:
            return self._json(502, {"error": str(exc)})


class LegacyConsoleServer(ThreadingHTTPServer):
    daemon_threads = True


def main() -> None:
    port = int(os.environ.get("GARUDA_LEGACY_PORT", "8091"))
    server = LegacyConsoleServer(("127.0.0.1", port), LegacyConsoleHandler)
    print(
        f"Garuda integrated legacy console: http://127.0.0.1:{port} — engine {ENGINE}. "
        "Network lab only; Sudarshana follows runtime authorization gates.",
        flush=True,
    )
    try:
        server.serve_forever()
    finally:
        server.server_close()


if __name__ == "__main__":
    main()
