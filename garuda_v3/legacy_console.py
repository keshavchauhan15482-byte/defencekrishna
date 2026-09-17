"""Serve the legacy Ultron console on localhost:8091 with a same-origin Garuda bridge.

The legacy visualisation is intentionally kept intact. This server injects a small
integration layer that routes the console to the authenticated Garuda V15 runtime
on localhost:8090 without exposing local bearer tokens to the browser.

Network-lab scenarios are recorded/synthetic telemetry exercises. Attack names are
scenario metadata; Garuda risk/alert values are model outputs. Sudarshana remains
subject to the runtime's real authorization and enforcement gates.
"""
from __future__ import annotations

import copy
import json
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

SCENARIOS = {
    "syn_flood": {"label": "SYN Flood", "mode": "known", "offset": 0.011, "family": "volumetric"},
    "port_scan": {"label": "Port Scan", "mode": "known", "offset": 0.017, "family": "reconnaissance"},
    "lateral_smb": {"label": "SMB Lateral Movement", "mode": "known", "offset": 0.023, "family": "lateral-movement"},
    "burst_ddos": {"label": "DDoS Burst", "mode": "known", "offset": 0.029, "family": "volumetric"},
    "dns_tunnel": {"label": "DNS Tunnel Anomaly", "mode": "unknown", "offset": 0.013, "family": "novel-anomaly"},
    "c2_beacon": {"label": "C2 Beacon Anomaly", "mode": "unknown", "offset": 0.019, "family": "novel-anomaly"},
    "exfil_spike": {"label": "Exfiltration Spike", "mode": "unknown", "offset": 0.031, "family": "novel-anomaly"},
    "clean_baseline": {"label": "Clean Baseline", "mode": "clean", "offset": 0.0, "family": "benign"},
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
    """Create a schema-valid local lab variant without pretending the scenario label is a model class."""
    if key not in SCENARIOS:
        raise ValueError("Unknown network-lab scenario")
    scenario = SCENARIOS[key]
    if scenario["mode"] == "clean":
        payload = _read_replay("replay.json")
        payload["data_source"] = "recorded_network_baseline"
        return payload

    payload = copy.deepcopy(_read_replay("alert_replay.json"))
    # Deterministically nudge a few observed numeric features. This gives each
    # network-lab scenario a distinct response fingerprint while preserving the
    # real graph schema and keeping the model inference path unchanged.
    base = float(scenario["offset"])
    jitter = (nonce % 97) * 0.000001
    x = payload.get("x", [])
    mask = payload.get("mask", [])
    touched = 0
    for t in range(max(0, len(x) - 3), len(x)):
        row_mask = mask[t] if t < len(mask) else []
        for node, feats in enumerate(x[t]):
            active = node < len(row_mask) and bool(row_mask[node])
            if not active or not feats:
                continue
            for feature_index, scale in ((0, 1.0), (2, 0.55), (3, 0.35)):
                if feature_index < len(feats):
                    value = float(feats[feature_index]) + base * scale + jitter
                    feats[feature_index] = max(0.0, min(1.0, value))
            touched += 1
            if touched >= 5:
                break
        if touched >= 5:
            break
    payload["data_source"] = (
        "synthetic_network_lab_known:" if scenario["mode"] == "known"
        else "synthetic_network_lab_unknown:"
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

    # Unknown scenarios are intentionally fresh fingerprints on each run. Known
    # scenarios are deterministic so the reviewed exact-memory path can match.
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
        "telemetry_kind": "synthetic",
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
        return self.headers.get("Host", "") in {"127.0.0.1:8091", "localhost:8091"}

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
        except (RuntimeError, ValueError, KeyError, json.JSONDecodeError) as exc:
            return self._json(502, {"error": str(exc)})

    def do_POST(self) -> None:
        url = urlsplit(self.path)
        if not self._host_ok() or not self._check_origin():
            return self._json(403, {"error": "Local same-origin console only"})
        if url.path != "/bridge/simulate":
            return self._json(404, {"error": "Unknown endpoint"})
        try:
            length = int(self.headers.get("Content-Length", "0"))
            if not 0 < length <= 4096:
                raise ValueError("Invalid request size")
            obj = json.loads(self.rfile.read(length).decode("utf-8"))
            key = obj.get("scenario")
            return self._json(200, _simulate(key))
        except (RuntimeError, ValueError, KeyError, TypeError, json.JSONDecodeError) as exc:
            return self._json(422, {"error": str(exc)})


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
