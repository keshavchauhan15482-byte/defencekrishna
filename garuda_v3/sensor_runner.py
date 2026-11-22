"""Run an authorized, packet-trained Garuda shadow sensor from ONE terminal.

This is a local/private sensor, not a cloud packet sniffer or inline IPS.
Requires an actual host network interface, the user's OS packet-capture
permission, a locally kept Render sensor secret, and real compatible traffic.

Example on macOS from repo root:
  python3.12 -m garuda_v3.sensor_runner --interface en0 --authorized
"""
from __future__ import annotations

import argparse
import getpass
import http.client
import json
import os
import secrets
import shutil
import signal
import subprocess
import sys
import threading
import time
from pathlib import Path
from urllib.parse import urlsplit

from .live_publisher import deliver_pending, read_private_token, validate_endpoint
from .shadow_agent import ShadowAgent

DEFAULT_ARTIFACTS = "garuda_v3/artifacts/calibrated_host_v6"
DEFAULT_ENDPOINT = "https://krishna-shadow-telemetry.onrender.com/api/live/ingest"
MAX_PCAP_BYTES = 256 * 1024 * 1024


def required_capture_seconds(meta):
    """Capture at least 8 complete history windows AND a trailing partial bucket."""
    if meta.get("mode") != "host" or meta.get("packet_features_trained") is not True:
        raise ValueError(
            "Packet capture requires a packet-trained HOST risk checkpoint, "
            "not the 10-second CSV-flow residual_run or a state-only checkpoint"
        )
    if meta.get("risk_head_trained") is False or meta.get("risk_output_permitted") is False:
        raise ValueError("Selected checkpoint is state-only; risk probabilities are withheld")
    h, w = meta.get("history"), meta.get("window_seconds")
    if type(h) is not int or type(w) is not int or h < 1 or w < 1:
        raise ValueError("Invalid checkpoint history/window metadata")
    # Starting mid-window and dropping the last partial bucket need spare time.
    seconds = (h + 2) * w
    if not 90 <= seconds <= 600:
        raise ValueError(
            f"Checkpoint needs {seconds}s of capture; this bounded runner supports "
            "only 90..600s. Use a scoped/rolling capture sensor for longer windows"
        )
    return seconds


def _ensure_token(path):
    path = Path(path).expanduser()
    if path.exists() or path.is_symlink():
        return read_private_token(path)
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    if path.parent.is_symlink():
        raise ValueError("Sensor secret parent must not be a symlink")
    print("Paste the independent GARUDA_LIVE_SENSOR_TOKEN from Render Settings.")
    print("It is not shown as you type, and is never committed or sent to the browser.")
    token = getpass.getpass("Sensor token: ").strip()
    if not 32 <= len(token) <= 256 or any(ord(c) < 33 or ord(c) > 126 for c in token):
        raise ValueError("Invalid token length/characters; no credential saved")
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    fd = os.open(path, flags, 0o600)
    with os.fdopen(fd, "w", encoding="ascii") as handle:
        handle.write(token)
    os.chmod(path, 0o600)
    return token


def _capture_stream(interface, inbox, seconds, *, use_sudo=True, max_bytes=MAX_PCAP_BYTES):
    """Capture real PCAP bytes over stdout; the file stays user-owned (not root-owned).

    Capture subprocess uses *only* tcpdump with a fixed argument vector, no
    shell, no browser target and no attacker-supplied filter string.
    """
    import re

    if (not isinstance(interface, str) or interface.startswith("-") or
            not re.fullmatch(r"[a-zA-Z0-9_.:-]{1,32}", interface)):
        raise ValueError("Interface must be a simple local interface name (e.g. en0)")
    if not isinstance(seconds, int) or not 90 <= seconds <= 600:
        raise ValueError("Capture duration must be 90..600 seconds")
    binary = shutil.which("tcpdump")
    if not binary:
        raise RuntimeError("tcpdump missing. macOS typically provides /usr/sbin/tcpdump")
    if use_sudo:
        if shutil.which("sudo") is None:
            raise RuntimeError("sudo not installed; root capture permission needed")
        # Explicit local OS prompt, only before privileged packet capture.
        subprocess.run(["sudo", "-v"], check=True)
    folder = Path(inbox).expanduser()
    if folder.is_symlink() or not folder.is_dir():
        raise ValueError("Existing, non-symlink sensor inbox required")
    temp = folder / ("pending-" + secrets.token_hex(12) + ".pcap")
    ready = folder / ("capture-" + secrets.token_hex(12) + ".pcap.ready")
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    fd = os.open(temp, flags, 0o600)
    command = (["sudo", "-n"] if use_sudo else []) + [
        binary, "-i", interface, "-s", "0", "-U", "-w", "-"
    ]
    proc = None
    errors = []
    try:
        with os.fdopen(fd, "wb") as output:
            proc = subprocess.Popen(
                command, stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                start_new_session=True,
            )

            def copy_bytes():
                try:
                    total = 0
                    while True:
                        chunk = proc.stdout.read(65536)
                        if not chunk:
                            break
                        total += len(chunk)
                        if total > max_bytes:
                            errors.append("Capture exceeds 256 MiB safety limit")
                            try:
                                os.killpg(proc.pid, signal.SIGINT)
                            except ProcessLookupError:
                                pass
                            break
                        output.write(chunk)
                except (OSError, ValueError) as exc:
                    errors.append(type(exc).__name__)

            reader = threading.Thread(target=copy_bytes, daemon=True)
            reader.start()
            try:
                proc.wait(timeout=seconds)
            except subprocess.TimeoutExpired:
                # Signals both the sudo wrapper and its tcpdump child when
                # they share the dedicated process group.
                try:
                    os.killpg(proc.pid, signal.SIGINT)
                except ProcessLookupError:
                    pass
                try:
                    proc.wait(timeout=12)
                except subprocess.TimeoutExpired:
                    os.killpg(proc.pid, signal.SIGKILL)
                    proc.wait(timeout=5)
                    errors.append("tcpdump failed to stop cleanly")
            reader.join(timeout=15)
            if reader.is_alive():
                errors.append("Packet writer did not terminate")
            output.flush()
            os.fsync(output.fileno())
        if errors:
            raise RuntimeError("; ".join(errors))
        if proc.returncode not in (0, -signal.SIGINT, 128 + signal.SIGINT, 130):
            raise RuntimeError("tcpdump exited before a valid capture was finished")
        if not temp.is_file() or not 24 < temp.stat().st_size <= max_bytes:
            raise RuntimeError("Capture is empty or exceeded the bounded size")
        # Only a *closed* PCAP becomes visible to the inference worker.
        os.replace(temp, ready)
        return ready
    finally:
        if proc is not None and proc.poll() is None:
            try:
                os.killpg(proc.pid, signal.SIGKILL)
                proc.wait(timeout=5)
            except (OSError, subprocess.TimeoutExpired):
                pass
        if temp.exists():
            temp.unlink()



class SensorHeartbeat:
    """Reports genuine local capture-worker liveness, never model evidence."""

    def __init__(self, publish_url, token, model_sha256, capture_seconds):
        endpoint = validate_endpoint(publish_url)
        self._endpoint = endpoint
        self._token = token
        self._model = model_sha256
        self._duration = capture_seconds
        self._state = "capturing"
        self._lock = threading.Lock()
        self._stop = threading.Event()
        self._worker = None

    def set_state(self, state):
        if state not in ("capturing", "processing"):
            raise ValueError("Invalid sensor process heartbeat state")
        with self._lock:
            self._state = state

    def _send(self):
        with self._lock:
            current = self._state
        payload = json.dumps({
            "schema": "krishna-sensor-heartbeat-v1",
            "kind": "heartbeat",
            "state": current,
            "capture_seconds": self._duration,
            "model_sha256": self._model,
        }, separators=(",", ":")).encode("utf-8")
        connector = (http.client.HTTPSConnection if self._endpoint.scheme == "https"
                     else http.client.HTTPConnection)
        conn = connector(self._endpoint.hostname, self._endpoint.port, timeout=8)
        try:
            conn.request(
                "POST", "/api/sensor/heartbeat", body=payload, headers={
                    "Authorization": "Bearer " + self._token,
                    "Content-Type": "application/json",
                    "Accept": "application/json",
                }
            )
            response = conn.getresponse()
            response.read(2048)
            if response.status != 202:
                raise RuntimeError("Server did not accept sensor heartbeat")
        finally:
            conn.close()

    def start(self):
        if self._worker is not None:
            return
        def worker():
            while not self._stop.is_set():
                try:
                    self._send()
                except (OSError, RuntimeError, ValueError) as exc:
                    # Network outage never becomes fabricated inference evidence.
                    print(json.dumps({"event": "sensor_heartbeat_unavailable",
                                      "reason": type(exc).__name__}), flush=True)
                if self._stop.wait(30):
                    break
        self._worker = threading.Thread(target=worker, daemon=True)
        self._worker.start()

    def stop(self):
        self._stop.set()
        if self._worker:
            self._worker.join(timeout=10)


def run(args):
    if not args.authorized:
        raise ValueError("--authorized required: capture only interfaces you own/control")
    if not args.interface:
        raise ValueError("--interface required: do not guess a network to monitor")
    validate_endpoint(args.publish_url)
    inbox = Path(args.inbox).expanduser()
    if inbox.is_symlink():
        raise ValueError("Inbox symlink not allowed")
    inbox.mkdir(parents=True, exist_ok=True, mode=0o700)
    token = _ensure_token(args.token_file)
    database = Path(args.database).expanduser()
    database.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    agent = ShadowAgent(args.artifacts, database)
    try:
        duration = required_capture_seconds(agent.service.meta)
        print(json.dumps({
            "sensor": "packet_shadow_v1",
            "interface": args.interface,
            "checkpoint": str(args.artifacts),
            "window_seconds": agent.service.meta["window_seconds"],
            "required_history_seconds": agent.service.meta["history"] * agent.service.meta["window_seconds"],
            "capture_seconds": duration,
            "forecast_horizons_seconds": [
                (i + 1) * agent.service.meta["window_seconds"] for i in range(4)
            ],
            "mode": "SHADOW_ONLY",
            "automatic_containment": False,
            "remote_raw_packets": False,
        }), flush=True)
        # Obtain operator OS permission before reporting a running sensor.
        if not args.no_sudo:
            subprocess.run(["sudo", "-v"], check=True)
        heartbeat = SensorHeartbeat(args.publish_url, token, agent.service.model_hash, duration)
        heartbeat.start()
        try:
            while True:
                heartbeat.set_state("capturing")
                capture = _capture_stream(
                    args.interface, inbox, duration, use_sudo=not args.no_sudo
                )
                heartbeat.set_state("processing")
                result = agent.process(capture)
                status = result.get("status", "unknown")
                print(json.dumps({
                    "event": "real_capture_processed",
                    "status": status,
                    "reason": result.get("reason") if status != "forecast" else None,
                    "risk_support": result.get("runtime_support", {}).get("supported"),
                }), flush=True)
                if status == "forecast":
                    deliver_pending(agent, args.publish_url, token)
                    row = agent.db.execute(
                        "SELECT delivered_at FROM live_deliveries WHERE capture_sha256=? AND model_sha256=?",
                        (result["capture_sha256"], result["model_sha256"]),
                    ).fetchone()
                    if row:
                        print(json.dumps({
                            "event": "render_persisted",
                            "source": "genuine_closed_pcap",
                            "mode": "SHADOW_ONLY"
                        }), flush=True)
                        # Remove sensitive raw data only AFTER DB acceptance.
                        # Use --keep-pcaps for local audit retention.
                        if not args.keep_pcaps:
                            capture.unlink()
                    else:
                        print(json.dumps({"event": "delivery_pending_retry"}), flush=True)
                # No synthetic or recorded fallback is ever substituted.
                deliver_pending(agent, args.publish_url, token)
                if args.once:
                    break
        finally:
            heartbeat.stop()
    finally:
        agent.db.close()

def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--interface", required=True, help="Your explicitly authorized interface, e.g. en0")
    p.add_argument("--authorized", action="store_true")
    p.add_argument("--artifacts", default=DEFAULT_ARTIFACTS)
    p.add_argument("--inbox", default="garuda_v3/runtime/live-inbox")
    p.add_argument("--database", default="garuda_v3/runtime/live-sensor.sqlite")
    p.add_argument("--publish-url", default=DEFAULT_ENDPOINT)
    p.add_argument("--token-file", default="garuda_v3/runtime/live-sensor.key")
    p.add_argument("--keep-pcaps", action="store_true", help="Retain sensitive raw captures locally for review")
    p.add_argument("--no-sudo", action="store_true", help="Only if your OS already grants packet-capture privileges")
    p.add_argument("--once", action="store_true", help="Collect and publish one completed capture then exit")
    args = p.parse_args()
    try:
        run(args)
    except KeyboardInterrupt:
        print("Sensor stopped by operator", flush=True)
    except (OSError, ValueError, RuntimeError, subprocess.CalledProcessError) as exc:
        p.exit(1, "Sensor withheld: " + str(exc) + "\n")


if __name__ == "__main__":
    main()
