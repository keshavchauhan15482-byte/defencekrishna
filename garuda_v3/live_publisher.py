"""Ship metadata-only near-live results from completed owned PCAP/CSV captures.

The existing shadow agent performs local inference. This process sends only SHA256
provenance and the four risk horizons to the separate read-only event feed; no
packet contents, host addresses, policy updates or credentials are sent.
"""
from __future__ import annotations

import argparse
import http.client
import json
import os
import stat
import time
from pathlib import Path
from urllib.parse import urlsplit

from .shadow_agent import ShadowAgent


def read_private_token(filename):
    path = Path(filename)
    if path.is_symlink():
        raise ValueError("Token must not be a symlink")
    info = path.stat()
    if not stat.S_ISREG(info.st_mode) or (os.name == "posix" and info.st_mode & 0o077):
        raise ValueError("Token must be a private regular file (chmod 600)")
    token = path.read_text(encoding="ascii").strip()
    if not 32 <= len(token) <= 256 or any(ord(c) < 33 or ord(c) > 126 for c in token):
        raise ValueError("Invalid sensor token")
    return token


def validate_endpoint(url):
    parsed = urlsplit(url)
    if parsed.scheme not in ("http", "https") or not parsed.hostname:
        raise ValueError("HTTPS endpoint required")
    if (parsed.username or parsed.password or parsed.query or parsed.fragment
            or parsed.path != "/api/live/ingest"):
        raise ValueError("Only exact /api/live/ingest endpoint allowed")
    if parsed.scheme == "http" and parsed.hostname not in ("localhost", "127.0.0.1", "::1"):
        raise ValueError("Plain HTTP allowed only on loopback")
    return parsed


def event_from_result(result):
    if result.get("status") != "forecast":
        raise ValueError("Only successful shadow forecasts may be published")
    return {
        "schema": "krishna-live-v1",
        "kind": "forecast",
        "capture_sha256": result["capture_sha256"],
        "model_sha256": result["model_sha256"],
        "cutoff_epoch_seconds": result["cutoff_epoch_seconds"],
        "trajectory": [
            {"horizon_seconds": item["horizon_seconds"],
             "malicious_flow_probability": item["malicious_flow_probability"]}
            for item in result["trajectory"]
        ],
        "alert": result["alert"] is True,
        "supported": result.get("runtime_support", {}).get("supported") is True,
        "automatic_containment": False,
    }


def publish(url, token, record):
    parsed = validate_endpoint(url)
    raw = json.dumps(event_from_result(record), allow_nan=False, separators=(",", ":")).encode()
    if len(raw) > 8192:
        raise ValueError("Event exceeds 8 KiB")
    connector = http.client.HTTPSConnection if parsed.scheme == "https" else http.client.HTTPConnection
    connection = connector(parsed.hostname, parsed.port, timeout=8)
    try:
        connection.request("POST", parsed.path, body=raw, headers={
            "Authorization": "Bearer " + token, "Content-Type": "application/json",
            "Accept": "application/json",
        })
        response = connection.getresponse()
        body = response.read(2048)
        if response.status != 202:
            raise RuntimeError("Sensor endpoint returned HTTP " + str(response.status))
        receipt = json.loads(body)
        if receipt.get("accepted") is not True:
            raise RuntimeError("No sensor acceptance receipt")
        return receipt
    finally:
        connection.close()


def deliver_pending(agent, url, token):
    db = agent.db
    db.execute("""CREATE TABLE IF NOT EXISTS live_deliveries(
        capture_sha256 TEXT, model_sha256 TEXT, delivered_at REAL,
        PRIMARY KEY(capture_sha256, model_sha256))""")
    db.commit()
    rows = db.execute("""SELECT o.capture_sha256, o.model_sha256, o.result
        FROM observations o LEFT JOIN live_deliveries d
          ON o.capture_sha256=d.capture_sha256 AND o.model_sha256=d.model_sha256
        WHERE o.status='forecast' AND d.capture_sha256 IS NULL
        ORDER BY o.created ASC LIMIT 8""").fetchall()
    for capture, model, raw in rows:
        record = json.loads(raw)
        if abs(time.time() - float(record["cutoff_epoch_seconds"])) > 300:
            # Never pretend that a recorded historical PCAP is fresh telemetry.
            print(json.dumps({"event": "historical_capture_skipped", "capture_sha256": capture}), flush=True)
            with db:
                db.execute("INSERT OR IGNORE INTO live_deliveries VALUES (?,?,?)",
                           (capture, model, time.time()))
            continue
        try:
            receipt = publish(url, token, record)
        except (OSError, ValueError, RuntimeError, json.JSONDecodeError) as exc:
            print(json.dumps({"event": "sensor_delivery_failed", "reason": type(exc).__name__}), flush=True)
            break  # Keep the outbox row pending; delivery is not falsely confirmed.
        with db:
            db.execute("INSERT OR IGNORE INTO live_deliveries VALUES (?,?,?)",
                       (capture, model, time.time()))
        print(json.dumps({"event": "sensor_delivery_accepted", "id": receipt["event_id"]}), flush=True)


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--artifacts", required=True)
    p.add_argument("--inbox", required=True, help="Immutable completed .pcap.ready/.csv.ready files")
    p.add_argument("--database", required=True)
    p.add_argument("--publish-url", required=True)
    p.add_argument("--token-file", required=True)
    p.add_argument("--interval", type=int, default=10)
    p.add_argument("--once", action="store_true")
    args = p.parse_args()
    if args.interval < 2:
        p.error("--interval must be at least 2 seconds")
    validate_endpoint(args.publish_url)
    token = read_private_token(args.token_file)
    inbox = Path(args.inbox)
    if not inbox.is_dir():
        p.error("Capture inbox does not exist")
    agent = ShadowAgent(args.artifacts, args.database)
    try:
        while True:
            for path in sorted(inbox.glob("*.ready")):
                try:
                    result = agent.process(path)
                    if result.get("status") != "already_processed":
                        print(json.dumps({"event": "capture_processed",
                                          "status": result.get("status"),
                                          "capture_sha256": result.get("capture_sha256")}), flush=True)
                except (ValueError, OSError, KeyError) as exc:
                    print(json.dumps({"event": "capture_rejected",
                                      "reason": type(exc).__name__}), flush=True)
            deliver_pending(agent, args.publish_url, token)
            if args.once:
                break
            time.sleep(args.interval)
    finally:
        agent.db.close()


if __name__ == "__main__":
    main()
