# Near-live owned-traffic shadow feed (prototype)

This is a **working, optional, same-origin near-live feed**, not a real-time inline IPS or a production SaaS. It uses the existing pinned risk checkpoint and completed-capture `ShadowAgent`. It does **not** retrain the model, improve accuracy, assert successful-compromise prediction, or approve Arjuna/Krishna/Sudarshana containment.

The browser no longer silently polls recorded replay to animate the live gauge. Real captures add new graph points only when their inference result arrives. The lab still offers a clearly labelled **manual recorded demo**.

## Data path

```text
Your OWN interface / test network (tcpdump, optional, explicit)
    -> 90+ second completed PCAP (.pcap.ready), kept on sensor
    -> ShadowAgent (pinned compatible risk checkpoint)
    -> live_publisher (4 horizons + hashes only, durable SQLite outbox)
    -> POST /api/live/ingest (independent sensor bearer, <=8 KiB)
    -> in-memory bounded LiveFeed (128 events, no policy capability)
    -> GET /bridge/live/events?after=N (same-origin console)
    -> actual sensor points + provenance, shadow-only status
```

Near-live means **one new advisory result after each complete capture** (e.g. every ~90 seconds, plus processing delay), not continuous 10-second packet classification. The collector polls for closed files every 10 seconds by default. The dashboard polls event metadata every 2.6 seconds; polling faster does not increase inference frequency. Model predictions are future malicious-flow probabilities, not chances of successfully compromising a website.

## Local quickstart (two/three terminals)

Use a disposable test host or an interface you own and are allowed to monitor. Never put the sensor token into JavaScript, screenshots, Git, public logs, or browser local storage.

From the repo root, create an ignored runtime folder and an independent private secret:

```bash
mkdir -p garuda_v3/runtime/live-inbox
umask 077
python - <<'PY'
from pathlib import Path
import secrets
p=Path("garuda_v3/runtime/live-sensor.key")
p.write_text(secrets.token_urlsafe(40), encoding="ascii")
p.chmod(0o600)
PY
```

**Terminal A — backend + actual console (localhost only):**

```bash
export GARUDA_LIVE_SENSOR_TOKEN="$(cat garuda_v3/runtime/live-sensor.key)"
python start_main_console.py
# Open http://127.0.0.1:8090/console.html
```

**Terminal B — capture publisher (same machine for this local test):**

```bash
python -m garuda_v3.live_publisher \
  --artifacts garuda_v3/artifacts/residual_run \
  --inbox garuda_v3/runtime/live-inbox \
  --database garuda_v3/runtime/live-shadow.sqlite \
  --publish-url http://127.0.0.1:8090/api/live/ingest \
  --token-file garuda_v3/runtime/live-sensor.key
```

**Terminal C — optional automatic packet capture on an owned interface:**

```bash
python -m garuda_v3.live_capture \
  --interface YOUR_OWN_INTERFACE \
  --inbox garuda_v3/runtime/live-inbox \
  --capture-seconds 90 --repeat --authorized
```

You need `tcpdump` installed and OS capture permissions (root or an appropriately delegated capture capability). Do not run the web server as root or grant browser users any packet-capture control. The capture worker uses a fixed `tcpdump` command with no shell or remote target. It closes a capture before publishing the `.pcap.ready` file. Both the publisher and capture worker can be restarted independently.

A compatible capture must have enough noncontiguous-free 10-second windows for the **8-window / 80-second** model history. Insufficient or incompatible capture traffic is withheld, not turned into a fake zero score. Endpoints without real supported packet/flow fields may fail the support gate and remain advisory.

## What success looks like

1. With only the backend running, dashboard says `WAITING FOR SENSOR`; the gauge does **not** animate fake prediction samples.
2. A fresh, compatible completed capture is processed locally. The publisher prints `sensor_delivery_accepted` with an event ID.
3. Dashboard changes to `NEAR-LIVE · SHADOW ONLY` and receives the actual timestamp, hash provenance and 10/20/30/40-second model outputs.
4. If no new capture arrives for 120 seconds, `STALE` appears. Old scores remain visibly historical.
5. Old PCAPs older than 300 seconds are not promoted as live. The manual recorded replay is visibly labelled.
6. HTTP `401` is expected for missing/wrong sensor credentials; malformed/old/containment-claiming events receive `422`. No sensor request can publish a containment policy.

The standard attack-lab scenarios are separately labelled **recorded/lab**. Their HTTP 403 test results are not evidence that this new sensor automatically blocked an attacker.

## Security and operations

- The actual Garuda server **still binds to 127.0.0.1**. Do not change it to `0.0.0.0` or expose the raw API/tokens.
- A remote publisher may use only **HTTPS** `/api/live/ingest` behind a separately authenticated, reviewed TLS gateway. Remote `http://` is rejected. The gateway must preserve the internal Host contract and protect all console `/bridge/*` views; the local profile console itself does not provide a customer login.
- `GARUDA_LIVE_SENSOR_TOKEN` is a separate 32–256-character secret, not the viewer/operator token. Pilot-profile ingestion may use this sensor credential but has no API operator rights.
- Request bodies are capped at 8 KiB; event fields, cutoff freshness, SHA-256 and four probability horizons are validated. Incoming event ID is generated server-side.
- No packet contents, client IPs or node names cross the ingest API; the **original PCAPs and SQLite database remain on the sensor**. Protect and delete them under a written retention policy. The capture inbox is NOT automatically pruned.
- The in-memory feed holds at most 128 events and resets on restart. The sensor publisher has a local SQLite delivery ledger and retries failed deliveries until the sample ages out. This is not a durable server event bus or exactly-once delivery guarantee.
- Live mode does not create policies, arm the lab, approve containment, change model weights, or imply verified pre-compromise warning. Deployment, customer network validation, independent security review, alerting and privacy review remain external gates.

## Regression checks

```bash
python -m unittest garuda_v3.tests.test_live_feed_ingestion -v
node --check garuda_v3/ui/console-integrated.js
python -m pytest garuda_v3/tests -q
```

For the next iteration: a rolling/overlapping 10-second window sensor, sensor heartbeat independent of forecasts, authenticated tenant-scoped event storage, backpressure/load tests, and external gateway review. Do not claim those are shipped here.
