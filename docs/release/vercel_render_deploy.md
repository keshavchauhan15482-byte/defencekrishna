# Vercel frontend + Render shadow telemetry backend

## Deployment status

This repository contains a **deployable, tested configuration**. Importing a
GitHub repository alone does not create or publish accounts/projects on Vercel
and Render. Until both services and a real owned sensor are connected,
the frontend shows **WAITING/OFFLINE**, never fake live forecasts.

This first hosting edition is **near-live and shadow-only**. It does NOT serve
public model inference, packet inspection, autonomous blocking, or a public
Attack Lab. The full Garuda prediction engine stays with the authorized
packet-capture sensor. Only validated forecast metadata is transmitted.

## Architecture

~~~text
OWN SENSOR / PRIVATE PYTHON
  Real 90+ second completed PCAP
    -> existing ShadowAgent + pinned Garuda risk model
    -> live_publisher with local durable SQLite outbox
    -> HTTPS POST https://<your-render-service>.onrender.com/api/live/ingest
RENDER PYTHON
  Authenticated metadata-only relay backed by separate PostgreSQL history
    -> GET /api/live/events protected by independent viewer token
VERCEL
  /api/live-events serverless function (stores viewer token server-side)
    -> same-origin /bridge/live/events?after=N
    -> original premium Krishna Defence console
~~~

No browser sensor credentials, raw packet bytes, attacker IPs or model
checkpoints are uploaded. The token gate is separate from all WAF/policy APIs.
Do NOT change the private `garuda_v3.integrated_server` listener from
127.0.0.1 to 0.0.0.0. The Render relay is a different bounded service.

## 1. Deploy Render relay (first)

1. First confirm the existing Render PostgreSQL database named `krishna-live-telemetry` is available in the same workspace and Singapore region. Do **not** create a second database.
2. In Render create a **Blueprint** from
   `keshavchauhan15482-byte/defencekrishna` on `main` using root
   `render.yaml`. This creates the Python web service
   `krishna-shadow-telemetry`. The `/health` endpoint should respond with
   `{"status":"ready","service":"advisory_telemetry_relay"}`.
3. Set two **different**, randomly generated 40+ character secrets when
   prompted by Render Blueprint:
   - `GARUDA_LIVE_SENSOR_TOKEN` = independent device ingest secret
   - `RENDER_VIEWER_TOKEN` = server-to-server Vercel read secret
4. Store both only in the platform's secret manager or a private `chmod 600`
   file on your own computer. Never commit, paste into this chat, or put in
   browser JavaScript/screenshots. You can generate each locally using
   `python -c "import secrets; print(secrets.token_urlsafe(48))"`.
5. Note the **actual HTTPS Render service URL** displayed by Render. Do not
   assume its name in advance.

Health checking does not establish live data: before a sensor publishes, the
feed is `waiting`.

The Render relay now REQUIRES `DATABASE_URL` from the **separate** existing
`krishna-live-telemetry` PostgreSQL resource. It creates only its own
`krishna_live_forecasts` table and never edits trained model weights, recorded
datasets, training labels, or inference checkpoints. Forecast metadata
persists across web-service restarts. The web API reads at most 128 rows per
poll; the database retains prior rows instead of silently truncating history.
Raw PCAP files remain on the owned sensor and are not uploaded to PostgreSQL.

The currently provisioned **free** Render PostgreSQL instance is scheduled
to expire on **22 December 2026**. Free database persistence is therefore NOT
indefinite. Before expiry, migrate/upgrade to long-lived storage and establish
backup, retention, user access and privacy controls. If Render's free web
service sleeps, the dashboard shows stale/offline until it wakes; the retained
database history remains separate. Production always-on operation needs
adequate hosting, observability and independent review.

## 2. Deploy Vercel frontend

1. From Vercel, **Import Git Repository**
   `keshavchauhan15482-byte/defencekrishna`, branch `main`.
2. Root Directory: repository root `./`. Framework preset: **Other**.
   The committed root `vercel.json` builds the EXISTING `console.html` into
   `public/`, injects the approved V131/V132 style/JS assets and serves it
   at `/`. Don't select `garuda_v3` as Vercel root.
3. Configure Vercel **server-side Environment Variables**:
   - `RENDER_BACKEND_URL`: actual HTTPS URL of the Render relay, with no
     path (example pattern `https://YOUR-SERVICE.onrender.com`)
   - `RENDER_VIEWER_TOKEN`: exactly the reader token you configured in
     Render in step 1. Do NOT prefix it with "Bearer".
4. Deploy and open the NEW Vercel `*.vercel.app` URL. The old
   `*.chatgpt.site` URL is a separate previous deployment, and won't switch.
5. Initially the status should show **WAITING FOR SENSOR**, not claim any
   attack was detected. If Vercel env or Render are missing, you should see
   an explicit **OFFLINE** state.

**Trust boundary:** the Vercel function reads the viewer token server-side and
returns only score/timestamp/trajectory metadata. No Render token is
present in static HTML. The Render ingest endpoint requires a different
secret, and is never proxied by Vercel.

## 3. Start a genuinely owned-network Garuda sensor

On the PC or authorized lab machine with full compatible model artifacts,
follow `docs/release/near_live_shadow_feed.md` and create a private sensor
token file whose contents equal `GARUDA_LIVE_SENSOR_TOKEN` on Render. Example:

~~~sh
mkdir -p garuda_v3/runtime/live-inbox
umask 077
python - <<'PY'
from pathlib import Path
import getpass
path = Path("garuda_v3/runtime/live-sensor.key")
path.write_text(getpass.getpass("Enter Render GARUDA_LIVE_SENSOR_TOKEN: "))
path.chmod(0o600)
PY
python -m garuda_v3.live_publisher \
  --artifacts garuda_v3/artifacts/residual_run \
  --inbox garuda_v3/runtime/live-inbox \
  --database garuda_v3/runtime/live-shadow.sqlite \
  --publish-url https://YOUR-RENDER-SERVICE.onrender.com/api/live/ingest \
  --token-file garuda_v3/runtime/live-sensor.key
~~~

Start the capture worker on an interface that you **own or have explicit
permission to monitor**. Requires installed `tcpdump` and capture permissions:

~~~sh
python -m garuda_v3.live_capture \
  --interface YOUR_OWN_INTERFACE \
  --inbox garuda_v3/runtime/live-inbox \
  --capture-seconds 90 --repeat --authorized
~~~

Every successfully completed 90s+ PCAP may produce a new advisory forecast,
provided it has enough contiguous graph windows and matches the runtime model
contract. Fresh capture must have current packet timestamps; old recordings are
rejected as near-live. No new captures for >120 seconds => `STALE`.
The dashboard polls every 2.6 seconds for *new events*; this is **not** a
2.6-second packet interception or a verified pre-compromise warning.

## 4. Validate end-to-end

- Render `/health` => HTTP 200 (only confirms relay process).
- Vercel homepage => original premium Krishna UI, shows either WAITING/OFFLINE.
- Wrong ingest token => HTTP 401.
- Invalid sensor event or synthetic historical timestamp => HTTP 422.
- Authentic supported PCAP processed in private sensor => publisher prints
  `sensor_delivery_accepted`; Render replies 202, saves an independent PostgreSQL row; Vercel dashboard gets **one**
  new score and graph point per distinct accepted capture.
- Valid repeated delivery does not generate another graph point.
- No new sample => STALE. A Render restart preserves PostgreSQL history; the 128-row API page limit does not delete stored records.
- Every stored record includes immutable capture hash, checkpoint hash, timestamps and four prediction horizons; it is **not** used for automatic model retraining.
- Attacks blocked, zero-day detections and automatic containment remain **not
  established** by this telemetry transport. Remote Upload / Attack Lab controls
  are deliberately disabled on the Vercel static deployment rather than
  pretending a remote model exists.

## Deployment tests

~~~sh
node --test tests/test_vercel_render_deploy.mjs
python -m unittest discover -s tests -p 'test_render_live_relay.py' -v
~~~

These run in `.github/workflows/krishna-integration-ci.yml` in addition
to existing Python/Node regression checks. The production Vercel/Render
deployments need their own smoke checks after account connection.

## Next development gate

If a full cloud-hosted AI inference endpoint is required, create a **separate**
authenticated, rate-limited research service, benchmark checkpoint RAM/startup
and capture support, isolate each tenant, and keep autonomous policy endpoints
disabled until independently reviewed. The existing localhost-only integrated
runtime is **not** ready to bind directly to the public internet.
