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

## 3. Start real packet sensor from your authorized Mac

The cloud services cannot capture packets from your Mac. Follow the new **one-command macOS activation** at [packet_sensor_macos.md](packet_sensor_macos.md) or use the explicit command below from a Git checkout:

~~~bash
bash scripts/start-garuda-sensor-macos.sh en0
~~~

The runner uses the packet-trained `garuda_v3/artifacts/calibrated_host_v6` checkpoint, **not the incompatible 10s flow-trained `residual_run` checkpoint**. It takes up to 600 seconds of actual authorized packet capture, sends an independent authenticated heartbeat every 30 seconds to confirm sensor liveness, then runs the pinned 60s/120s/180s/240s advisory forecast and persists it into `krishna_live_forecasts` only after Render confirms acceptance. Packet payloads stay local. No cloud automatic blocking or retraining is enabled.

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


## Automatically saved website activity — separated from trained AI

The deployed Vercel console records a single **anonymous real page-load HTTP request** per page load via `POST /api/site-activity`. The Vercel function generates a random transport UUID server-side and forwards only `kind=page_load` to Render's `/api/site-activity/ingest` using a third, independent secret `RENDER_ACTIVITY_TOKEN`. Render persists these events in the separate `krishna_site_activity_events` PostgreSQL table and returns last-24-hours and lifetime request counts through the authenticated existing read-only telemetry route. The premium website renders these counts in the **Observed requests** panel. The counter counts actual first-party requests, **not unique people**, detected attacks, blocked threats, packet traffic, nor Garuda AI inferences; these raw anonymous request records are never used to retrain or update the checkpoint.

The original `krishna_live_forecasts` PostgreSQL table remains **dedicated to actual model outputs from compatible completed PCAP/CSV network captures**. Data must originate from an owned sensor using the pinned model and separate `GARUDA_LIVE_SENSOR_TOKEN`. The website activity counter does not enter that table and cannot generate fake model forecasts. The Vercel-side secret and Render-side secret must match and must never appear in browser source or GitHub files. Check the same-origin POST is 202, then GET `/bridge/live/events?after=0` includes `site_activity`. Before any genuine capture, `events=[]` and `state=waiting` are the correct model status.

This site HTTP telemetry is limited to page-load counts and deliberately does not save IPs, cookies, user agents, referrers, or full URLs. It is not a packet sniffer or SIEM. For real network-level Garuda inference, a compatible authorized capture sensor is still required. The free PostgreSQL database expires on **22 December 2026** unless migrated or upgraded; arrange backup/migration and a longer-term storage plan before then.
