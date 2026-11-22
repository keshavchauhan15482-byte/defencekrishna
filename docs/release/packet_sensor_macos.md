# Real network sensor — macOS activation

**Status:** Vercel + Render + PostgreSQL are already deployed. This adds a real, private packet-trained Garuda collector. Cloud app access cannot capture packets from a user's Mac without OS permissions. This one local command is unavoidable.

## One local command, after cloning the repository

Run in macOS Terminal on your **own/authorized network**:

~~~bash
git clone https://github.com/keshavchauhan15482-byte/defencekrishna.git
cd defencekrishna
bash scripts/start-garuda-sensor-macos.sh
~~~

If you already have the repository, run `git pull --ff-only` instead of cloning. The script suggests this Mac's default interface from `route -n get default`, verifies it exists, and **requires you to type `AUTHORIZED`** before any capture starts. To choose a different interface explicitly, pass its name (for example `en0`); only inspect networks you own or have explicit permission to monitor. Python 3.12+ and macOS's built-in tcpdump are required. The script creates its own environment and installs pinned NumPy; it does not modify training data.

The local shell first asks you to confirm lawful ownership/authorization; there is no silent or remote packet capture. The first time, the Python sensor privately asks for Render `GARUDA_LIVE_SENSOR_TOKEN`. Obtain it in the **krishna-shadow-telemetry** Render service Environment Settings; do not use `RENDER_VIEWER_TOKEN` or `RENDER_ACTIVITY_TOKEN`. Do NOT share/paste credentials in chat or GitHub. This token is stored only in an ignored private local file with file mode 0600. The Mac will ask for an OS `sudo` permission to capture packets. Garuda inference itself runs as your normal user.

To run one capture then stop, instead use:

~~~bash
bash scripts/start-garuda-sensor-macos.sh en0 --once
~~~

Then run without `--once` for repeated sessions. Press Ctrl+C to stop.

## What is actually running

The trained checkpoint compatible with packet features is `garuda_v3/artifacts/calibrated_host_v6`, using **8 × 60-second observed graphs**. The older `residual_run` trained on CSV completed flows with a 10-second contract: **it cannot be used for live PCAP packet features**. The runner checks the checkpoint before capture.

Each bounded **600-second** real capture:
- Passes through the already-trained Garuda GraphSAGE + LSTM risk model. It forecasts future malicious-flow probability at **+60, +120, +180 and +240 seconds**, not +10/20/30/40s. The cloud endpoint now validates either complete 10s or complete 60s horizon sequences, never a mixed one.
- Is NOT labelled as a verified network intrusion, attacker identity, successful compromise or automatic block. Unsupported-domain risk forecasts remain advisory and response actions stay disabled.
- Sends only SHA-256 capture/model provenance, cutoff time, support status, and the four advisory risk probabilities via HTTPS to Render. No raw packet, IP, cookie or packet payload is uploaded.
- Writes accepted output to the separate Render PostgreSQL `krishna_live_forecasts` table. A confirmed storage acknowledgment is required before the local raw PCAP is deleted by default. Use the advanced `--keep-pcaps` Python option for authorized local packet-retention with a privacy policy.
- Sends an independent authenticated heartbeat approximately every 30 seconds while the local capture process runs. The website displays **sensor capturing** while it waits for the first complete window; **the heartbeat is not a model forecast**. Sensor liveness is persisted to `krishna_sensor_heartbeat`.

Separate data lanes stay unchanged: original immutable training data + model checkpoint; newly collected Garuda forecast data; anonymous website page-request counters `krishna_site_activity_events`. No retraining or weight changes occur automatically.

## If you downloaded the ZIP (folder `defencekrishna-main`)

ZIP downloads do **not** contain a `.git` directory, so `git pull` will not work in this folder. After the fix lands on `main`, use these two commands from inside your existing `defencekrishna-main` folder to update only the sensor runner and its macOS launcher, **without deleting local secret files or training data**:

~~~bash
curl -fLsS --output garuda_v3/sensor_runner.py https://raw.githubusercontent.com/keshavchauhan15482-byte/defencekrishna/main/garuda_v3/sensor_runner.py
curl -fLsS --output scripts/start-garuda-sensor-macos.sh https://raw.githubusercontent.com/keshavchauhan15482-byte/defencekrishna/main/scripts/start-garuda-sensor-macos.sh
bash scripts/start-garuda-sensor-macos.sh
~~~

The fixed sensor checks Render's sensor-token authorization **before** requesting privileged packet capture. If the saved token has the wrong value, the process exits with HTTP 401 and no capture starts. Never paste token values into GitHub, URLs, or ChatGPT.

The Mac's `sudo tcpdump -i en0 -c 3 -nn` permission test captures 3 packets and is not an AI inference test. The packet-trained model's parser currently supports **IPv4 only**; the fixed runner captures IPv4 (`ip` BPF) rather than storing unrelated IPv6 frames. Genuine IPv4 traffic over eight contiguous 60-second windows is still required for a valid forecast. If your own Mac/network currently runs IPv6-only traffic, the runner may withhold the forecast; it does not fabricate detections.

## Important limits

**This is a 10-minute near-live closed-capture prototype, not 10-second streaming or inline prevention.** Public Vercel and Render cloud access does not grant remote packet capture on a user Mac. It only monitors the explicitly authorized interface you choose. Input can be withheld when it lacks eight contiguous packet windows, exceeds 256 MiB/64 host nodes, has unsupported link-layer or IPv6 traffic, or falls outside model support. Unsupported results do not become zero risk. You can check the local log for `real_capture_processed`, `sensor_delivery_accepted`, or `delivery_pending_retry`.

macOS `sudo` may need renewed authorization on subsequent 600s captures; keep the Terminal session open. This does not install a covert daemon or auto-start network monitoring at login. For an unattended production sensor, a reviewed OS-level agent and approved security/persistence design is needed. Render's free PostgreSQL expires **22 December 2026** without an upgrade/migration; backups and retention are not guaranteed forever.

## Verification

~~~bash
python -m unittest garuda_v3.tests.test_sensor_runner -v
python -m unittest garuda_v3.tests.test_live_feed_ingestion -v
python -m unittest discover -s tests -p 'test_postgres_store.py' -v
node --test tests/site_live_routes.test.mjs tests/test_vercel_render_deploy.mjs
~~~

These tests verify checkpoint compatibility and data contracts, not capture success on your actual Mac. End-to-end activation is proven only by an authorized local capture and the resulting accepted PostgreSQL forecast record.
