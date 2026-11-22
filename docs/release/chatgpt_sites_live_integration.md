# Existing ChatGPT Sites: integrate Krishna's real-capture feed

**Status: integration kit in the GitHub repo, NOT installed on the published Site.**
Current user Site: `https://krishna-defence-console-keshav.keshavchauhan1254.chatgpt.site/`.
The GitHub repo and ChatGPT Sites are separate deployment surfaces. This guide
does not claim that the production Site has been edited or deployed.

## Architecture with zero public Python ports

```text
Owned lab / server
  90s+ closed capture
      -> garuda_v3.live_publisher (existing pinned Garuda risk checkpoint)
      -> HTTPS POST /api/live/ingest on ChatGPT Site
      -> Web API adapter validates hashes, timestamps, 10/20/30/40s scores
      -> Site D1 table krishna_live_events (max 128 retained samples)
      -> same-origin GET /bridge/live/events?after=N
      -> the existing premium UI displays real event points only on arrival
```

Only SHA-256 capture and checkpoint hashes, timestamps, probability horizons
and support flags are submitted. **No raw packet, IP address, arbitrary request
body, permission to block, or secret appears in the viewer's browser.** Site
handlers return the sanitized read-only projection (no hashes). The Python
model stays on a private owned sensor host. The Site is not a packet sniffer.

## Integrate in the *existing* Site project

1. Open the existing Site through **ChatGPT > Sites > Edit** (or its owner "Edit site" control).
   Use the original project, **not** "Create a new Site"; preserve the same public URL and
   existing hero, brand, architecture, forecasts, Attack Lab and judge-facing evidence.
2. Bring into that Site's actual server-side source:
   - `site_integration/chatgpt_sites/live_routes.mjs`
   - `site_integration/chatgpt_sites/schema.sql`
   - `site_integration/chatgpt_sites/live_client.mjs` (browser-side client)
   from GitHub main, and adapt imports to the Site's actual framework/router.
   The generic Web Fetch adapter exports `handleKrishnaLiveRequest(request, env)`.
   In the Site's existing fetch/router entrypoint, **before its fallback routes**:
   ```js
   const maybeLiveResponse = await handleKrishnaLiveRequest(request, env);
   if (maybeLiveResponse) return maybeLiveResponse;
   // otherwise continue the EXISTING site's request handler
   ```
   Do not overwrite the Site's existing app/router or other database schema.
3. Provision/confirm Site's D1 binding named `DB` (adjust the adapter binding
   consistently if the project uses another name). Apply only the additive
   `schema.sql` migration in the Site's standard migration workflow.
4. Set `GARUDA_LIVE_SENSOR_TOKEN` as a secret **in the Site Settings**, not in
   client JavaScript/GitHub, and set exactly the same secret in the local
   publisher's private `--token-file`. This secret must be independent of
   any viewer, operator or Sites auth credential.
5. If Site sign-in restricts machine requests, use the Sites editor to generate
   an **SIWC bypass token** for the sensor. Store it ONLY in another private
   file on the publisher machine; supply `--sites-bypass-file`. The publisher
   will send `OAI-Sites-Authorization: Bearer ...` for Sites' sign-in gate, and
   the independent ordinary `Authorization: Bearer ...` header for the
   app-level sensor validation. A bypass token alone must grant no sensor access.
   On a publicly accessible Site that has no sign-in gate for this route, omit it.
6. Rewire the **existing hosted UI**:
   - Stop any automatic `/replay` or `/bridge/replay` polling presented as LIVE.
   - Poll same-origin `/bridge/live/events?after=LAST_ID` every 2.6 seconds,
     starting at 0.
   - Update score/trajectory/alerts only for newly returned `events`.
   - Display `WAITING FOR SENSOR`, `NEAR-LIVE · SHADOW ONLY`,
     `STALE` and `OFFLINE` from the actual API state.
   - Keep Replay and Attack Lab as manually initiated, **clearly labelled**
     recorded/local scenarios. Do not count those as real network blocks.
   - Keep the existing modular Garuda / Arjuna / Krishna / Sudarshana layout.
     Disable all forecast-triggered autonomous containment on this route.
7. Preview under the actual Site access rules, confirm D1 migration and
   sensor-token rejection tests, save a Site version, and deploy that reviewed
   version through ChatGPT Sites. Publishing is a separate explicit step.
   **Neither GitHub merge nor this integration kit deploys the Site.**

## Starting the sensor on an authorized network

Create the local private token exactly as in
`docs/release/near_live_shadow_feed.md`, then start the existing inference
publisher. Example from the checkout of GitHub main:

```sh
python -m garuda_v3.live_publisher \
  --artifacts garuda_v3/artifacts/residual_run \
  --inbox garuda_v3/runtime/live-inbox \
  --database garuda_v3/runtime/live-shadow.sqlite \
  --publish-url https://krishna-defence-console-keshav.keshavchauhan1254.chatgpt.site/api/live/ingest \
  --token-file garuda_v3/runtime/live-sensor.key
```

If a sign-in bypass is required, add
`--sites-bypass-file /private/path/sites-bypass.key`. Never paste either
secret into the chat, URL, GitHub or screenshots.

Optionally run the capture worker, with `--authorized`, on your own interface:

```sh
python -m garuda_v3.live_capture \
  --interface YOUR_OWN_INTERFACE \
  --inbox garuda_v3/runtime/live-inbox \
  --capture-seconds 90 --repeat --authorized
```

Requires a supported OS sensor, installed tcpdump and explicit packet-capture
permission. Fresh, complete, compatible PCAPs are necessary; the 90s capture
duration plus parsing and publishing delay makes this **near-live** rather than
a 10-second inline interception engine.

## Deployment validation contract

- No sensor + no data -> `WAITING`, **not fake 90% risk**.
- Wrong token -> `401`; malformed or old capture -> `422`.
- Fresh supported capture -> `202` accepted, new site event ID and one
  new real event in dashboard; same hash pair retries do not create a new row.
- Five successive captures -> five independent observed datapoints, not
  interpolated fabricated values. No new captures for 120s -> `STALE`.
- GET feed exposes only sensor risk metadata, not hashes/IPs/payloads.
- No `/api/policy` route is created; all sensor events remain
  `SHADOW_ONLY`, `automatic_containment:false`.
- The frontend may be public or private depending on Site settings; a
  **public Site exposes the displayed score data to all visitors**. Keep it
  private or use approved non-sensitive demo data if operational security
  results should not be public.

## Operational limitations

The D1 adapter stores only the latest 128 accepted events and attempts best-effort
30-day deletion on each new ingest. Deletion after a long idle period is **not
guaranteed** without a scheduled cleanup or approved retention process. Use
Site-level scheduled cleanup for strict legal retention obligations.

This code has a request-size limit, validation and token authentication, but
is not independently security-certified. Run its Node tests and review Site
auth, migrations, replay handling, CSP, Site visitor identity and data access
before publishing. Never pass source packet content or the raw Python model
server through this Site.

```sh
node --test tests/site_live_routes.test.mjs
python -m unittest garuda_v3.tests.test_live_feed_ingestion -v
```

The *actual ChatGPT Site edit/publish action* requires the original Site project
through its owner/authorized editor workflow. GitHub connectors cannot deploy a
separately hosted ChatGPT Site by pushing commits.
