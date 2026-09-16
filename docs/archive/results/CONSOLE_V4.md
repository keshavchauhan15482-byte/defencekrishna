# Krishna Defence Command Console 4

## Start the offline console

From the project folder, install the dependencies described in README.md, then run:

```bash
python3 -m garuda_v3.server
```

Open http://127.0.0.1:8090. Use a local viewer or operator token from `garuda_v3/runtime/access.json`. Connect, then select **Explore recorded traffic** or **Run alert replay**. Tokens remain in tab memory. The replay is recorded dataset telemetry, not live network monitoring.

The redesigned console includes an interactive perspective-projected 3D graph built from observed adjacency, orbit/zoom controls, future-risk timeline, feature attribution, provenance, model comparisons, four defence layers, policy controls, an event ledger and reviewed snapshot memory. It is fully offline, responsive, and supports reduced motion. No cloud fonts or scripts are required.

## What the four layers currently do

| Layer | Implemented behavior | Scope |
|---|---|---|
| Garuda | Trained GraphSAGE–LSTM autoregressive forecast emits an audited signal | Future malicious-flow risk; not verified pre-compromise prediction |
| Krishna | Unreviewed forecast alerts enter a review queue | An alert is not proof of an unknown or zero-day attack |
| Arjuna | Operator-reviewed exact snapshot fingerprints take the known-match route on replay | Does not learn a generalized exploit signature; legacy proxy WAF remains separate |
| Sudarshana | Publishes HMAC-authenticated, expiring IP policy consumed by the Node proxy | Proxy-level containment; signing is not data encryption or proof of breach prevention |

Operator incident escalation records supplied evidence as an **operator-reported** breach. It does not infer a verified breach. There is no autonomous vulnerability repair, cryptographic data vault or general zero-day detection in this release.

## Optional isolated-lab automatic response

Default operation is review-only. For an isolated lab, configure both processes with the same fresh `GARUDA_POLICY_KEY` (at least 32 characters), policy file and operator token. Set the console's `GARUDA_ENFORCE=1`, `GARUDA_LAB_AUTOMATION=1` and an explicit `GARUDA_ALLOWED_CIDRS`, for example `198.51.100.0/24` for simulated documentation addresses. Configure the proxy's `GARUDA_POLICY_FILE` to the absolute `garuda_v3/runtime/policy.json` path. Never ship runtime credentials.

Connect as operator, enter a scoped lab IP and a 10–60 second policy TTL, and choose **Arm lab response**. Authorization expires after two minutes in the UI. An alert forecast can now publish a policy for that preselected IP. The service graph does not identify this IP as an attacker: target binding is deliberately supplied by the operator. Policy publication is shown as pending proxy confirmation. Revoke removes an individual policy; emergency revoke disarms automation and revokes all v3 policies. Disarm alone retains existing policy TTLs.

Unknown-to-known demo: run alert replay, inspect the evidence, record a descriptive attack/review type and an evidence reference, approve the snapshot, then replay it. The route changes from Krishna to Arjuna. A different snapshot does not inherit the approval.

## Verification and remaining gates

On 2026-09-12, all **36 Python regression tests passed**, including access control on response actions, disabled-default behavior, CIDR/TTL checks, expiry, reviewed fingerprint matching, audit integrity and a real model → policy → local Node proxy integration test. That test observes HTTP 200 before forecasting, 403 for the armed target after forecasting, 200 for an unaffected IP, and 200 again after revocation. The payload is a real stored held-out graph bound to a simulated lab source IP; the HTTP request itself did not generate the forecast.

Run the suite from the project root:

```bash
OPENBLAS_NUM_THREADS=1 python3 -m unittest discover -s garuda_v3/tests -v
node --check garuda_v3/ui/app.js
```

Forecast/model quality has not improved merely because the console and response wiring changed. Original clean-history and unseen-family failures remain in the model evidence documents. Production release still needs live telemetry attribution, independently validated warning lead time, false-positive controls, durable operations and deployment security validation.

Browser validation: headless Chromium, 1440×1000 desktop and 390×844 mobile. Connected with operator role, ran real alert replay (91.8% peak), approved a reviewed snapshot and verified Arjuna routing on replay. No JavaScript page errors and no mobile horizontal overflow were observed. Screenshots are in `console_preview/`.
