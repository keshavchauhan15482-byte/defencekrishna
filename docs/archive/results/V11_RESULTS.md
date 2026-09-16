# V11 — Verified local enforcement fixes and timeline readiness

This release fixes concrete protection bugs in the shipped Node proxy and
Sudarshana core. It does not claim a new trained attack-progression model,
pre-compromise warning success, independent holdout accuracy, or 9/10 readiness.
All V10 data, weights and results are preserved.

## Fixed protection defects

1. **Escalation bypass:** HUMAN_ESCALATED lockdowns were omitted by the request
   check, allowing traffic despite a fail-closed escalation message. IP, route,
   session and pattern checks now retain containment for escalated scopes.
2. **Fake two-party signatures:** public hardcoded strings, including duplicate
   signer strings, could satisfy unlock approval. Unlock now verifies two
   distinct configured Ed25519 public keys. Signatures bind signer, scope,
   unique lockdown ID and a short expiry. Invalid, duplicate, expired and
   previous-lock approvals fail. No configured keys means no signed unlock.
3. **Fabricated forecast-to-block endpoint:** the old mitigate route embedded a
   hardcoded 96.3% forecast and success claim. It now returns HTTP 410 with no
   containment action. A synthetic score cannot authorize enforcement.
4. **Policy tamper downgrade:** a bad/unavailable signed policy previously
   cleared an existing policy. The last verified policy is now retained until
   its expiry. A newer valid signed empty policy performs emergency revoke.
   Older issued timestamps and same-timestamp conflicting payloads are rejected.
5. **Ledger gaps:** the first retained block is now checked, retained-chain
   anchoring is tracked and indexes remain monotonic after retention trimming.
   Output describes hash-chain consistency, not mathematical immutability.

The legacy lifecycle example now generates real independent test keypairs.
`unlock-approval.js` signs an approval locally; it does not expose private keys.

## Executed evidence

- **65 Python tests passed**, including holdout reuse rejection and immutable
  reservation-file creation.
- **15 strict Node control checks passed**, including escalation containment,
  distinct-signature enforcement, tampering/replay rejection and ledger checks.
- **12 actual loopback HTTP checks passed** through the shipped proxy against
  a separate protected HTTP server.
- **5 existing source-exposure/demo-provenance checks passed.**

HTTP evidence uses upstream receipt counts, not only the proxy's response label:

| Test | HTTP result | Upstream delivery |
|---|---:|---:|
| Legitimate baseline | 200 | Yes |
| Unauthenticated management | 401 | No |
| Retired fabricated mitigation | 410 | No |
| Signed IP containment | 403 | No |
| Unrelated client during containment | 200 | Yes |
| Spoofed X-Forwarded-For bypass attempt | 403 | No |
| Invalid policy signature | 403 | No |
| Stale signed revoke | 403 | No |
| Fresh signed emergency revoke | 200 | Yes |
| Active short-TTL policy | 403 | No |
| Expired policy | 200 | Yes |
| Known SQL-injection-shaped query | 403 | No |

These are real HTTP requests on loopback, with a harmless receipt-only upstream.
The SQL-shaped query is inspected as text; no exploit is executed. This proves
local known-payload filtering and reviewed policy enforcement. It does **not**
prove Garuda forecast-triggered containment, unknown-attack generalisation,
exfiltration prevention, arbitrary application compatibility or enterprise scale.

Evidence files: `datasets/v11/http_lab_results.json`, `http_lab.log`,
`proxy_lab.log`, `controls.log`, `python_tests.log`, `exposure_tests.log`.

## Timeline audit: why training is still gated

The official dataset page identifies `Attack_info.csv`, extracted from Caldera
reports, as the supplementary attack-step information. On 2026-09-14 the official
download route and its advertised browse link returned a registration form with
"Server error". No invented identity was submitted and no registration was bypassed.

Available Phase 2 provenance candidates are not verified network ground truth.
The Initial Access candidates contain **two rows at one unique timestamp**,
1701469216.029. The first prepared complete graph window starts at 1701469020.
Only **three closed history windows** precede that candidate event. The current
model requires eight. Both candidates consequently have no eligible full history.
The event is a process first-seen candidate, not a confirmed compromise timestamp.

Missing history must not be padded with imagined benign traffic or joined across
capture gaps. Repeating the same single event also does not create independent
incidents. Other candidate stages have not been promoted to supervised labels.

`garuda_v3.v11_readiness` records per-stage candidate counts, unique event times,
context availability, source hashes and reasons training remains disallowed.
It also creates a conservative source-usage registry. `freeze_holdout` rejects
known/reused source hashes and refuses to overwrite a reservation. The registry
is an audit aid, not independent proof of complete historical usage.

## Required evidence to unblock the remaining model work

Provide the original CICAPT `Attack_info.csv` / Caldera execution reports and
host/PID/clock mapping for the existing captures. For pre-compromise evaluation,
we also need evidence distinguishing attempted action from successful compromise,
with sufficient observed prehistory. Complete reviewed stage-negative coverage
is required; absence of a candidate event does not establish a negative label.

If the original capture cannot provide enough prehistory or independent repeated
incidents, collect a controlled, isolated capture with logged incident outcomes
and reserve complete runs before training. Do not claim that another epoch or
larger model fixes missing ground truth. Independent holdout FPR/recall and stage
performance remain unestablished by this release.

## Operator setup and reproducibility

Run from the project root:

```bash
npm run test:v11
python -m unittest discover -s garuda_v3/tests
python tests/test_proxy_exposure.py
python -m garuda_v3.v11_readiness
```

The HTTP harness copies the proxy into a temporary directory, generates temporary
signing credentials, binds only loopback interfaces, and shuts down its processes.
It does not modify a customer deployment or publish the hosted console.

For actual operator unlock configuration, `GARUDA_UNLOCK_KEYS_FILE` points to a
JSON mapping of distinct signer IDs to Ed25519 PEM public keys. Each operator
keeps their own private key and signs independently:

```bash
node unlock-approval.js PRIVATE_KEY_PEM SIGNER SCOPE_KEY LOCKDOWN_ID
```

Collect two resulting approval objects into `signatures` in the existing
operator-authenticated `/__sentinel/unlock` POST body, alongside `scopeType` and
`scopeValue`. Scope and lockdown ID must match the active lock; approvals expire
within two minutes by default, with a maximum accepted five-minute validity.
The utility is for trusted operators, not a public key-management service.

## Operational limits still open

- Signing authenticates policies/approvals; it does not encrypt application data.
- Policy replay watermark, Sudarshana lockdowns and ledger anchors are in memory.
  Durable recovery/replay protection across process restarts and independent
  ledger anchoring still require integration work.
- Numeric-confidence autonomous recovery and newly learned rules have not been
  independently validated against benign traffic and unseen attacks.
- Key custody/rotation, customer telemetry, sustained load tests and independent
  security review remain pending. Manual public-IP exposure is not approved by
  these local tests.
- V10 state-MSE results are unchanged: 14.23% LSTM and 10.43% GNN reductions on
  the previously evaluated CICAPT phase. They are not attack-detection scores.

## Sources

- [CICAPT-IIoT2024 publisher: network, provenance and supplementary attack information](https://www.unb.ca/cic/datasets/iiot-dataset-2024.html)
- [Official download route checked](https://cicresearch.ca/IOTDataset/CICAPT-IIoT-Dataset/)
