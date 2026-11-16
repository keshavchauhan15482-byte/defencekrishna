# Pilot runtime security boundary

This change hardens engineering controls. It does **not** certify enterprise
readiness or improve model precision, recall, five-stage support or lead time.
The AIT research branch remains separate; its failed risk gates are not promoted.

## Profiles

`GARUDA_DEPLOYMENT_PROFILE=local` preserves the offline SIH console. The console
bridge is a trusted-local demonstration surface, not a public authenticated app.
Do not expose or tunnel it publicly. All runtime listeners now reject non-loopback
bind addresses, including wildcard binds. This is defense in depth, not protection
against a local user or a reverse proxy that forwards unauthenticated traffic.

`GARUDA_DEPLOYMENT_PROFILE=pilot` requires a bearer token on **all** console,
asset, bridge and API requests except `/health`. Viewer tokens can read;
operator tokens are required for every POST, including simulations and uploads.
Pilot startup refuses enforcement and lab automation. This keeps customer
evaluation shadow-only while model qualification remains incomplete.

Example (uses existing local launcher/credentials; does not provision a gateway):

```sh
GARUDA_DEPLOYMENT_PROFILE=pilot GARUDA_ENFORCE=0 GARUDA_LAB_AUTOMATION=0 python -m garuda_v3.integrated_server
```

A normal browser cannot attach bearer headers to every asset by itself. A pilot
needs an independently configured authenticated TLS gateway which maps verified
users to viewer/operator roles and supplies credentials server-side. Never place
the operator token in HTML, JavaScript, query strings or localStorage. A viewer
gateway must not inject an operator token for writes. Do not trust forwarded
identity headers supplied by clients. Gateway TLS, Host/Origin rewriting,
logout/session expiry and CSRF protection require integration testing before use.
No gateway or public deployment is claimed by this change.

## Implemented controls

- Distinct 32+ character viewer/operator tokens; signing key must be independent,
  32+ characters, with explicit containment scope before enforcement can start.
- Private runtime folder mode 0700 and database mode 0600 on supported POSIX hosts.
- Shared HTTP dispatch rejects duplicate Host/Content-Length/Authorization,
  transfer encoding, malformed lengths, GET bodies and oversized requests before
  console or API handlers run. Existing per-route limits remain stricter.
- Pilot request logs are JSON: random request ID, method, status and latency.
  They exclude credentials, bodies, raw URLs, query strings and client IPs.
- `/health` is liveness only. Bearer-authenticated `/api/readiness` returns 503 on
  local audit corruption and 200 when the loaded service and local audit pass.
  It is not a model-performance or enterprise-release gate.
- Existing scoped TTL policies, revoke and kill switch remain; new tests exercise
  expiration, concurrent creation, emergency revoke and corrupt-audit rejection.

## Deployment acceptance still required

1. TLS/SSO gateway and tenant isolation: **not implemented** by this patch. Use a
   separate process, runtime directory and credentials for each pilot/customer;
   this does not make the runtime a multi-tenant SaaS.
2. Rehearse encrypted SQLite backups using SQLite's online backup mechanism,
   restore in a separate offline instance and check audit integrity. Hash chaining
   detects inconsistent edits; it is not tamper-proof storage or an external
   signed anchor. Configure restricted remote log retention and alerts.
3. Run independent security/dependency review, realistic load/soak tests, disk-full
   recovery and gateway failure tests. The bounded HTTP thread pool is not a
   production capacity claim. Agree a retention/deletion policy with the customer.
4. Freeze fresh campaign qualification with verified labels and compromise
   timestamps. Keep all response actions shadow/operator-reviewed until gates pass.

## Reproduce focused checks

```sh
python -m unittest garuda_v3.tests.test_runtime_guard -v
python -m unittest garuda_v3.tests.test_api garuda_v3.tests.test_core -v
```

Full repository CI remains the merge requirement. Never relax a failed security
or forecasting gate merely to label a release enterprise-ready.
