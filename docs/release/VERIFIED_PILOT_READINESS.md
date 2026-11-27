# Production pilot readiness — bounded evidence update

## Implemented
- Stream-bounded upstream JSON decoding: maximum 128 KiB decoded response; reject oversized, malformed and invalid UTF-8 responses; cancel incomplete bodies.
- Missing/unknown feed continuity now indicates a gap, never a verified continuous forecast.
- A fixed four-request read-only terminal audit checks public dummy access, restricted dummy denial attributable to the application, a second legitimate request, and the advisory feed. It never accepts arbitrary URLs or sends attack inputs.
- New regressions are included in integration CI.

## Reproduce
```sh
node --test tests/test_bounded_feed.cjs tests/test_hosted_pilot_audit.cjs
node scripts/verify_hosted_pilot.cjs
```

The latter performs only four sequential HTTPS GET requests to the project's existing public synthetic endpoints; no secrets or raw telemetry are exported. Its timestamps, latency and status are observations, not an SLA. An edge-only 403 is not credited to the application guard. No production protection switch, simulated outage, or automatic containment is introduced.

## Remaining gates
| Gate | Evidence required |
|---|---|
| Independent security assessment | Authorized external reviewer and signed scope/report |
| Live pre-compromise forecasting | Frozen model, real authorized ingress telemetry, verified incident timestamps, clean histories, untouched campaigns, recall/FPR intervals |
| Autonomous containment | Trusted target identity, independent approvals, durable revocation and rollback, legitimate-user safety |
| Customer readiness | Explicit customer authorization, isolated staging, availability and recovery objectives, independent testing, tenant isolation and contracts |

The current release remains advisory for Garuda. No passing local test proves live forecasting, arbitrary website protection or customer deployment readiness. Do not enable automatic containment without the remaining gates.
