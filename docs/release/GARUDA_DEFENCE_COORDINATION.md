# Garuda defence coordination contract

The hosted authenticated telemetry gateway now emits a server-generated
`defence_coordination` object. It is a recommendation for module review,
not an active enforcement message bus or new firewall rule.

- A supported model alert within its actual forecast horizon, fresh sensor
  heartbeat and continuous feed recommends Arjuna known-threat and Krishna
  anomaly review. No arbitrary confidence threshold is substituted for the
  model's own alert decision.
- Stale, expired, unsupported, malformed, future-dated or non-alert evidence
  withholds the recommendation.
- The contract reserves a BLOCK_REVIEW_REQUESTED state for verified
  precompromise evidence; the current hosted gateway explicitly projects
  verified_precompromise=false. Thus that state is not currently reachable
  from live data.
- Sudarshana requires independently verified scoped evidence and signed
  operator policy; no forecast, client-supplied IP, or browser can grant
  blocking. Existing deterministic request guards continue independently.

No production auto-block authority, calibrated new forecast performance,
or direct dispatch to the historical private proxy is claimed. Activation
requires authenticated target binding, independent representative false
positive and lead-time validation, durable revocation and rollback, and
approved scoped policy. See OPERATOR_APPROVAL_AND_FORECAST_READINESS.md.

Test: `node --test tests/test_garuda_coordination.cjs`.
