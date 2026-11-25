# Production readiness and operator approval

## Current boundaries
- Existing free Vercel custom rules and application guards enforce selected
  request boundaries. Managed OWASP SQLi/XSS deny is blocked by account billing
  (HTTP 402). No plan or billing change was made.
- Sudarshana verifies dual signatures over an exact route/client-IP scope,
  independently documented confirmed-escape reference and expiration. The
  production deployment remains unarmed until real authorized operators approve
  an eligible policy. There is no general automatic IP ban.
- Garuda's completed-capture feed is not trusted source-to-client attribution.
  No public field, confidence score or apparent risk can authorize containment.

## Secure local ceremony
Use Node 22+ on each authorized approver's own device. Keep the private directory
outside Git, with mode 0700. Example: 
`node scripts/sudarshana_operator.cjs keygen "$HOME/.krishna-operator" operator1`.
Each approver keeps their private PEM separate and shares ONLY the public PEM.
The toolkit creates a proposal, detached signatures and a verified public policy
bundle; see its usage message. A real incident reference and authorization for
the exact client IP and route are prerequisites. Never use an arbitrary visitor
as a test subject; use an isolated owned test client and synthetic records.
The reviewer independently validates the incident evidence, target scope,
potential shared-IP impact and expiry before signing. Never create both keys
on one device and call that independent operator approval.
The final bundle contains public keys and signatures, not private keys. Vercel
environment policy variables are a deployment snapshot. Do not activate until
the IP provenance, allowlist, reliable revocation/distribution and operational
rollback have been independently reviewed. Emergency-stop via environment change
requires deployment propagation; it is not an instantaneous global revoke.
Expiry is enforced at request time. No script automatically changes cloud settings.

## Repeatable evidence
`node --test tests/test_operator_readiness.cjs` checks local key permissions,
two distinct approvals, tampered policy rejection, wrong route, expiry and
emergency stop over real loopback HTTP using a reserved fixture address.
This does not demonstrate an actual public-client lockdown.
`node scripts/check_hosted_readiness.cjs` reads the real public advisory feed
and reports missing readiness gates without printing addresses, secrets or
model inputs. Even a supported fresh forecast cannot satisfy attribution merely
by carrying a client-supplied IP field.

## Research gates required before autonomous containment
Obtain owner-authorized server/network telemetry at the protected ingress,
with authenticated flow identity and clock alignment. Establish a verified
mapping to the real protected resource; shared-NAT addresses do not prove
attacker identity. Evaluate fresh campaigns and benign controls on a frozen
model and calibration, with per-family recall, false-positive confidence
intervals and positive verified compromise-timestamp lead time. Test target
binding, replay rejection, policy revocation and legitimate-user access in a
private staging environment. An independent operator must approve any proposed
scope. Until then keep Garuda advisory and retain deterministic server-side
request blocking. No new dataset results or production readiness scores are
claimed by this release.

## Strict hosted evidence audit
The public gateway projects only numeric forecast horizons and probabilities;
invalid scores, cutoffs or mixed horizon contracts fail closed. Run
`node scripts/check_hosted_readiness.cjs --require-advisory-evidence` for a
nonzero exit if the forecast window has elapsed, continuity or model support
is missing, the sensor is stale or verified precompromise evidence is absent.
The current public gateway deliberately sets verified_precompromise to false.
A passing advisory audit would still never authorize containment. Restart the
authorized local sensor using the existing Mac setup guide when it is stale.

## Cloud-first dashboard (no local computer required)
The hosted console now prioritizes actual persisted page-load request counts,
including recent and previous five-minute windows. Its health is based on the
authenticated cloud feed, not packet-sensor liveness. The local activation
prompt is removed from the hosted UI; the optional research collector remains
available independently. Page-load counts are not full network traffic, unique
visitors, model input or attacks. No replacement packet inference or autonomous
containment is claimed. Older relay versions report short-window counts as
unavailable until the backend has updated.
