# Live HTTP defence proof — bounded production adapter (22 Nov 2026)

## Scope

Public Vercel: the new \`/api/security-check?record=...\` endpoint receives **real HTTPS requests**, parses actual browser inputs on the server, and sends genuine HTTP status codes. It can read only constant, synthetic fixture data. It never connects to the live telemetry PostgreSQL tables or models, reads real user records, writes a learning database, adds IP rules or operates a deliberately exploitable live SQL endpoint.

The **unprotected before** fixture is a deterministic local test-only function in \`tests/test_live_defence_gateway.cjs\`, never a deployed route. CI sends requests to a loopback test server for the **protected after** fixture; it verifies the before fixture exposes only synthetic data and the after endpoint denies the identical input.

## Four named lanes, with boundaries

1. **Arjuna (active, bounded HTTP signature adapter):** rejects limited SQLi, XSS, traversal and command-injection-shaped dummy inputs with \`403\`. This is *not* the large private historical DetectionEngine in production and must not be called a full WAF.
2. **Krishna (active, bounded structural review):** rejects unrecognized dangerous-looking prototypes/structural patterns in the dummy route with \`403\`; this is a fixed heuristic, not a trained open-set detector or production learning/promotion.
3. **Sudarshan (active for dummy resource boundary):** rejects access to a restricted dummy record with \`403\` regardless of client-supplied roles/headers. This is server-side object access control, **not** an autonomous cryptographic IP-lockdown or signed-policy deployment. The existing private \`sudarshana-core.js\` and \`policy-guard.js\` are evaluated by their existing local tests.
4. **Garuda (independent live forecast):** Mac's authorized PCAP sensor reports real model forecasts to Render in \`SHADOW_ONLY\` mode. Forecasts are not input to this gateway's block policy; unsupported/stale predictions never trigger a deny.

The public site may have **Vercel Firewall** protections at the edge, if separately configured. An edge deny does not prove Arjuna saw the request. Both remain distinct in the UI.

## Non-destructive browser test

Open \`https://krishna-defence-system.vercel.app/#lab\`, select **Run 5 safe HTTP tests**. These real browser requests target a dummy-only endpoint with a total budget of five requests per click. Tests are expected to return:

| Request record value | Expected HTTP | Lane |
| --- | --- | --- |
| \`demo-public\` | 200 | Arjuna allowed public fixture |
| \`' OR 1=1--\` | 403 | Arjuna known signature |
| \`<script>alert(1)</script>\` | 403 | Arjuna known signature |
| \`__proto__[isAdmin]\` | 403 | Krishna structural review |
| \`demo-private\` | 403 | Sudarshan dummy scope |

The test client never sends real credentials, SQL statements to databases, high-volume traffic, executable payloads or user data. If Vercel blocks at its edge before the function, the lane will show *EDGE / UNKNOWN* rather than falsely attributing the block to the application.

## Limitations and next steps

- This proves server-side validation/authorization for the *synthetic test API only*. It does **not** certify protection for arbitrary production applications, users, login flows, databases, malware, host-level lateral movement, or distributed denial-of-service.
- A production WAF requires Vercel Firewall configuration and separate verification; per-instance memory counters are not reliable global rate limits across serverless instances.
- Scaled Arjuna/Krishna/Sudarshan adoption needs a real reverse proxy or edge enforcement architecture, isolated tenants, reviewed policy signing and revocation, durable audit, independent security assessment, staged rollback and representative attack/benign holdouts.
- Do not enable Garuda-driven automatic block merely because a risk estimate exceeds a threshold. Existing research deployment has unsupported domain cases.
- Never enter private tokens into browser consoles or share credentials in security-test screenshots.

## CI regression

\`node --test tests/test_live_defence_gateway.cjs\` exercises a local dummy before/after and actual loopback HTTP 200/403/404/405/422 responses. \`node --test tests/test_vercel_render_deploy.mjs\` enforces correct public lab wiring.
