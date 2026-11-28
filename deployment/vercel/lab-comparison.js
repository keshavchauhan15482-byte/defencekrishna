(() => {
  "use strict";
  const panel = document.getElementById("lab-comparison");
  if (!panel) return;
  const button = panel.querySelector("button");
  const status = panel.querySelector('[role="status"]');
  const evidence = panel.querySelector("ol");

  function addEvidence(message) {
    const row = document.createElement("li");
    row.textContent = new Date().toLocaleTimeString() + " · " + message;
    evidence.append(row);
  }

  async function readFixture(record) {
    const response = await fetch("/api/security-check?record=" + record, {
      credentials: "omit",
      cache: "no-store",
      signal: AbortSignal.timeout(8000),
    });
    return { status: response.status, body: await response.json() };
  }

  button.addEventListener("click", async () => {
    button.disabled = true;
    evidence.replaceChildren();
    status.textContent = "Checking hosted guard…";
    addEvidence("OFF · Simulated outage · illustrative HTTP 503");
    try {
      const restricted = await readFixture("demo-private");
      const denied = restricted.status === 403 && restricted.body?.decision === "DENY"
        && restricted.body?.lane === "SUDARSHAN"
        && restricted.body?.reason === "FIXTURE_SCOPE_DENIED"
        && !Object.hasOwn(restricted.body, "record");
      addEvidence("ON · Restricted fixture · HTTP " + restricted.status
        + (denied ? " · Sudarshan denied access" : " · Expected denial unverified"));
      const publicRecord = await readFixture("demo-public");
      const allowed = publicRecord.status === 200 && publicRecord.body?.decision === "ALLOW"
        && publicRecord.body?.record?.id === "demo-public";
      addEvidence("ON · Public fixture · HTTP " + publicRecord.status
        + (allowed ? " · Public record available" : " · Public access unverified"));
      status.textContent = denied && allowed ? "Hosted guard checks passed" : "Hosted guard checks did not pass";
    } catch {
      status.textContent = "Hosted guard results unavailable";
    } finally {
      button.disabled = false;
    }
  });
  status.textContent = "Ready";
  button.disabled = false;
})();
