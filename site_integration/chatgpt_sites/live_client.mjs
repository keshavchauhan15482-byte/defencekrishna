/**
 * Framework-agnostic browser client for the EXISTING ChatGPT Sites dashboard.
 * Uses same-origin read-only API only. Never receives or stores a sensor token.
 * UI must display live statuses distinctly from any manual recorded replay.
 */
export function createKrishnaSiteLiveClient({
  fetchImpl = fetch,
  onEvent = () => {},
  onState = () => {},
  onError = () => {},
  intervalMs = 2600,
  setIntervalImpl = setInterval,
  clearIntervalImpl = clearInterval,
} = {}) {
  if (!Number.isInteger(intervalMs) || intervalMs < 1000) throw Error("Polling interval >= 1000ms required");
  let cursor = 0, busy = false, timer = null, stopped = false;

  async function poll() {
    if (stopped || busy) return;
    busy = true;
    try {
      const response = await fetchImpl("/bridge/live/events?after=" + cursor, {
        credentials: "same-origin", cache: "no-store",
      });
      if (!response.ok) throw Error("Sensor feed returned HTTP " + response.status);
      const data = await response.json();
      if (!data || !Array.isArray(data.events) ||
          !["disabled","waiting","near_live","stale"].includes(data.state))
        throw Error("Invalid live-feed response");
      for (const event of data.events) {
        if (!event || !Number.isSafeInteger(event.id) || event.id <= cursor) continue;
        if (event.kind !== "forecast" || event.automatic_containment !== false ||
            !Array.isArray(event.trajectory) || event.trajectory.length !== 4) {
          throw Error("Unsupported live event; no UI claim issued");
        }
        cursor = event.id;
        onEvent(event); // Add ONE actual graph point per newly ingested event.
      }
      onState({
        state: data.state, sensorAge: data.sensor_age_seconds,
        source: "completed_capture_shadow", gap: data.gap === true,
        advisoryOnly: true,
      });
    } catch (error) {
      onError(error instanceof Error ? error.message : "Sensor feed unavailable");
    } finally {
      busy = false;
    }
  }
  function start() {
    if (stopped || timer !== null) return;
    timer = setIntervalImpl(poll, intervalMs);
    void poll();
  }
  function stop() {
    stopped = true;
    if (timer !== null) clearIntervalImpl(timer);
    timer = null;
  }
  return { poll, start, stop, getCursor: () => cursor };
}
