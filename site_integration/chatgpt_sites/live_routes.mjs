/**
 * ChatGPT Sites-compatible, Web Fetch API adapter for Krishna's real sensor feed.
 *
 * Mount this in the EXISTING Site's server request router. The Sites project
 * source is separate from this GitHub repo, so this module is an integration
 * kit, not an automatically installed or deployed Site version.
 *
 * env.DB: Sites D1 binding (or adjust binding name)
 * env.GARUDA_LIVE_SENSOR_TOKEN: 32+ char server-side secret, never browser code
 *
 * No Python server is exposed; the local publisher pushes JSON metadata to the
 * Site's POST /api/live/ingest endpoint over HTTPS. No policy or packet payload.
 */
const INGEST = "/api/live/ingest";
const FEED = "/bridge/live/events";
const HORIZONS = [10, 20, 30, 40];
const MAX_BODY = 8192;
const MAX_EVENTS = 128;
const MAX_AGE = 300;
const STALE_AGE = 120;
const RETENTION = 30 * 24 * 60 * 60;

function json(data, status = 200) {
  return new Response(JSON.stringify(data), {
    status,
    headers: {
      "Content-Type": "application/json; charset=utf-8",
      "Cache-Control": "no-store",
      "X-Content-Type-Options": "nosniff",
      "Cross-Origin-Resource-Policy": "same-origin", // do not grant cross-origin reads
    }
  });
}

export function validateSensorPayload(data, now = Math.floor(Date.now() / 1000)) {
  if (!data || typeof data !== "object" || Array.isArray(data)) throw Error("JSON object required");
  const required = ["schema","kind","capture_sha256","model_sha256","cutoff_epoch_seconds",
    "trajectory","alert","supported","automatic_containment"];
  if (Object.keys(data).length !== required.length ||
      required.some(k => !Object.prototype.hasOwnProperty.call(data, k))) {
    throw Error("Unexpected sensor schema");
  }
  if (data.schema !== "krishna-live-v1" || data.kind !== "forecast") throw Error("Unsupported event");
  const sha = /^[a-f0-9]{64}$/i;
  if (!sha.test(data.capture_sha256) || !sha.test(data.model_sha256)) throw Error("SHA-256 provenance required");
  const cutoff = data.cutoff_epoch_seconds;
  if (typeof cutoff !== "number" || !Number.isFinite(cutoff) ||
      cutoff < now - MAX_AGE || cutoff > now + 60) throw Error("Capture not fresh");
  if (typeof data.alert !== "boolean" || typeof data.supported !== "boolean" ||
      data.automatic_containment !== false) throw Error("No autonomous actions allowed");
  if (!Array.isArray(data.trajectory) || data.trajectory.length !== 4) throw Error("Exactly four horizons required");
  const trajectory = data.trajectory.map((item,i) => {
    if (!item || typeof item !== "object" || Array.isArray(item) ||
        Object.keys(item).length !== 2 ||
        !Object.prototype.hasOwnProperty.call(item,"horizon_seconds") ||
        !Object.prototype.hasOwnProperty.call(item,"malicious_flow_probability") ||
        item.horizon_seconds !== HORIZONS[i] ||
        typeof item.malicious_flow_probability !== "number" ||
        !Number.isFinite(item.malicious_flow_probability) ||
        item.malicious_flow_probability < 0 || item.malicious_flow_probability > 1)
      throw Error("Invalid horizon/probability");
    return {
      horizon_seconds: HORIZONS[i],
      malicious_flow_probability: Math.round(item.malicious_flow_probability * 1e8)/1e8,
    };
  });
  return {
    capture_sha256: data.capture_sha256.toLowerCase(),
    model_sha256: data.model_sha256.toLowerCase(),
    cutoff_epoch_seconds: cutoff,
    trajectory,
    alert: data.alert,
    supported: data.supported,
    score: Math.round(Math.max(...trajectory.map(x => x.malicious_flow_probability)) * 10000) / 100,
  };
}

export async function sensorAuthorized(header, token) {
  if (typeof token !== "string" || token.length < 32 || token.length > 256 ||
      !header?.startsWith("Bearer ")) return false;
  const supplied = header.slice(7);
  const encoder = new TextEncoder();
  const [a,b] = await Promise.all([
    crypto.subtle.digest("SHA-256", encoder.encode(supplied)),
    crypto.subtle.digest("SHA-256", encoder.encode(token)),
  ]);
  const first = new Uint8Array(a), second = new Uint8Array(b);
  let different = 0;
  for (let i=0; i<32; i++) different |= first[i] ^ second[i];
  return different === 0;
}

async function readSmallJSON(request) {
  const declared = request.headers.get("Content-Length");
  if (declared && (!/^\d+$/.test(declared) || Number(declared) > MAX_BODY)) throw Error("Event too large");
  const reader = request.body?.getReader();
  if (!reader) throw Error("Empty body");
  const parts = [];
  let size = 0;
  try {
    for (;;) {
      const {value,done} = await reader.read();
      if (done) break;
      size += value.length;
      if (size > MAX_BODY) throw Error("Event too large");
      parts.push(value);
    }
  } finally {
    try { await reader.cancel(); } catch {}
    reader.releaseLock();
  }
  if (!size) throw Error("Empty body");
  const merged = new Uint8Array(size);
  let pos=0;
  for (const chunk of parts) { merged.set(chunk,pos); pos+=chunk.length; }
  return JSON.parse(new TextDecoder("utf-8",{fatal:true}).decode(merged));
}

function publicEvent(row) {
  const details = JSON.parse(row.payload_json);
  return {
    id: row.id,
    kind: "forecast",
    source: "completed_capture_shadow",
    received_at: row.received_at,
    cutoff_epoch_seconds: row.cutoff_epoch_seconds,
    score: details.score,
    trajectory: details.trajectory,
    alert: details.alert,
    supported: details.supported,
    operating_mode: "SHADOW_ONLY",
    automatic_containment: false,
    verified_precompromise: false,
  };
}

/**
 * Returns Response for live routes, or null for unrelated requests.
 * This handles only ONE isolated advisory feed, never arbitrary proxy targets.
 */
export async function handleKrishnaLiveRequest(request, env) {
  const url = new URL(request.url);
  const path = url.pathname;
  if (path !== INGEST && path !== FEED) return null;
  if (!env?.DB) return json({error:"Live event database not configured"},503);

  if (path === INGEST) {
    if (request.method !== "POST") return json({error:"POST required"},405);
    if (!(await sensorAuthorized(request.headers.get("Authorization"), env.GARUDA_LIVE_SENSOR_TOKEN))) {
      return json({error:"Sensor credential required"},401);
    }
    if (request.headers.get("Content-Type")?.split(";")[0].trim().toLowerCase() !== "application/json")
      return json({error:"JSON required"},415);
    let record;
    try {
      record = validateSensorPayload(await readSmallJSON(request));
    } catch {
      return json({error:"Malformed, unsafe or historical event"},422);
    }
    try {
      const now = Date.now() / 1000;
      const db = env.DB;
      // DB is a metadata store only. No source IP, packet bytes, or policy keys.
      const recent = await db.prepare(
        "SELECT COUNT(*) AS n FROM krishna_live_events WHERE received_at > ?"
      ).bind(now - 60).first();
      if (Number(recent?.n || 0) >= 60) return json({error:"Sensor ingestion rate limit"},429);
      await db.prepare(
        "INSERT OR IGNORE INTO krishna_live_events (received_at,cutoff_epoch_seconds,capture_sha256,model_sha256,payload_json) VALUES (?,?,?,?,?)"
      ).bind(now, record.cutoff_epoch_seconds, record.capture_sha256,
        record.model_sha256, JSON.stringify(record)).run();
      const stored = await db.prepare(
        "SELECT id FROM krishna_live_events WHERE capture_sha256 = ? AND model_sha256 = ?"
      ).bind(record.capture_sha256,record.model_sha256).first();
      // Best-effort pruning on ingest. A scheduled deletion job is needed to
      // enforce maximum retention while the sensor remains idle.
      await db.prepare("DELETE FROM krishna_live_events WHERE received_at < ?").bind(now - RETENTION).run();
      await db.prepare(
        "DELETE FROM krishna_live_events WHERE id NOT IN (SELECT id FROM krishna_live_events ORDER BY id DESC LIMIT ?)"
      ).bind(MAX_EVENTS).run();
      return json({accepted:true,event_id:stored?.id,mode:"SHADOW_ONLY"},202);
    } catch {
      return json({error:"Live event database unavailable"},503);
    }
  }

  if (request.method !== "GET") return json({error:"GET required"},405);
  const rawAfter = url.searchParams.get("after") ?? "0";
  if (!/^\d{1,16}$/.test(rawAfter)) return json({error:"Invalid cursor"},422);
  const after = Number(rawAfter);
  if (!Number.isSafeInteger(after)) return json({error:"Invalid cursor"},422);

  try {
    const db = env.DB;
    const newest = await db.prepare(
      "SELECT id,received_at FROM krishna_live_events ORDER BY id DESC LIMIT 1"
    ).first();
    const oldest = await db.prepare(
      "SELECT id FROM krishna_live_events ORDER BY id ASC LIMIT 1"
    ).first();
    const rows = await db.prepare(
      "SELECT id,received_at,cutoff_epoch_seconds,payload_json FROM krishna_live_events WHERE id > ? ORDER BY id ASC LIMIT ?"
    ).bind(after, MAX_EVENTS).all();
    const now = Date.now() / 1000;
    const age = newest ? Math.max(0, now - newest.received_at) : null;
    const state = !env.GARUDA_LIVE_SENSOR_TOKEN ? "disabled" :
      !newest ? "waiting" : age > STALE_AGE ? "stale" : "near_live";
    return json({
      state, source:"completed_capture_shadow", stream:"bounded_polling",
      automatic_containment:false,
      cursor: Number(newest?.id || 0),
      events:(rows.results || []).map(publicEvent),
      sensor_age_seconds: age == null ? null : Math.round(age*10)/10,
      gap: !!(after > 0 && oldest && after < oldest.id - 1),
    });
  } catch {
    return json({error:"Live event database unavailable"},503);
  }
}
