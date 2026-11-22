"use strict";
/**
 * Vercel serverless same-origin gateway to authenticated Render advisory feed.
 * No sensor token, viewer token or Render backend URL appears in browser JS.
 */
module.exports = async function handler(request, response) {
  response.setHeader("Cache-Control", "no-store");
  response.setHeader("X-Content-Type-Options", "nosniff");
  response.setHeader("Cross-Origin-Resource-Policy", "same-origin");
  if (request.method !== "GET") {
    return response.status(405).json({error:"GET required"});
  }
  const raw = request.query?.after ?? "0";
  if (typeof raw !== "string" || !/^\d{1,16}$/.test(raw) ||
      !Number.isSafeInteger(Number(raw))) {
    return response.status(422).json({error:"Invalid event cursor"});
  }
  const token = process.env.RENDER_VIEWER_TOKEN;
  const base = process.env.RENDER_BACKEND_URL;
  if (!token || token.length < 32 || !base) {
    return response.status(503).json({error:"Render live feed is not configured"});
  }
  let backend;
  try {
    backend = new URL(base);
    if (backend.protocol !== "https:" || backend.username || backend.password ||
        backend.search || backend.hash || (backend.pathname !== "/" && backend.pathname !== "")) {
      throw Error("Unsupported backend URL");
    }
  } catch {
    return response.status(503).json({error:"Backend URL configuration invalid"});
  }
  try {
    const upstream = await fetch(
      new URL("/api/live/events?after=" + raw, backend),
      {headers:{Authorization:"Bearer " + token,Accept:"application/json"},
       redirect:"error",signal:AbortSignal.timeout(20_000),cache:"no-store"}
    );
    if (!upstream.ok) throw Error("Upstream unavailable");
    const contentLength = Number(upstream.headers.get("content-length") || 0);
    if (contentLength > 131072) throw Error("Upstream response too large");
    const text = await upstream.text();
    if (text.length > 131072) throw Error("Upstream response too large");
    const parsed = JSON.parse(text);
    if (!parsed || !["waiting","disabled","stale","near_live"].includes(parsed.state) ||
        !Array.isArray(parsed.events) || parsed.events.length > 128) {
      throw Error("Malformed upstream response");
    }
    // Explicitly project event fields so upstream never leaks hashes/raw inputs.
    const events = parsed.events.map(event => {
      if (!Number.isSafeInteger(event.id) || !Array.isArray(event.trajectory) ||
          event.trajectory.length !== 4 || event.automatic_containment !== false) {
        throw Error("Invalid shadow feed event");
      }
      return {
        id:event.id,kind:"forecast",source:"completed_capture_shadow",
        cutoff_epoch_seconds:event.cutoff_epoch_seconds,
        trajectory:event.trajectory,score:event.score,
        alert:event.alert===true,supported:event.supported===true,
        operating_mode:"SHADOW_ONLY",automatic_containment:false,
        verified_precompromise:false,
      };
    });
    return response.status(200).json({
      state:parsed.state,cursor:parsed.cursor,
      events,source:"completed_capture_shadow",
      sensor_age_seconds:parsed.sensor_age_seconds,
      gap:parsed.gap===true,automatic_containment:false,
    });
  } catch {
    return response.status(503).json({error:"Live telemetry backend unavailable; no live data claimed"});
  }
};
