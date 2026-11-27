"use strict";
/**
 * Vercel serverless same-origin gateway to authenticated Render advisory feed.
 * No sensor token, viewer token or Render backend URL appears in browser JS.
 */
const {checkKnownApiInput}=require("../deployment/vercel/defence_gate.js");
const {readBoundedJson}=require("../deployment/vercel/bounded_json.js");
const {coordinate}=require("../deployment/vercel/garuda_coordination.js");

const {historicalDeny}=require("../deployment/vercel/historical_inspection.js");
const {applySignedContainment}=require("../deployment/vercel/signed_scope.js");
module.exports = async function handler(request, response) {
  response.setHeader("Cache-Control", "no-store");
  response.setHeader("X-Content-Type-Options", "nosniff");
  response.setHeader("Cross-Origin-Resource-Policy", "same-origin");
  if (request.method !== "GET") {
    return response.status(405).json({error:"GET required"});
  }
  if(applySignedContainment(request,response,"live-events"))return;
  const raw = request.query?.after ?? "0";
  const inspection=checkKnownApiInput(raw);
  if(inspection){
    response.setHeader("X-Krishna-Lane",inspection.lane);
    response.setHeader("X-Krishna-Decision","deny");
    return response.status(inspection.status).json({
      error:"Disallowed request parameter",reason:inspection.reason,
      lane:inspection.lane,automatic_containment:false
    });
  }
  if (typeof raw !== "string" || !/^\d{1,16}$/.test(raw) ||
      !Number.isSafeInteger(Number(raw))) {
    const historical=await historicalDeny(raw);
    if(historical){
      response.setHeader("X-Krishna-Lane",historical.lane);
      response.setHeader("X-Krishna-Decision","deny");
      response.setHeader("X-Krishna-Engine",historical.engine);
      return response.status(403).json({error:"Disallowed request parameter",lane:historical.lane,reason:historical.reason,automatic_containment:false});
    }
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
    const parsed = await readBoundedJson(upstream);
    if (!parsed || !["waiting","disabled","stale","near_live"].includes(parsed.state) ||
        !Array.isArray(parsed.events) || parsed.events.length > 128) {
      throw Error("Malformed upstream response");
    }
    // Explicitly project event fields so upstream never leaks hashes/raw inputs.
    const events = parsed.events.map(event => {
      if (!event || !Number.isSafeInteger(event.id) || event.id < 1 ||
          !Number.isFinite(event.cutoff_epoch_seconds) || event.cutoff_epoch_seconds <= 0 ||
          !Number.isFinite(event.score) || event.score < 0 || event.score > 100 ||
          !Array.isArray(event.trajectory) ||
          event.trajectory.length !== 4 || event.automatic_containment !== false) {
        throw Error("Invalid shadow feed event");
      }
      const trajectory=event.trajectory.map(point=>{
        if(!point || !Number.isSafeInteger(point.horizon_seconds) ||
          !Number.isFinite(point.malicious_flow_probability) ||
          point.malicious_flow_probability<0 || point.malicious_flow_probability>1)
          throw Error("Invalid forecast point");
        return {horizon_seconds:point.horizon_seconds,malicious_flow_probability:point.malicious_flow_probability};
      });
      if(![10,60].some(step=>trajectory.every((p,i)=>p.horizon_seconds===step*(i+1))))
        throw Error("Invalid forecast horizon contract");
      return {
        id:event.id,kind:"forecast",source:"completed_capture_shadow",
        cutoff_epoch_seconds:event.cutoff_epoch_seconds,
        trajectory,score:event.score,
        alert:event.alert===true,supported:event.supported===true,
        operating_mode:"SHADOW_ONLY",automatic_containment:false,
        verified_precompromise:false,
      };
    });
    const activity=parsed.site_activity;
    if(!activity||activity.source!=="first_party_page_requests"||
       !Number.isSafeInteger(activity.total_requests)||activity.total_requests<0||
       !Number.isSafeInteger(activity.requests_24h)||activity.requests_24h<0||
       (activity.last_request_at!==null && (
        typeof activity.last_request_at!=="number"||
        !Number.isFinite(activity.last_request_at)))) {
      throw Error("Site activity summary unavailable");
    }
    return response.status(200).json({
      state:parsed.state,cursor:parsed.cursor,
      events,source:"completed_capture_shadow",
      sensor_age_seconds:parsed.sensor_age_seconds,
      gap:parsed.gap!==false,automatic_containment:false,
      defence_coordination:coordinate({state:parsed.state,gap:parsed.gap,events,sensor_status:parsed.sensor_status}),
      site_activity:{
        source:"first_party_page_requests",is_model_input:false,
        total_requests:activity.total_requests,
        requests_24h:activity.requests_24h,
        // Rolling upgrade: older relays omit these fields; unknown is not zero.
        requests_5m:Number.isSafeInteger(activity.requests_5m)&&activity.requests_5m>=0&&activity.requests_5m<=activity.requests_24h?activity.requests_5m:null,
        requests_previous_5m:Number.isSafeInteger(activity.requests_previous_5m)&&activity.requests_previous_5m>=0&&activity.requests_previous_5m<=activity.requests_24h?activity.requests_previous_5m:null,
        last_request_at:activity.last_request_at,
      },
      sensor_status: {
        source: "authenticated_sensor_heartbeat",
        state: ["absent","capturing","processing","stale"].includes(parsed.sensor_status?.state)
          ? parsed.sensor_status.state : "absent",
        sensor_age_seconds: Number.isFinite(parsed.sensor_status?.sensor_age_seconds)
          ? parsed.sensor_status.sensor_age_seconds : null,
        capture_seconds: Number.isSafeInteger(parsed.sensor_status?.capture_seconds)
          && parsed.sensor_status.capture_seconds >= 90
          && parsed.sensor_status.capture_seconds <= 600
          ? parsed.sensor_status.capture_seconds : null,
      },
    });
  } catch {
    return response.status(503).json({error:"Live telemetry backend unavailable; no live data claimed"});
  }
};
