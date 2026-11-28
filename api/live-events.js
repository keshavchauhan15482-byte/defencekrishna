"use strict";
/**
 * Vercel serverless same-origin gateway to authenticated Render advisory feed.
 * No sensor token, viewer token or Render backend URL appears in browser JS.
 */
const {checkKnownApiInput}=require("../deployment/vercel/defence_gate.js");
const {readBoundedJson}=require("../deployment/vercel/bounded_json.js");

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
    if(!Number.isSafeInteger(parsed.cursor)||parsed.cursor<0)throw Error("Invalid feed cursor");
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
    const risk=parsed.fixture_risk;
    const fixtureRisk=risk?.source==="observed_fixture_http_index"&&risk.is_prediction===false&&risk.automatic_containment===false&&
      Number.isSafeInteger(risk.score)&&risk.score>=0&&risk.score<=100&&Number.isSafeInteger(risk.denials_recent_minute_buckets)&&risk.denials_recent_minute_buckets>=0&&
      Number.isSafeInteger(risk.requests_5m)&&risk.requests_5m>=0&&Number.isFinite(risk.observed_at)&&Math.abs(Date.now()/1000-risk.observed_at)<60?
      {source:risk.source,score:risk.score,denials_recent_minute_buckets:risk.denials_recent_minute_buckets,requests_5m:risk.requests_5m,observed_at:risk.observed_at,is_prediction:false,automatic_containment:false}:null;
    const h=parsed.http_forecast;
    const bounded=(n,max)=>Number.isFinite(n)&&n>=0&&n<=max;
    const validHttp=h?.source==="recorded_http_traffic_forecast_v1"&&h.condition==="no_new_fixture_denials"&&h.is_attack_probability===false&&h.automatic_containment===false&&
      h.validation_scope==="rolling_internal_page_count_audit"&&["ewma","persistence"].includes(h.method)&&Number.isFinite(h.issued_at)&&Math.abs(Date.now()/1000-h.issued_at)<60&&
      Number.isSafeInteger(h.history_minutes)&&h.history_minutes>=12&&h.history_minutes<=60&&h.audit_samples===h.history_minutes-8&&
      bounded(h.ewma_mae,1e9)&&bounded(h.persistence_mae,1e9)&&bounded(h.expected_requests_per_minute,1e9)&&
      Array.isArray(h.trajectory)&&h.trajectory.length===4&&h.trajectory.every((p,i)=>p?.horizon_seconds===[60,120,180,300][i]&&Number.isSafeInteger(p.conditional_index)&&bounded(p.conditional_index,100)&&bounded(p.expected_page_requests,5e9))&&h.score===h.trajectory[0].conditional_index;
    const httpForecast=validHttp?{source:h.source,issued_at:h.issued_at,history_minutes:h.history_minutes,audit_samples:h.audit_samples,method:h.method,ewma_mae:h.ewma_mae,persistence_mae:h.persistence_mae,expected_requests_per_minute:h.expected_requests_per_minute,score:h.score,trajectory:h.trajectory.map(p=>({horizon_seconds:p.horizon_seconds,expected_page_requests:p.expected_page_requests,conditional_index:p.conditional_index})),condition:h.condition,is_attack_probability:false,automatic_containment:false,validation_scope:h.validation_scope}:null;
    return response.status(200).json({
      http_forecast:httpForecast,
      fixture_risk:fixtureRisk,
      state:parsed.state,cursor:parsed.cursor,server_epoch_seconds:Date.now()/1000,
      events,source:"completed_capture_shadow",
      sensor_age_seconds:parsed.sensor_age_seconds,
      gap:parsed.gap!==false,automatic_containment:false,
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
