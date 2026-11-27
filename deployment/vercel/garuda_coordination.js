"use strict";
// Server-side coordination from the authenticated, sanitized advisory feed.
// A recommendation is not an enforcement policy. Never infer client identity
// from a global packet forecast or accept a browser-supplied target.
function coordinate(feed,now=Date.now()/1000){
 const events=Array.isArray(feed?.events)?feed.events:[];
 const event=events.at(-1);
 const blockers=[];
 const points=event?.trajectory;
 const valid=Array.isArray(points)&&points.length===4&&[10,60].some(step=>points.every((p,i)=>p?.horizon_seconds===step*(i+1)&&Number.isFinite(p.malicious_flow_probability)&&p.malicious_flow_probability>=0&&p.malicious_flow_probability<=1));
 const cutoff=event?.cutoff_epoch_seconds;
 if(!valid||!Number.isFinite(cutoff)||cutoff<=0||cutoff>now||now>=cutoff+points[3].horizon_seconds)blockers.push("FORECAST_WINDOW_INVALID_OR_EXPIRED");
 if(feed?.state!=="near_live"||feed?.gap!==false)blockers.push("FEED_NOT_FRESH_OR_CONTINUOUS");
 const sensor=feed?.sensor_status;
 if(!["capturing","processing"].includes(sensor?.state)||!Number.isFinite(sensor.sensor_age_seconds)||sensor.sensor_age_seconds<0||sensor.sensor_age_seconds>=90)blockers.push("SENSOR_NOT_FRESH");
 if(event?.source!=="completed_capture_shadow"||event?.operating_mode!=="SHADOW_ONLY"||event?.automatic_containment!==false||event?.supported!==true)blockers.push("MODEL_SUPPORT_UNVERIFIED");
 if(event?.alert!==true)blockers.push("NO_MODEL_ALERT");
 const review=blockers.length===0;
 // No public feed currently provides independently verified compromise timing
 // or authenticated flow-to-client binding. Never elevate this into a deny.
 const evidence=review&&event?.verified_precompromise===true;
 const state=evidence?"BLOCK_REVIEW_REQUESTED":review?"INSPECTION_RECOMMENDED":"WITHHELD";
 if(!evidence)blockers.push("VERIFIED_PRECOMPROMISE_EVIDENCE_REQUIRED");
 blockers.push("TRUSTED_TARGET_BINDING_REQUIRED","INDEPENDENT_CALIBRATION_AND_OPERATOR_APPROVAL_REQUIRED");
 return {schema:"krishna-garuda-coordination-v1",state,source_event_id:review&&Number.isSafeInteger(event.id)?event.id:null,expires_at:review?cutoff+points[3].horizon_seconds:null,
  arjuna:review?"REVIEW_KNOWN_THREAT_EVIDENCE":"NORMAL_REQUEST_GUARDS",
  krishna:review?"REVIEW_ANOMALY_EVIDENCE":"NORMAL_REQUEST_GUARDS",
  sudarshana:evidence?"OPERATOR_BLOCK_REVIEW_REQUIRED":"NO_NEW_CONTAINMENT",
  automatic_containment:false,blocking_authorized:false,blockers};
}
module.exports={coordinate};
