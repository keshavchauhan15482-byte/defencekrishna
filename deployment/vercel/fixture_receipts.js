"use strict";
const REASONS={"ARJUNA":["SQLI_SIGNATURE","XSS_SIGNATURE","TRAVERSAL_SIGNATURE","COMMAND_SIGNATURE","HISTORICAL_DANGER_PATTERN","UNSPECIFIED_RULE"],"KRISHNA":["STRUCTURAL_ANOMALY_REVIEW","HISTORICAL_STRUCTURE_REVIEW","UNSPECIFIED_RULE"],"SUDARSHAN":["FIXTURE_SCOPE_DENIED","UNSPECIFIED_RULE"]};
function projectReceipts(input,now=Date.now()/1000){
 if(input?.source!=="server_recorded_fixture_denials"||input.scope!=="synthetic_fixture_only"||input.automatic_containment!==false||!Number.isFinite(input.observed_at)||Math.abs(now-input.observed_at)>=60||!Array.isArray(input.events)||input.events.length>12)return null;
 const ids=new Set(),events=[];
 for(const e of input.events){
  if(!e||!Number.isSafeInteger(e.id)||e.id<1||ids.has(e.id)||!Number.isFinite(e.observed_at)||e.observed_at>input.observed_at||e.observed_at<input.observed_at-1800||!Object.hasOwn(REASONS,e.lane)||!REASONS[e.lane].includes(e.reason)||e.decision!=="DENY"||e.status!==403||e.event_prediction_probability!==null)return null;
  ids.add(e.id);events.push({id:e.id,observed_at:e.observed_at,lane:e.lane,reason:e.reason,decision:"DENY",status:403,event_prediction_probability:null});
 }
 return {source:input.source,scope:input.scope,observed_at:input.observed_at,events,automatic_containment:false};
}
module.exports={projectReceipts};
