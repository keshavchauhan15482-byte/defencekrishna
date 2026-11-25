"use strict";
// Read-only audit of the project's own public feed; never generates a policy.
const endpoint="https://krishna-defence-system.vercel.app/bridge/live/events?after=0";
function assess(feed){
 const event=Array.isArray(feed?.events)?feed.events.at(-1):undefined;
 const blockers=[];
 if(feed?.state!=="near_live")blockers.push("forecast_not_fresh");
 if(!["capturing","processing"].includes(feed?.sensor_status?.state))blockers.push("sensor_not_active");
 if(event?.supported!==true)blockers.push("runtime_support_unverified");
 if(event?.verified_precompromise!==true)blockers.push("precompromise_evidence_unverified");
 // This public projection contains no trusted mapping between a forecast and
 // an HTTP client identity. Never accept arbitrary fields as proof of attribution.
 blockers.push("trusted_target_attribution_absent","independent_production_false_positive_validation_absent","operator_authorization_required");
 return {mode:"SHADOW_ONLY",forecast_state:feed?.state||"unavailable",sensor_state:feed?.sensor_status?.state||"unavailable",
   supported:event?.supported===true,automatic_containment:false,blockers};
}
if(require.main===module)(async()=>{
 try{
   const r=await fetch(endpoint,{redirect:"error",signal:AbortSignal.timeout(25000)});
   if(!r.ok)throw Error("Feed unavailable");
   console.log(JSON.stringify(assess(await r.json()),null,2));
 }catch{console.log(JSON.stringify(assess(null),null,2));process.exitCode=1;}
})();
module.exports={assess};
