"use strict";
// Read-only audit of the project's own public feed; never generates a policy.
const endpoint="https://krishna-defence-system.vercel.app/bridge/live/events?after=0";
function assess(feed,now=Date.now()/1000){
 const event=Array.isArray(feed?.events)?feed.events.at(-1):undefined;
 const blockers=[];
 const cutoff=event?.cutoff_epoch_seconds;
 const trajectory=event?.trajectory;
 const validTrajectory=Array.isArray(trajectory)&&trajectory.length===4&&
   [10,60].some(step=>trajectory.every((p,i)=>p?.horizon_seconds===step*(i+1)&&
   Number.isFinite(p.malicious_flow_probability)&&p.malicious_flow_probability>=0&&p.malicious_flow_probability<=1));
 const windowOpen=validTrajectory&&Number.isFinite(cutoff)&&cutoff>0&&cutoff<=now&&now<cutoff+trajectory[3].horizon_seconds;
 if(!windowOpen)blockers.push("forecast_horizon_elapsed_or_unverified");
 if(feed?.gap!==false)blockers.push("feed_continuity_unverified");
 if(feed?.state!=="near_live")blockers.push("forecast_not_fresh");
 if(!["capturing","processing"].includes(feed?.sensor_status?.state))blockers.push("sensor_not_active");
 if(event?.supported!==true)blockers.push("runtime_support_unverified");
 if(event?.verified_precompromise!==true)blockers.push("precompromise_evidence_unverified");
 const advisoryEvidenceReady=blockers.length===0;
 // This public projection contains no trusted mapping between a forecast and
 // an HTTP client identity. Never accept arbitrary fields as proof of attribution.
 blockers.push("trusted_target_attribution_absent","independent_production_false_positive_validation_absent","operator_authorization_required");
 return {mode:"SHADOW_ONLY",forecast_state:feed?.state||"unavailable",sensor_state:feed?.sensor_status?.state||"unavailable",
   supported:event?.supported===true,forecast_window_open:windowOpen,
   advisory_evidence_ready:advisoryEvidenceReady,automatic_containment:false,blockers};
}
if(require.main===module)(async()=>{
 try{
   const r=await fetch(endpoint,{redirect:"error",signal:AbortSignal.timeout(25000)});
   if(!r.ok)throw Error("Feed unavailable");
   const report=assess(await r.json());
   console.log(JSON.stringify(report,null,2));
   if(process.argv.includes("--require-advisory-evidence")&&!report.advisory_evidence_ready)process.exitCode=2;
 }catch{console.log(JSON.stringify(assess(null),null,2));process.exitCode=1;}
})();
module.exports={assess};
