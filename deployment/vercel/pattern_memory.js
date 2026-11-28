"use strict";
const {projectReceipts}=require("./fixture_receipts.js");
function projectPatternMemory(d,now=Date.now()/1000){
 if(d?.source!=="authenticated_fixture_pattern_memory_v1"||d.scope!=="synthetic_fixture_only"||d.automatic_containment!==false||d.model_retrained!==false||!Number.isFinite(d.observed_at)||Math.abs(now-d.observed_at)>=60||!Array.isArray(d.profiles)||d.profiles.length>20)return null;
 const seen=new Set(),profiles=[];
 for(const p of d.profiles){
   if(!p||p.reason==="UNSPECIFIED_RULE"||!Number.isSafeInteger(p.confirmations)||p.confirmations<1||p.confirmations>8||!Number.isFinite(p.last_seen)||p.last_seen<=0||p.last_seen>d.observed_at)return null;
   if(!projectReceipts({source:"server_recorded_fixture_denials",scope:"synthetic_fixture_only",automatic_containment:false,observed_at:now,events:[{id:1,observed_at:now,lane:p.lane,reason:p.reason,status:403,decision:"DENY",event_prediction_probability:null}]},now))return null;
   const key=p.lane+":"+p.reason,version=1+[2,4,8].filter(n=>p.confirmations>=n).length;
   if(seen.has(key)||p.version!==version||p.review_state!==["new","repeated","established","saturated"][version-1])return null;
   seen.add(key);profiles.push({lane:p.lane,reason:p.reason,confirmations:p.confirmations,version,review_state:p.review_state,last_seen:p.last_seen});
 }
 if(d.patterns_saved!==profiles.length||d.candidate_revisions!==profiles.reduce((n,p)=>n+p.version-1,0))return null;
 return {source:d.source,scope:d.scope,observed_at:d.observed_at,patterns_saved:d.patterns_saved,candidate_revisions:d.candidate_revisions,profiles,automatic_containment:false,model_retrained:false};
}
module.exports={projectPatternMemory};
