"use strict";
// Metadata from the actual fixture guard only. Never forward payload, identity,
// headers, arbitrary client score or user-supplied event fields.
const {randomUUID}=require("node:crypto");
const REASONS={"ARJUNA":["DEMO_HOSPITAL_AVAILABILITY","DEMO_DDOS_BURST","DEMO_PORT_SCAN","DEMO_SYN_FLOOD","SQLI_SIGNATURE","XSS_SIGNATURE","TRAVERSAL_SIGNATURE","COMMAND_SIGNATURE","HISTORICAL_DANGER_PATTERN","UNSPECIFIED_RULE"],"KRISHNA":["DEMO_HOSPITAL_ANOMALY","DEMO_C2_BEACON","DEMO_DNS_TUNNEL","STRUCTURAL_ANOMALY_REVIEW","HISTORICAL_STRUCTURE_REVIEW","UNSPECIFIED_RULE"],"SUDARSHAN":["DEMO_HOSPITAL_PRIVATE","DEMO_EXFIL_SPIKE","DEMO_LATERAL_SMB","FIXTURE_SCOPE_DENIED","UNSPECIFIED_RULE"]};
function fixtureReason(lane,reason){return REASONS[lane]?.includes(reason)?reason:"UNSPECIFIED_RULE";}
async function recordFixtureDecision(decision){
 const lane=decision?.lane;
 if(decision?.status!==403||decision.allowed!==false||!["ARJUNA","KRISHNA","SUDARSHAN"].includes(lane))return false;
 const token=process.env.RENDER_ACTIVITY_TOKEN,base=process.env.RENDER_BACKEND_URL;
 if(!token||token.length<32||!base)return false;
 try{
  const url=new URL(base);
  if(url.protocol!=="https:"||url.username||url.password||url.search||url.hash||url.pathname!=="/")return false;
  const r=await fetch(new URL("/api/fixture-decisions/ingest",url),{method:"POST",headers:{Authorization:"Bearer "+token,"Content-Type":"application/json"},body:JSON.stringify({schema:"fixture-denial-v2",request_uuid:randomUUID(),lane,reason:fixtureReason(lane,decision.reason)}),redirect:"error",signal:AbortSignal.timeout(2500),cache:"no-store"});
  return r.status===202;
 }catch{return false;}
}
module.exports={recordFixtureDecision,fixtureReason};
