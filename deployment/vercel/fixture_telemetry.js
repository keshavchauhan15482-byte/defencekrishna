"use strict";
// Metadata from the actual fixture guard only. Never forward payload, identity,
// headers, arbitrary client score or user-supplied event fields.
const {randomUUID}=require("node:crypto");
async function recordFixtureDecision(decision){
 const lane=decision?.lane;
 if(decision?.status!==403||decision.allowed!==false||!["ARJUNA","KRISHNA","SUDARSHAN"].includes(lane))return false;
 const token=process.env.RENDER_ACTIVITY_TOKEN,base=process.env.RENDER_BACKEND_URL;
 if(!token||token.length<32||!base)return false;
 try{
  const url=new URL(base);
  if(url.protocol!=="https:"||url.username||url.password||url.search||url.hash||url.pathname!=="/")return false;
  const r=await fetch(new URL("/api/fixture-decisions/ingest",url),{method:"POST",headers:{Authorization:"Bearer "+token,"Content-Type":"application/json"},body:JSON.stringify({schema:"fixture-denial-v1",request_uuid:randomUUID(),lane}),redirect:"error",signal:AbortSignal.timeout(2500),cache:"no-store"});
  return r.status===202;
 }catch{return false;}
}
module.exports={recordFixtureDecision};
