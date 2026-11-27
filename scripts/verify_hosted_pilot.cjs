"use strict";
// Fixed, read-only first-party production smoke checks. No arbitrary targets,
// fault injection, attack strings, concurrency, retries or production changes.
const {performance}=require("node:perf_hooks");
const {readBoundedJson}=require("../deployment/vercel/bounded_json.js");
const {assess}=require("./check_hosted_readiness.cjs");
const origin="https://krishna-defence-system.vercel.app";
const checks=[
 ["public_dummy","/api/security-check?record=demo-public",200],
 ["restricted_dummy","/api/security-check?record=demo-private",403],
 ["public_dummy_after","/api/security-check?record=demo-public",200],
 ["advisory_feed","/bridge/live/events?after=0",200]
];
async function run(fetcher=fetch){
 const rows=[];let forecast=null;
 for(const [id,path,expected] of checks){
  const started_at=new Date().toISOString(),start=performance.now();
  try{
   const r=await fetcher(origin+path,{method:"GET",redirect:"error",cache:"no-store",signal:AbortSignal.timeout(20000),headers:{Accept:"application/json"}});
   const body=await readBoundedJson(r);
   const engine=r.headers.get("x-krishna-engine");
   const lane=r.headers.get("x-krishna-lane");
   let verified=false;
   if(id==="restricted_dummy")verified=r.status===403&&lane==="SUDARSHAN"&&engine==="bounded-route-guard"&&body?.reason==="FIXTURE_SCOPE_DENIED"&&!Object.hasOwn(body,"record");
   else if(id==="advisory_feed"){
    forecast=assess(body);
    verified=r.status===200&&body?.automatic_containment===false&&body?.site_activity?.source==="first_party_page_requests";
   }else verified=r.status===200&&body?.record?.id==="demo-public"&&body?.decision==="ALLOW";
   rows.push({id,started_at,elapsed_ms:Math.round(performance.now()-start),status:r.status,expected,engine,lane,verified});
  }catch{rows.push({id,started_at,elapsed_ms:Math.round(performance.now()-start),status:null,expected,verified:false,error:"request_or_response_unverified"});}
 }
 return {schema:"krishna-readonly-hosted-audit-v1",observed_at:new Date().toISOString(),origin,request_count:rows.length,rows,checks_passed:rows.every(r=>r.verified),forecast,limitations:["Read-only synthetic fixture and advisory checks only","No attack, downtime, load, customer or enterprise security certification","Forecast and containment readiness are separate gates"]};
}
if(require.main===module)run().then(report=>{console.log(JSON.stringify(report,null,2));if(!report.checks_passed)process.exitCode=1;}).catch(()=>{process.exitCode=1;});
module.exports={run};
