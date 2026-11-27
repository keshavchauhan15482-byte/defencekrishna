"use strict";
const test=require("node:test"),assert=require("node:assert/strict");
const {coordinate}=require("../deployment/vercel/garuda_coordination.js");
const at=1760000000;
function fixture(){return {state:"near_live",gap:false,sensor_status:{state:"capturing",sensor_age_seconds:10},events:[{id:7,source:"completed_capture_shadow",operating_mode:"SHADOW_ONLY",automatic_containment:false,cutoff_epoch_seconds:at,trajectory:[10,20,30,40].map(h=>({horizon_seconds:h,malicious_flow_probability:.99})),supported:true,alert:true,verified_precompromise:false}]};}
test("fresh supported model alert requests inspection without granting blocking",()=>{
 const r=coordinate(fixture(),at+1);
 assert.equal(r.state,"INSPECTION_RECOMMENDED");
 assert.equal(r.arjuna,"REVIEW_KNOWN_THREAT_EVIDENCE");
 assert.equal(r.krishna,"REVIEW_ANOMALY_EVIDENCE");
 assert.equal(r.sudarshana,"NO_NEW_CONTAINMENT");
 assert.equal(r.expires_at,at+40);
 assert.equal(r.blocking_authorized,false);
});
test("expired, stale, unsupported, future, invalid and non-alert forecasts withhold",()=>{
 for(const change of [f=>f.state="stale",f=>f.gap=null,f=>f.sensor_status.sensor_age_seconds=90,f=>f.sensor_status.sensor_age_seconds=NaN,f=>f.events[0].supported=false,f=>f.events[0].alert=false,f=>f.events[0].cutoff_epoch_seconds=at+2,f=>f.events[0].trajectory[3].horizon_seconds=240,f=>f.events[0].automatic_containment=true]){
  const f=fixture();change(f);assert.equal(coordinate(f,at+1).state,"WITHHELD");
 }
 assert.equal(coordinate(fixture(),at+40).state,"WITHHELD");
 assert.equal(coordinate(null,at).state,"WITHHELD");
});
test("even a verified forecast or spoofed target cannot authorize containment",()=>{
 const f=fixture();Object.assign(f.events[0],{verified_precompromise:true,target_ip:"192.0.2.1",operator_approved:true});
 const r=coordinate(f,at+1);assert.equal(r.state,"BLOCK_REVIEW_REQUESTED");
 assert.equal(r.sudarshana,"OPERATOR_BLOCK_REVIEW_REQUIRED");assert.equal(r.blocking_authorized,false);
 assert.equal(r.automatic_containment,false);assert.equal(r.target_ip,undefined);
});
test("production gateway strips upstream forged precompromise and policy fields",async()=>{
 const handler=require("../api/live-events.js"),oldFetch=globalThis.fetch,oldUrl=process.env.RENDER_BACKEND_URL,oldToken=process.env.RENDER_VIEWER_TOKEN;
 process.env.RENDER_BACKEND_URL="https://fixture.invalid";process.env.RENDER_VIEWER_TOKEN="x".repeat(40);
 try{
  const f=fixture();f.events[0].cutoff_epoch_seconds=Date.now()/1000-1;Object.assign(f.events[0],{score:99,verified_precompromise:true,target_ip:"192.0.2.1",operator_approved:true});
  f.site_activity={source:"first_party_page_requests",total_requests:0,requests_24h:0,last_request_at:null};
  globalThis.fetch=async()=>new Response(JSON.stringify(f));
  const res={code:0,body:null,setHeader(){},status(n){this.code=n;return this;},json(b){this.body=b;return this;}};
  await handler({method:"GET",query:{after:"0"},headers:{}},res);
  assert.equal(res.code,200);assert.equal(res.body.events[0].verified_precompromise,false);
  assert.equal(res.body.defence_coordination.state,"INSPECTION_RECOMMENDED");
  assert.equal(res.body.defence_coordination.blocking_authorized,false);
 }finally{globalThis.fetch=oldFetch;for(const [k,v] of [["RENDER_BACKEND_URL",oldUrl],["RENDER_VIEWER_TOKEN",oldToken]])if(v===undefined)delete process.env[k];else process.env[k]=v;}
});
