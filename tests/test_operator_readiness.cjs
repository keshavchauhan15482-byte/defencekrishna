"use strict";
const test=require("node:test"),assert=require("node:assert/strict");
const fs=require("node:fs"),os=require("node:os"),path=require("node:path"),http=require("node:http");
const {keygen,proposal,approve,assemble}=require("../scripts/sudarshana_operator.cjs");
const {assess}=require("../scripts/check_hosted_readiness.cjs");
const {scopeMatches}=require("../deployment/vercel/signed_scope.js");
test("Independent local approval artifacts support bounded real HTTP containment rehearsal",async()=>{
 const dir=fs.mkdtempSync(path.join(os.tmpdir(),"krishna-operator-"));
 let server;
 try{
   for(const id of ["alice","bob"])keygen(dir,id);
   assert.equal(fs.statSync(path.join(dir,"alice.private.pem")).mode&0o777,0o600);
   const payload=proposal("security-check","192.0.2.10","fixture_01",60);
   const approvals=["alice","bob"].map(id=>approve(payload,id,path.join(dir,id+".private.pem")));
   const keys=Object.fromEntries(["alice","bob"].map(id=>[id,fs.readFileSync(path.join(dir,id+".public.pem"),"utf8")]));
   const env={...assemble(payload,approvals,keys),VERCEL:"1",VERCEL_ENV:"production"};
   const p=JSON.parse(payload);
   let now=p.issued_at,stopped=false;
   // This is a loopback-only fixture with simulated trusted platform metadata.
   // No caller-supplied forwarding headers influence identity; no real IP blocked.
   server=http.createServer((req,res)=>{
     const route=req.url==="/check"?"security-check":"live-events";
     const platformRequest={headers:{host:"krishna-defence-system.vercel.app","x-vercel-forwarded-for":"192.0.2.10"}};
     const deny=scopeMatches(platformRequest,route,{...env,SUDARSHANA_EMERGENCY_STOP:stopped?"1":"0"},now);
     res.writeHead(deny?403:200);res.end(deny?"Scoped access denied":"Dummy allowed");
   });
   await new Promise(resolve=>server.listen(0,"127.0.0.1",resolve));
   const base="http://127.0.0.1:"+server.address().port;
   assert.equal((await fetch(base+"/check")).status,403);
   assert.equal((await fetch(base+"/other")).status,200);
   stopped=true;
   assert.equal((await fetch(base+"/check")).status,200);
   stopped=false;now=p.expires_at;
   assert.equal((await fetch(base+"/check")).status,200);
   assert.throws(()=>assemble(payload,[approvals[0],approvals[0]],keys));
   assert.throws(()=>assemble(payload.replace("192.0.2.10","192.0.2.11"),approvals,keys));
   assert.throws(()=>proposal("security-check","192.0.2.10","fixture_01",901));
 }finally{
   if(server)await new Promise(resolve=>server.close(resolve));
   fs.rmSync(dir,{recursive:true,force:true});
 }
});
test("Untrusted public forecast fields never authorize containment",()=>{
 const r=assess({state:"near_live",sensor_status:{state:"capturing"},events:[{supported:true,verified_precompromise:true,target_ip:"192.0.2.10",automatic_containment:true}]});
 assert.equal(r.automatic_containment,false);
 assert.ok(r.blockers.includes("trusted_target_attribution_absent"));
 assert.ok(assess(null).blockers.includes("forecast_not_fresh"));
});

test("Forecast horizon expiry and gaps cannot pass advisory readiness",()=>{
 const at=1760000000;
 const feed={state:"near_live",gap:false,sensor_status:{state:"processing"},events:[{
  cutoff_epoch_seconds:at,trajectory:[60,120,180,240].map(h=>({horizon_seconds:h,malicious_flow_probability:.2})),
  supported:true,verified_precompromise:true}]};
 assert.equal(assess(feed,at+239).advisory_evidence_ready,true);
 assert.equal(assess(feed,at+240).advisory_evidence_ready,false);
 assert.equal(assess(feed,at-1).forecast_window_open,false);
 assert.equal(assess({...feed,gap:true},at+10).advisory_evidence_ready,false);
 assert.equal(assess(feed,at+1).automatic_containment,false);
});
