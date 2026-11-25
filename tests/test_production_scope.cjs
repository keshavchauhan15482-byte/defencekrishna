"use strict";
const test=require("node:test"),assert=require("node:assert/strict");
const {generateKeyPairSync,sign}=require("node:crypto");
const {historicalDeny}=require("../deployment/vercel/historical_inspection.js");
const {verifiedScope,scopeMatches}=require("../deployment/vercel/signed_scope.js");
const check=require("../api/security-check.js");
const at=1760000000;
function fixture(){
  const a=generateKeyPairSync("ed25519"),b=generateKeyPairSync("ed25519");
  const payload=JSON.stringify({schema:"krishna-scope-v1",audience:"krishna-defence-system.vercel.app",route:"security-check",target_ip:"192.0.2.10",incident_ref:"fixture_01",evidence_kind:"operator_confirmed_escape",issued_at:at-1,expires_at:at+60});
  const approvals=[a,b].map((p,i)=>({key_id:"key"+i,signature:sign(null,Buffer.from(payload),p.privateKey).toString("base64")}));
  const keys=Object.fromEntries([a,b].map((p,i)=>["key"+i,p.publicKey.export({type:"spki",format:"pem"})]));
  const env={VERCEL:"1",VERCEL_ENV:"production",SUDARSHANA_POLICY_MODE:"enforce",SUDARSHANA_APPROVER_KEYS:JSON.stringify(keys),SUDARSHANA_SIGNED_POLICY:JSON.stringify({payload,approvals})};
  const request={headers:{host:"krishna-defence-system.vercel.app","x-vercel-forwarded-for":"192.0.2.10"}};
  return {env,request,payload,approvals,keys};
}
test("two independent signed approvals enforce only the approved IP, route and lifetime",()=>{
  const {env,request}=fixture();
  assert.ok(verifiedScope(env,at));
  assert.equal(scopeMatches(request,"security-check",env,at),true);
  assert.equal(scopeMatches(request,"live-events",env,at),false);
  assert.equal(scopeMatches({...request,headers:{...request.headers,"x-vercel-forwarded-for":"192.0.2.11"}},"security-check",env,at),false);
  assert.equal(scopeMatches({...request,headers:{host:request.headers.host,"x-forwarded-for":"192.0.2.10"}},"security-check",env,at),false);
  assert.equal(scopeMatches(request,"security-check",env,at+60),false);
  assert.equal(scopeMatches(request,"security-check",{...env,SUDARSHANA_EMERGENCY_STOP:"1"},at),false);
  assert.equal(scopeMatches(request,"security-check",{...env,VERCEL_ENV:"preview"},at),false);
});
test("tampering, repeated signing key and disabled policy cannot create a lock",()=>{
  const {env,payload,approvals,keys}=fixture();
  assert.equal(verifiedScope({...env,SUDARSHANA_SIGNED_POLICY:JSON.stringify({payload:payload.replace("192.0.2.10","192.0.2.11"),approvals})},at),null);
  assert.equal(verifiedScope({...env,SUDARSHANA_APPROVER_KEYS:JSON.stringify({...keys,key1:keys.key0}),SUDARSHANA_SIGNED_POLICY:JSON.stringify({payload,approvals:[approvals[0],{...approvals[0],key_id:"key1"}]})},at),null);
  assert.equal(verifiedScope({},at),null);
});
test("passive historical worker recognizes the existing structural fixture without any learned state",async()=>{
  const v='["constructor"]["prototype"]["isAdmin"]';
  const result=await historicalDeny(v);
  assert.equal(result?.status,403);
  assert.equal(result?.engine,"historical-passive");
  const res={headers:{},setHeader(k,v){this.headers[k]=v},status(n){this.code=n;return this},json(x){this.body=x;return this}};
  await check({method:"GET",url:"/api/security-check",query:{record:v},headers:{}},res);
  assert.equal(res.code,403);
  assert.equal(res.headers["X-Krishna-Engine"],"historical-passive");
  assert.equal(res.body.automatic_ip_lockdown,false);
  assert.equal(await historicalDeny("x".repeat(513)),null);
});
