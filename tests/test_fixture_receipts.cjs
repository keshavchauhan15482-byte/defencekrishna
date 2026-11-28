"use strict";
const test=require("node:test"),assert=require("node:assert/strict");
const {projectReceipts}=require("../deployment/vercel/fixture_receipts.js");
const {fixtureReason}=require("../deployment/vercel/fixture_telemetry.js");
const now=1760000000;
const fixture=()=>({source:"server_recorded_fixture_denials",scope:"synthetic_fixture_only",observed_at:now,automatic_containment:false,events:[{id:1,observed_at:now-1,lane:"ARJUNA",reason:"SQLI_SIGNATURE",decision:"DENY",status:403,event_prediction_probability:null,private:"not exposed"}]});
test("receipt projection strips untrusted metadata and refuses fabricated prediction",()=>{
 const d=projectReceipts(fixture(),now);assert.equal(d.events[0].reason,"SQLI_SIGNATURE");assert.equal(d.events[0].private,undefined);assert.equal(d.events[0].event_prediction_probability,null);
 for(const patch of [{event_prediction_probability:.99},{lane:"KRISHNA"},{status:200},{reason:"arbitrary input"},{observed_at:now-1801}]){
  const f=fixture();Object.assign(f.events[0],patch);assert.equal(projectReceipts(f,now),null);
 }
 assert.equal(projectReceipts(fixture(),now+61),null);
});
test("coarse reason labels only",()=>{assert.equal(fixtureReason("ARJUNA","XSS_SIGNATURE"),"XSS_SIGNATURE");assert.equal(fixtureReason("SUDARSHAN","SQLI_SIGNATURE"),"UNSPECIFIED_RULE");});

test("global count is independent of the displayed receipt limit",()=>{const f=fixture();f.recorded_denials_30m=20;assert.equal(projectReceipts(f,now).recorded_denials_30m,20);f.recorded_denials_30m=0;assert.equal(projectReceipts(f,now),null);});
