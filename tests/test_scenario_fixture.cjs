"use strict";
const test=require("node:test"),assert=require("node:assert/strict");
const {inspectRequest}=require("../deployment/vercel/defence_gate.js");
const {fixtureReason}=require("../deployment/vercel/fixture_telemetry.js");
const {projectReceipts}=require("../deployment/vercel/fixture_receipts.js");
const cases=[["hospital_availability","ARJUNA","DEMO_HOSPITAL_AVAILABILITY"],["hospital_anomaly","KRISHNA","DEMO_HOSPITAL_ANOMALY"],["hospital_private","SUDARSHAN","DEMO_HOSPITAL_PRIVATE"],["syn_flood","ARJUNA","DEMO_SYN_FLOOD"],["port_scan","ARJUNA","DEMO_PORT_SCAN"],["lateral_smb","SUDARSHAN","DEMO_LATERAL_SMB"],["burst_ddos","ARJUNA","DEMO_DDOS_BURST"],["dns_tunnel","KRISHNA","DEMO_DNS_TUNNEL"],["c2_beacon","KRISHNA","DEMO_C2_BEACON"],["exfil_spike","SUDARSHAN","DEMO_EXFIL_SPIKE"]];
test("seven fixed scenario policy denials and one clean allow, no arbitrary execution",()=>{
 for(const [key,lane,reason] of cases){
   const d=inspectRequest({method:"GET",url:"/api/security-check?record=lab-"+key,headers:{}});
   assert.equal(d.status,403);assert.equal(d.engine,"scenario-fixture-policy");assert.equal(d.lane,lane);assert.equal(d.reason,reason);assert.equal(fixtureReason(lane,reason),reason);
   const now=Date.now()/1000;
   assert.equal(projectReceipts({source:"server_recorded_fixture_denials",scope:"synthetic_fixture_only",automatic_containment:false,observed_at:now,events:[{id:1,observed_at:now,lane,reason,decision:"DENY",status:403,event_prediction_probability:null}]},now).events[0].reason,reason);
 }
 const clean=inspectRequest({method:"GET",url:"/api/security-check?record=lab-clean_baseline",headers:{}});
 assert.equal(clean.status,200);assert.equal(clean.allowed,true);
 assert.notEqual(inspectRequest({method:"GET",url:"/api/security-check?record=lab-arbitrary",headers:{}}).engine,"scenario-fixture-policy");
 assert.equal(inspectRequest({method:"POST",url:"/api/security-check?record=lab-syn_flood",headers:{}}).status,405);
});
