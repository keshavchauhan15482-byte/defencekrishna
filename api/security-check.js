"use strict";
/**
 * Read-only synthetic security fixture. Real HTTP requests reach this function
 * through Vercel; everything under test is fake/dummy and cannot reveal live
 * user records, edit telemetry, write policies or train/promote the ML model.
 */
const {inspectRequest,parseRecord}=require("../deployment/vercel/defence_gate.js");
const {historicalDeny}=require("../deployment/vercel/historical_inspection.js");
const {recordFixtureDecision}=require("../deployment/vercel/fixture_telemetry.js");
const {applySignedContainment}=require("../deployment/vercel/signed_scope.js");
module.exports=async function securityCheck(request,response){
  response.setHeader("Cache-Control","no-store");
  response.setHeader("X-Content-Type-Options","nosniff");
  response.setHeader("Cross-Origin-Resource-Policy","same-origin");
  response.setHeader("Content-Security-Policy","default-src 'none'; frame-ancestors 'none'");
  if(applySignedContainment(request,response,"security-check"))return;
  let decision=inspectRequest(request);
  if(decision.status===404 && decision.reason==="NO_PUBLIC_FIXTURE"){
    const value=parseRecord(request).value;
    const historical=await historicalDeny(value);
    if(historical)decision=historical;
  }
  response.setHeader("X-Krishna-Engine",decision.engine||"bounded-route-guard");
  response.setHeader("X-Krishna-Lane",decision.lane);
  response.setHeader("X-Krishna-Decision",decision.allowed?"allow":"deny");
  // Best-effort aggregate denial receipt; enforcement is independent of telemetry.
  const logged=await recordFixtureDecision(decision);
  response.setHeader("X-Krishna-Fixture-Telemetry",logged?"recorded":"not-recorded");
  // Do not forward source IP, browser cookies, headers, private records, or
  // attack payloads into the Render model/heartbeat PostgreSQL tables.
  return response.status(decision.status).json(decision.allowed?
    {ok:true,record:{id:"demo-public",message:"Public synthetic test record"},
     lane:decision.lane,decision:"ALLOW",source:"REAL_HTTP_DEFENCE_GATE",
     garuda:"SHADOW_ONLY_NOT_BLOCK_AUTHORITY",
     automatic_ip_lockdown:false}:
    {ok:false,lane:decision.lane,decision:"DENY",reason:decision.reason,
     source:"REAL_HTTP_DEFENCE_GATE",
     garuda:"SHADOW_ONLY_NOT_BLOCK_AUTHORITY",
     automatic_ip_lockdown:false});
};