"use strict";
const test=require("node:test"),assert=require("node:assert/strict");
const {run}=require("../scripts/verify_hosted_pilot.cjs");
test("exactly four fixed sequential read-only checks; edge denial is not application proof",async()=>{
 const urls=[];
 const report=await run(async(url,options)=>{
  urls.push(url);assert.equal(options.method,"GET");assert.equal(options.redirect,"error");
  if(url.includes("demo-private"))return new Response(JSON.stringify({reason:"edge denied"}),{status:403});
  if(url.includes("live/events"))return new Response(JSON.stringify({automatic_containment:false,site_activity:{source:"first_party_page_requests"}}));
  return new Response(JSON.stringify({decision:"ALLOW",record:{id:"demo-public"}}));
 });
 assert.equal(urls.length,4);assert.ok(urls.every(u=>u.startsWith("https://krishna-defence-system.vercel.app/")));
 assert.equal(report.rows[1].verified,false);assert.equal(report.checks_passed,false);assert.equal(report.forecast.automatic_containment,false);
});
