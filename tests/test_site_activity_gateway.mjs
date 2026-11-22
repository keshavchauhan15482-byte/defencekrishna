import assert from "node:assert/strict";
import test from "node:test";
import {createRequire} from "node:module";

const require=createRequire(import.meta.url);
const handler=require("../api/site-activity.js");
const base="https://krishna-defence-system.vercel.app";
function response(){return {code:0,body:null,headers:{},setHeader(k,v){this.headers[k]=v;},
  status(n){this.code=n;return this;},json(x){this.body=x;return this;}};}
function request(origin=base){return {method:"POST",headers:{
  origin,host:"krishna-defence-system.vercel.app","sec-fetch-site":"same-origin",
  "content-length":"0",
}};}

test("Site request becomes a private metadata-only authenticated event",async()=>{
 const oldFetch=globalThis.fetch, oldUrl=process.env.RENDER_BACKEND_URL,
       oldSecret=process.env.RENDER_ACTIVITY_TOKEN;
 process.env.RENDER_BACKEND_URL="https://krishna-shadow-telemetry.onrender.com";
 process.env.RENDER_ACTIVITY_TOKEN="A".repeat(48);
 let calls=0;
 try{
  globalThis.fetch=async (url,options)=>{
   calls++;
   assert.equal(String(url),"https://krishna-shadow-telemetry.onrender.com/api/site-activity/ingest");
   assert.equal(options.headers.Authorization,"Bearer "+"A".repeat(48));
   const data=JSON.parse(options.body);
   assert.deepEqual(Object.keys(data).sort(),["kind","request_uuid","schema"]);
   assert.equal(data.schema,"krishna-site-activity-v1");
   assert.equal(data.kind,"page_load");
   assert.match(data.request_uuid,/^[a-f0-9]{8}-/);
   return new Response(JSON.stringify({accepted:true}),{status:202});
  };
  let res=response();
  await handler(request(),res);
  assert.equal(res.code,202);
  assert.equal(res.body.recorded,true);
  assert.equal(calls,1);
  assert.equal(res.body.request_uuid,undefined);
  res=response();
  await handler(request("https://evil.example"),res);
  assert.equal(res.code,403);
  res=response();
  await handler({...request(),method:"GET"},res);
  assert.equal(res.code,405);
  res=response();
  await handler({...request(),query:{probe:"<script>alert(1)</script>"}},res);
  assert.equal(res.code,403);
  assert.equal(res.body.lane,"ARJUNA");
  res=response();
  await handler({...request(),query:{test:"safe"}},res);
  assert.equal(res.code,422);
  res=response();
  await handler({...request(),headers:{...request().headers,"content-length":"1024"}},res);
  assert.equal(res.code,413);
  assert.equal(calls,1);
 }finally{
  globalThis.fetch=oldFetch;
  if(oldUrl===undefined)delete process.env.RENDER_BACKEND_URL;
  else process.env.RENDER_BACKEND_URL=oldUrl;
  if(oldSecret===undefined)delete process.env.RENDER_ACTIVITY_TOKEN;
  else process.env.RENDER_ACTIVITY_TOKEN=oldSecret;
 }
});
