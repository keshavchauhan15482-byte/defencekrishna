"use strict";
const test=require("node:test"),assert=require("node:assert/strict");
const {readBoundedJson}=require("../deployment/vercel/bounded_json.js");
const handler=require("../api/live-events.js");
test("valid UTF-8 split across chunks is decoded correctly",async()=>{
 const bytes=new TextEncoder().encode(JSON.stringify({text:"नमस्ते"}));
 const stream=new ReadableStream({start(c){for(const b of bytes)c.enqueue(Uint8Array.of(b));c.close();}});
 assert.deepEqual(await readBoundedJson(new Response(stream)),{text:"नमस्ते"});
});
test("chunked oversized upstream is cancelled before reading the whole stream",async()=>{
 let cancelled=false;
 const stream=new ReadableStream({pull(c){c.enqueue(new Uint8Array(20));},cancel(){cancelled=true;}});
 await assert.rejects(readBoundedJson(new Response(stream),32),/too large/);
 assert.equal(cancelled,true);
});
test("invalid declared size, malformed JSON and invalid UTF-8 rejected",async()=>{
 await assert.rejects(readBoundedJson(new Response("{}",{headers:{"content-length":"1000"}}),32),/too large/);
 await assert.rejects(readBoundedJson(new Response("{")),SyntaxError);
 await assert.rejects(readBoundedJson(new Response(Uint8Array.of(255))),TypeError);
});
test("unknown continuity is not presented as a gap-free forecast",async()=>{
 const oldFetch=globalThis.fetch,oldUrl=process.env.RENDER_BACKEND_URL,oldToken=process.env.RENDER_VIEWER_TOKEN;
 process.env.RENDER_BACKEND_URL="https://fixture.invalid";
 process.env.RENDER_VIEWER_TOKEN="x".repeat(40);
 try{
  for(const gap of [undefined,null,true,false]){
   globalThis.fetch=async()=>new Response(JSON.stringify({state:"waiting",cursor:0,events:[],gap,site_activity:{source:"first_party_page_requests",total_requests:0,requests_24h:0,last_request_at:null}}));
   const res={code:0,body:null,setHeader(){},status(n){this.code=n;return this;},json(b){this.body=b;return this;}};
   await handler({method:"GET",query:{after:"0"},headers:{}},res);
   assert.equal(res.code,200);
   assert.equal(res.body.gap,gap!==false);
   assert.equal(res.body.automatic_containment,false);
  }
 }finally{
  globalThis.fetch=oldFetch;
  for(const [key,value] of [["RENDER_BACKEND_URL",oldUrl],["RENDER_VIEWER_TOKEN",oldToken]])if(value===undefined)delete process.env[key];else process.env[key]=value;
 }
});
