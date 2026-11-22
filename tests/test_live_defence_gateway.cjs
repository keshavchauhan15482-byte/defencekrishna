"use strict";
const test=require("node:test");
const assert=require("node:assert/strict");
const http=require("node:http");
const gateway=require("../api/security-check.js");
const {inspectRequest}=require("../deployment/vercel/defence_gate.js");

const PRIVATE_FIXTURE=Object.freeze({
  id:"demo-private",message:"LOCAL_ONLY_SYNTHETIC_SECRET_NOT_REAL_USER_DATA"
});
const PUBLIC_FIXTURE=Object.freeze({
  id:"demo-public",message:"Public synthetic test record"
});
const CASES=[
  ["baseline","demo-public",200,"ARJUNA"],
  ["sqli", "' OR 1=1--",403,"ARJUNA"],
  ["union","' UNION SELECT password FROM dummy",403,"ARJUNA"],
  ["xss","<script>alert(1)</script>",403,"ARJUNA"],
  ["traversal","../../etc/passwd",403,"ARJUNA"],
  ["unknown_structure","__proto__[isAdmin]",403,"KRISHNA"],
  ["forbidden_private","demo-private",403,"SUDARSHAN"],
  ["missing_fixture","demo-missing",404,"BOUNDARY"],
];

function unprotectedLocalFixture(record){
  // An intentionally vulnerable *test-only* function. It is never imported
  // by production APIs or deployed. It reads ONLY synthetic constant fixtures.
  if(record==="demo-private"||/\bor\s+1=1\b/i.test(record)){
    return {status:200,record:PRIVATE_FIXTURE};
  }
  return {status:200,record:PUBLIC_FIXTURE};
}

function fakeResponse(res){
  const state={status:200,headers:{}};
  return {
    setHeader(k,v){state.headers[k]=v;},
    status(code){state.status=code;return this;},
    json(payload){
      res.writeHead(state.status,{"Content-Type":"application/json",...state.headers});
      res.end(JSON.stringify(payload));
      return this;
    }
  };
}
async function withServer(callback){
  const server=http.createServer((req,res)=>{
    gateway({method:req.method,url:req.url,headers:req.headers},fakeResponse(res))
      .catch(()=>{res.writeHead(503);res.end();});
  });
  await new Promise(resolve=>server.listen(0,"127.0.0.1",resolve));
  try{return await callback("http://127.0.0.1:"+server.address().port);}
  finally{await new Promise(resolve=>server.close(resolve));}
}

test("Unprotected local-only dummy fixture leaks synthetic data; protected gateway denies same probe",async()=>{
  const before=unprotectedLocalFixture("' OR 1=1--");
  assert.equal(before.status,200);
  assert.equal(before.record.id,"demo-private");
  const protectedDecision=inspectRequest({
    method:"GET",url:"/api/security-check?record="+encodeURIComponent("' OR 1=1--"),
    headers:{}
  });
  assert.equal(protectedDecision.status,403);
  assert.equal(protectedDecision.lane,"ARJUNA");
});

test("Real loopback HTTP security exercise: Arjuna, Krishna, Sudarshan and safe baseline",async()=>{
  await withServer(async(base)=>{
    for(const [label,record,expected,lane] of CASES){
      const response=await fetch(base+"/api/security-check?record="+encodeURIComponent(record));
      const body=await response.json();
      assert.equal(response.status,expected,label);
      assert.equal(response.headers.get("X-Krishna-Lane"),lane,label);
      assert.equal(response.headers.get("X-Krishna-Decision"),
        expected===200?"allow":"deny",label);
      assert.equal(body.lane,lane,label);
      assert.equal(body.automatic_ip_lockdown,false,label);
      assert.equal(body.garuda,"SHADOW_ONLY_NOT_BLOCK_AUTHORITY",label);
      assert.equal(JSON.stringify(body).includes(PRIVATE_FIXTURE.message),false,label);
      if(expected===200){
        assert.equal(body.record.id,"demo-public");
        assert.equal(body.record.message,PUBLIC_FIXTURE.message);
      }else{assert.equal(body.record,undefined);}
    }
    let r=await fetch(base+"/api/security-check?record=demo-public",{method:"POST"});
    assert.equal(r.status,405);
    r=await fetch(base+"/api/security-check?record=demo-public&record=demo-private");
    assert.equal(r.status,422);
    r=await fetch(base+"/api/security-check?record=demo-public&unexpected=yes");
    assert.equal(r.status,422);
    r=await fetch(base+"/api/security-check?record="+encodeURIComponent("a".repeat(513)));
    assert.equal(r.status,422);
  });
});

test("A browser cannot choose a privilege lane or override Garuda shadow safety",()=>{
  for(const suffix of ["&lane=allow","&garuda_score=0","&auto_block=false"]){
    const result=inspectRequest({method:"GET",
      url:"/api/security-check?record=demo-private"+suffix,headers:{}});
    assert.equal(result.allowed,false);
    assert.equal(result.status,422);
  }
});

test("No privileged HTTP client header may make dummy private record accessible",async()=>{
  await withServer(async(base)=>{
    const resp=await fetch(base+"/api/security-check?record=demo-private",{
      headers:{"X-Forwarded-For":"127.0.0.1","X-User-Role":"admin",
        "X-Garuda-Risk":"0","Authorization":"Bearer forged"},
    });
    assert.equal(resp.status,403);
    const body=await resp.json();
    assert.equal(body.lane,"SUDARSHAN");
  });
});

test("Vercel rewritten request.query delivers actual record without raw URL search",()=>{
 const request={method:"GET",url:"/api/security-check",headers:{}};
 const publicResult=inspectRequest({...request,query:{record:"demo-public"}});
 assert.equal(publicResult.status,200);
 const malicious=inspectRequest({...request,query:{record:"' OR 1=1--"}});
 assert.equal(malicious.status,403);
 assert.equal(malicious.lane,"ARJUNA");
 const privateResult=inspectRequest({...request,query:{record:"demo-private"}});
 assert.equal(privateResult.status,403);
 assert.equal(privateResult.lane,"SUDARSHAN");
 const mismatch=inspectRequest({...request,
   url:"/api/security-check?record=demo-public",query:{record:"demo-private"}});
 assert.equal(mismatch.status,422);
 const multi=inspectRequest({...request,query:{record:["demo-public","demo-private"]}});
 assert.equal(multi.status,422);
});
