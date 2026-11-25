import assert from "node:assert/strict";
import test from "node:test";
import {readFileSync, existsSync} from "node:fs";
import {execFileSync} from "node:child_process";
import {createRequire} from "node:module";
import {dirname,resolve,join} from "node:path";
import {fileURLToPath} from "node:url";

const root=resolve(dirname(fileURLToPath(import.meta.url)),"..");
const require=createRequire(import.meta.url);
const handler=require("../api/live-events.js");

function mockResponse(){
  return {
    code:200,body:null,headers:{},
    setHeader(k,v){this.headers[k]=v;},
    status(code){this.code=code;return this;},
    json(body){this.body=body;return this;},
  };
}
test("Static premium Vercel build preserves the original console and labels unavailable controls",()=>{
  execFileSync(process.execPath,["deployment/vercel/build_site.mjs"],{cwd:root});
  const page=readFileSync(join(root,"public","console.html"),"utf8");
  const source=readFileSync(join(root,"console.html"),"utf8");
  assert.ok(page.includes("See the threat."));
  assert.ok(source.includes("See the threat."));
  assert.ok(page.includes("id=\"hosting-boundary\""));
  assert.ok(page.includes('/console-integrated.js'));
  assert.ok(page.includes('/console-v132-extra.js'));
  assert.ok(page.includes('/hosted-mode.js'));
  const js=readFileSync(join(root,"public","console-integrated.js"),"utf8");
  assert.ok(js.includes("pollLive()"));
  assert.equal(js.includes("setInterval(replay,"),false);
  assert.equal(js.includes("pushLivePoint(lastLiveValue)"),false);
  assert.ok(js.includes("IS_HOSTED_RELAY"));
  assert.ok(js.includes("Backend linked · waiting for sensor"));
  assert.ok(js.includes("Render telemetry connected · PostgreSQL available"));
  assert.ok(js.includes("if(IS_HOSTED_RELAY){"));
  assert.ok(js.includes("proofStatus();")); // still works for the local-only console
  assert.ok(js.includes("setInterval(counters,5000)")); // but only in non-hosted branch
  const hosted=readFileSync(join(root,"public","hosted-mode.js"),"utf8");
  assert.equal(hosted.includes('setDisabled("campaign"'),false);
  assert.ok(hosted.includes('setDisabled("analyze-file"'));
  assert.ok(hosted.includes('addHostedDefenceLab()'));
  assert.ok(hosted.includes('addRealHttpDefenceProof()'));
  assert.ok(hosted.includes('Run 5 safe HTTP tests'));
  assert.ok(hosted.includes('"/api/security-check?record="'));
  assert.ok(hosted.includes('HTTP checks verified'));
  assert.ok(existsSync(join(root,"api","security-check.js")));
  assert.ok(existsSync(join(root,"deployment","vercel","defence_gate.js")));
  assert.ok(handler.toString().includes("checkKnownApiInput"));
  assert.ok(readFileSync(join(root,"api","site-activity.js"),"utf8").includes("checkKnownApiInput"));
  assert.ok(hosted.includes('button.onclick=()=>selectScenario(i)'));
  assert.ok(hosted.includes('campaign.onclick=()=>{'));
  assert.ok(hosted.includes('replay.onclick=()=>{'));
  assert.ok(hosted.includes('BROWSER DEMO · NOT LIVE DATA'));
  assert.ok(hosted.includes('DEFENCE_WALKTHROUGHS.length'));
  assert.equal((hosted.match(/key:"(?:syn_flood|port_scan|lateral_smb|burst_ddos|dns_tunnel|c2_beacon|exfil_spike|clean_baseline)"/g)||[]).length,8);
  const walkthrough=hosted.slice(hosted.indexOf('function addHostedDefenceLab()'),hosted.indexOf('function addRealHttpDefenceProof()'));
  assert.equal(walkthrough.includes('fetch('),false);
  assert.equal(walkthrough.includes('setLiveScore('),false);
  assert.equal(walkthrough.includes('pushLivePoint('),false);
  assert.equal(walkthrough.includes('animateMetric('),false);
  assert.ok(walkthrough.includes('button.disabled=false'));
  assert.ok(walkthrough.includes('campaign.disabled=false'));
  assert.ok(page.includes('Attack scenarios are interactive browser-only defensive walkthroughs'));
  const css=readFileSync(join(root,"public","console-integrated.css"),"utf8");
  assert.ok(css.includes('live-defence-pass'));
  assert.ok(css.includes('hosted-lab-steps'));
  assert.ok(css.includes('hosted-demo-selected'));
  assert.ok(hosted.includes('recordFirstPartyPageRequest()'));
  assert.ok(hosted.includes('addSensorActivationPanel()'));
  assert.ok(hosted.includes('addOperationalHeartbeatPanel()'));
  assert.ok(hosted.includes('LIVE OPERATIONAL TELEMETRY'));
  assert.ok(hosted.includes('ops-heartbeat-age'));
  assert.ok(hosted.includes('ops-forecast-age'));
  assert.ok(hosted.includes('ops-support'));
  assert.ok(hosted.includes('krishna:forecast-received'));
  assert.ok(hosted.includes('krishna:sensor-status'));
  assert.ok(hosted.includes('estimated-lastHeartbeatTimestamp>10000'));
  assert.ok(hosted.includes('d.sensorAge')); // status derives from authenticated Render heartbeat
  assert.equal(hosted.includes('setLiveScore('),false);
  assert.equal(hosted.includes('pushLivePoint('),false);
  assert.ok(hosted.includes('Actual model horizons from last completed PCAP'));
  assert.ok(css.includes('ops-heartbeat-trace'));
  assert.ok(css.includes('forecast-stale'));
  assert.ok(js.includes('if(IS_HOSTED_RELAY)drawPoints(values)'));
  assert.ok(js.includes('LAST MODEL ESTIMATE'));
  assert.ok(js.includes('INPUT SUPPORT UNVERIFIED'));
  assert.ok(js.includes('STALE LAST FORECAST'));
  assert.ok(js.includes('krishna:forecast-received'));
  assert.ok(js.includes("series.length-1"));
  assert.ok(hosted.includes('krishna:sensor-status'));
  assert.ok(hosted.includes('No genuine forecast received'));
  assert.ok(hosted.includes('Copy Mac command'));
  assert.equal(hosted.includes('Bearer '),false);
  assert.ok(js.includes("krishna:sensor-status"));
  assert.ok(hosted.includes('ACTUAL WEBSITE HTTP ACTIVITY'));
  for(const asset of ["console-integrated.css","console-v131-overlay.css",
    "console-v132-extra.css","console-v131-overlay.js","console-v132-extra.js"]){
    assert.ok(existsSync(join(root,"public",asset)));
  }
  const bootstrap=readFileSync(join(root,"scripts/start-garuda-sensor-macos.sh"),"utf8");
  assert.ok(bootstrap.includes("route -n get default"));
  assert.ok(bootstrap.includes("Type AUTHORIZED"));
  assert.ok(bootstrap.indexOf("Type AUTHORIZED")<bootstrap.indexOf("pip install"));
  assert.ok(bootstrap.includes("sudo")===false); // sudo permission is scoped to the Python sensor runner
  assert.ok(bootstrap.includes("--authorized"));
  assert.equal(bootstrap.includes("${EXTRA[@]}"),false);
  assert.equal(bootstrap.includes('EXTRA=()'),false);
  assert.ok(bootstrap.includes('if [[ "$MODE" == "--once" ]]'));
  assert.ok(bootstrap.includes('--interface "$IFACE" --authorized --once'));
  assert.ok(bootstrap.includes('--interface "$IFACE" --authorized'));
  const cfg=JSON.parse(readFileSync(join(root,"vercel.json"),"utf8"));
  assert.ok(cfg.rewrites.some(x=>x.source==="/bridge/live/events"));
});

test("Vercel serverless API never needs browser sensor secrets and sanitizes event fields",async()=>{
  const oldFetch=globalThis.fetch;
  const oldBase=process.env.RENDER_BACKEND_URL;
  const oldToken=process.env.RENDER_VIEWER_TOKEN;
  process.env.RENDER_BACKEND_URL="https://krishna-relay.onrender.com";
  process.env.RENDER_VIEWER_TOKEN="v".repeat(40);
  let requestCount=0;
  try{
    globalThis.fetch=async(url,opts)=>{
      requestCount++;
      assert.equal(String(url),"https://krishna-relay.onrender.com/api/live/events?after=4");
      assert.equal(opts.headers.Authorization,"Bearer "+"v".repeat(40));
      return new Response(JSON.stringify({
        state:"near_live",cursor:5,sensor_age_seconds:1,gap:false,
        sensor_status:{state:"capturing",capture_seconds:600,
          sensor_age_seconds:12,model_sha256:"private-checkpoint"},
        site_activity:{source:"first_party_page_requests",
          total_requests:8,requests_24h:3,last_request_at:1760000000,
          email:"should-not-be-exposed",is_model_input:false},
        events:[{
          id:5,kind:"forecast",capture_sha256:"sensitive-hash",cutoff_epoch_seconds:1760000000,
          trajectory:[10,20,30,40].map(x=>({horizon_seconds:x,malicious_flow_probability:.2,private_metadata:"not-public"})),
          score:20,alert:false,supported:false,
          automatic_containment:false,
        }]
      }),{status:200,headers:{"Content-Type":"application/json"}});
    };
    const req={method:"GET",query:{after:"4"}},res=mockResponse();
    await handler(req,res);
    assert.equal(res.code,200);
    assert.equal(res.body.events.length,1);
    assert.equal(res.body.events[0].capture_sha256,undefined);
    assert.deepEqual(res.body.events[0].trajectory[0],{horizon_seconds:10,malicious_flow_probability:.2});
    assert.equal(res.body.events[0].automatic_containment,false);
    assert.equal(res.body.site_activity.total_requests,8);
    assert.equal(res.body.site_activity.email,undefined);
    assert.equal(res.body.site_activity.is_model_input,false);
    assert.equal(requestCount,1);
    const invalid=mockResponse();
    await handler({method:"GET",query:{after:"invalid"}},invalid);
    assert.equal(invalid.code,422);
    assert.equal(requestCount,1);
    const malicious=mockResponse();
    await handler({method:"GET",query:{after:"' OR 1=1--"}},malicious);
    assert.equal(malicious.code,403);
    assert.equal(malicious.body.lane,"ARJUNA");
    assert.equal(malicious.headers["X-Krishna-Decision"],"deny");
    assert.equal(requestCount,1); // malicious input never reaches Render
    const blocked=mockResponse();
    await handler({method:"POST",query:{}},blocked);
    assert.equal(blocked.code,405);
  }finally{
    globalThis.fetch=oldFetch;
    if(oldBase===undefined)delete process.env.RENDER_BACKEND_URL;
    else process.env.RENDER_BACKEND_URL=oldBase;
    if(oldToken===undefined)delete process.env.RENDER_VIEWER_TOKEN;
    else process.env.RENDER_VIEWER_TOKEN=oldToken;
  }
});

test("Malformed upstream forecast fails closed",async()=>{
 const oldFetch=globalThis.fetch,oldBase=process.env.RENDER_BACKEND_URL,oldToken=process.env.RENDER_VIEWER_TOKEN;
 process.env.RENDER_BACKEND_URL="https://krishna-relay.onrender.com";process.env.RENDER_VIEWER_TOKEN="v".repeat(40);
 try{
  const event={id:1,cutoff_epoch_seconds:1760000000,score:20,automatic_containment:false,
    trajectory:[10,20,30,40].map(x=>({horizon_seconds:x,malicious_flow_probability:.2}))};
  const activity={source:"first_party_page_requests",total_requests:0,requests_24h:0,last_request_at:null};
  for(const invalid of [{...event,score:101},{...event,cutoff_epoch_seconds:"bad"},
    {...event,trajectory:[10,20,30,240].map(x=>({horizon_seconds:x,malicious_flow_probability:.2}))},
    {...event,trajectory:[10,20,30,40].map(x=>({horizon_seconds:x,malicious_flow_probability:1.1}))}]){
   globalThis.fetch=async()=>new Response(JSON.stringify({state:"near_live",cursor:1,events:[invalid],site_activity:activity}));
   const res=mockResponse();await handler({method:"GET",query:{after:"0"}},res);
   assert.equal(res.code,503);assert.equal(res.body.events,undefined);
  }
 }finally{
  globalThis.fetch=oldFetch;
  if(oldBase===undefined)delete process.env.RENDER_BACKEND_URL;else process.env.RENDER_BACKEND_URL=oldBase;
  if(oldToken===undefined)delete process.env.RENDER_VIEWER_TOKEN;else process.env.RENDER_VIEWER_TOKEN=oldToken;
 }
});
