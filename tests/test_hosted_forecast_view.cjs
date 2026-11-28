"use strict";
const test=require("node:test"),assert=require("node:assert/strict"),fs=require("node:fs"),cp=require("node:child_process"),path=require("node:path");
const {classify}=require("../deployment/vercel/forecast-view.js");
const t=1760000000;
const fixture=()=>({event:{cutoff_epoch_seconds:t,supported:true,trajectory:[10,20,30,40].map((h,i)=>({horizon_seconds:h,malicious_flow_probability:.1+i*.2}))},feed:{online:true,gap:false,state:"near_live",sensor_status:{state:"capturing",sensor_age_seconds:2}}});
test("forecast expires by capture timestamp and not delivery time",()=>{
 const {event,feed}=fixture();
 assert.equal(classify(event,feed,t+1).state,"ACTIVE_ADVISORY");
 assert.equal(classify(event,feed,t+20).remaining.length,2);
 assert.equal(classify(event,feed,t+40).state,"EXPIRED");
 assert.equal(classify(event,feed,t-1).state,"INVALID");
});
test("unsupported, stale, disconnected, missing and gapped forecasts cannot become active",()=>{
 for(const [change,state] of [[(e,f)=>e.supported=false,"UNSUPPORTED"],[(e,f)=>f.sensor_status.sensor_age_seconds=90,"STALE"],[(e,f)=>f.gap=null,"GAP"],[(e,f)=>f.state="stale","STALE"],[(e,f)=>f.online=false,"OFFLINE"],[(e,f)=>e.trajectory[0].malicious_flow_probability=1.5,"INVALID"]]){
  const {event,feed}=fixture();change(event,feed);const v=classify(event,feed,t+1);assert.equal(v.state,state);assert.equal(v.active,false);assert.deepEqual(v.remaining,[]);
 }
 assert.equal(classify(null,fixture().feed,t).state,"WAITING");
});
test("60 second model horizons retain actual expiry",()=>{
 const {event,feed}=fixture();event.trajectory=[60,120,180,240].map(h=>({horizon_seconds:h,malicious_flow_probability:.5}));
 assert.equal(classify(event,feed,t+239).remaining.length,1);
 assert.equal(classify(event,feed,t+240).state,"EXPIRED");
});
test("hosted build has compact-only CSS and graph policy before integration",()=>{
 const root=path.resolve(__dirname,"..");
 cp.execFileSync(process.execPath,["deployment/vercel/build_site.mjs"],{cwd:root});
 const page=fs.readFileSync(path.join(root,"public","console.html"),"utf8");
 assert.match(page,/<body[^>]*class="[^"]*hosted-compact/);
 assert.ok(page.includes('id="prediction"')&&page.includes('id="forecast-status"'));
 assert.ok(page.indexOf('/forecast-view.js')<page.indexOf('/console-integrated.js'));
 assert.ok(page.includes('/hosted-compact.css')&&page.includes('id="lab"'));
 const css=fs.readFileSync(path.join(root,"public","hosted-compact.css"),"utf8");
 assert.ok(css.includes(':not(#lab):not(#live-defence-proof)'));
 for(const file of ["console-integrated.js","hosted-mode.js","forecast-view.js"])cp.execFileSync(process.execPath,["--check",path.join(root,"public",file)]);
});

test("compact dashboard keeps actual page activity distinct and hides inactive chart",()=>{
 const root=path.resolve(__dirname,"..");
 cp.execFileSync(process.execPath,["deployment/vercel/build_site.mjs"],{cwd:root});
 const page=fs.readFileSync(path.join(root,"public","console.html"),"utf8"),css=fs.readFileSync(path.join(root,"public","hosted-compact.css"),"utf8"),js=fs.readFileSync(path.join(root,"public","console-integrated.js"),"utf8"),host=fs.readFileSync(path.join(root,"public","hosted-mode.js"),"utf8");
 assert.ok(page.includes('id="compact-request-total"')&&page.includes('id="forecast-unavailable"')&&page.includes('Open Attack Lab'));
 assert.ok(css.includes('not([data-forecast-state="ACTIVE_ADVISORY"]) #traj-svg{display:none}'));
 assert.ok(js.includes('drawPoints(view.active?values:[])'));
 assert.ok(host.includes('count(d.total_requests)')&&host.includes('in last 24h · not attacks'));
});
