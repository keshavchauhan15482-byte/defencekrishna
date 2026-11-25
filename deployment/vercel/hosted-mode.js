(()=>{
"use strict";
// This is the public static frontend, NOT the original private Python console.
// Public site must not pretend that its recorded attack lab is running.
function setDisabled(id,reason){
  const el=document.getElementById(id);
  if(!el)return;
  el.disabled=true;
  el.setAttribute("aria-disabled","true");
  el.title=reason;
}

function addHttpTrafficPanel(){
  if(document.getElementById("http-activity-panel"))return;
  const panel=document.createElement("section");
  panel.id="http-activity-panel";
  panel.className="panel";
  panel.setAttribute("aria-label","Real website HTTP request activity");
  panel.innerHTML='<div class="panel-head"><div><span class="eyebrow">ACTUAL WEBSITE HTTP ACTIVITY · NOT AI FORECASTS</span><h2>Observed requests</h2></div><span id="http-activity-status" class="pill">Checking telemetry</span></div><div style="display:flex;gap:26px;flex-wrap:wrap;margin:16px 0"><div><small>RECORDED PAGE REQUESTS</small><div id="http-activity-total" style="font-size:30px">—</div></div><div><small>LAST 24 HOURS</small><div id="http-activity-day" style="font-size:30px">—</div></div><div><small>LAST RECORDED REQUEST</small><div id="http-activity-last" style="font-size:20px">—</div></div></div><p class="muted">Only anonymous page-load request counts are stored in a separate PostgreSQL table. No IPs, cookies, device IDs or packet contents. These counts are not unique visitors, attacks, or input to the trained Garuda model.</p>';
  const existing=document.getElementById("live-telemetry");
  if(existing)existing.after(panel);
  else document.querySelector("main")?.prepend(panel);
  document.addEventListener("krishna:site-activity",event=>{
    const d=event.detail;
    if(!d||d.is_model_input!==false)return;
    const total=Number(d.total_requests),day=Number(d.requests_24h);
    if(!Number.isSafeInteger(total)||total<0||!Number.isSafeInteger(day)||day<0)return;
    document.getElementById("http-activity-total").textContent=total.toLocaleString();
    document.getElementById("http-activity-day").textContent=day.toLocaleString();
    document.getElementById("http-activity-last").textContent=
      d.last_request_at==null?"Not recorded":new Date(Number(d.last_request_at)*1000).toLocaleString();
    document.getElementById("http-activity-status").textContent="Persisted · PostgreSQL";
  });
}
async function recordFirstPartyPageRequest(){
  const el=document.getElementById("http-activity-status");
  try{
    const r=await fetch("/api/site-activity",{
      method:"POST",credentials:"same-origin",cache:"no-store",
    });
    if(!r.ok)throw Error("not accepted");
    if(el)el.textContent="Page request saved";
  }catch{
    if(el)el.textContent="Activity storage offline";
  }
}


// Cloud health comes from the authenticated relay response, not a local sensor.
function addCloudMonitoringPanel(){
  if(document.getElementById("cloud-monitoring-panel"))return;
  const panel=document.createElement("section");
  panel.id="cloud-monitoring-panel";
  panel.className="panel";
  panel.setAttribute("aria-label","Cloud-only website monitoring");
  panel.innerHTML='<div class="panel-head"><div><span class="eyebrow">CLOUD-ONLY WEBSITE MONITORING</span><h2>Live hosted service status</h2></div><span class="pill" id="cloud-monitoring-state">Checking cloud</span></div>'
    +'<div class="ops-grid"><article><small>REQUESTS · LAST 5 MIN</small><strong id="cloud-recent">—</strong></article><article><small>PREVIOUS 5 MIN</small><strong id="cloud-prior">—</strong></article><article><small>LAST SUCCESSFUL POLL</small><strong id="cloud-last">—</strong></article></div>'
    +'<p class="muted">Counts come from persisted first-party page-load requests. No Mac or local setup is required for hosted monitoring and existing server-side request guards. This is not total ingress traffic, attack detection, or Garuda packet-model input. Packet forecasts remain optional and separately labeled; without a supported capture there is no fresh packet forecast.</p>';
  const existing=document.getElementById("http-activity-panel");
  if(existing)existing.after(panel);else document.querySelector("main")?.prepend(panel);
  const set=(id,value)=>{const el=panel.querySelector("#"+id);if(el)el.textContent=value;};
  const count=n=>Number.isSafeInteger(n)&&n>=0?n.toLocaleString():"Unavailable";
  document.addEventListener("krishna:site-activity",ev=>{
    const d=ev.detail;
    if(!d||d.is_model_input!==false)return;
    set("cloud-recent",count(d.requests_5m));
    set("cloud-prior",count(d.requests_previous_5m));
    set("cloud-last",new Date().toLocaleTimeString());
    set("cloud-monitoring-state","Cloud telemetry online");
  });
  document.addEventListener("krishna:sensor-status",ev=>{
    if(ev.detail?.backend!=="online"){
      set("cloud-monitoring-state","Cloud feed unavailable");
      set("cloud-recent","Unavailable");set("cloud-prior","Unavailable");
    }
  });
}

// The hosted Attack Lab is a browser-only educational walkthrough. The real
// /bridge/simulate and /bridge/lab/probe routes belong to the PRIVATE lab and
// must not be called on Vercel or represented as executed attacks or results.
// Keep the order matched to console-integrated.js's eight fixed scenario cards.
const DEFENCE_WALKTHROUGHS=Object.freeze([
  {key:"syn_flood",name:"SYN Flood",category:"Known-pattern review",
   signal:"Many SYN attempts with few completed handshakes",
   observe:"Check SYN-to-ACK balance, incomplete connections and affected service capacity.",
   assess:"Correlate packet timing and known signatures; require genuine Garuda evidence before giving any risk score.",
   respond:"Arjuna: review a scoped rate-limit or block rule with an authorized operator."},
  {key:"port_scan",name:"Port Scan",category:"Reconnaissance",
   signal:"One source probing multiple ports or destinations",
   observe:"Examine unique destination ports, sequential probes and legitimate discovery activity.",
   assess:"Check whether probes form a sustained scan rather than a harmless admin task.",
   respond:"Analyst review and a narrow allowlist-aware policy; no automatic action."},
  {key:"lateral_smb",name:"SMB Lateral",category:"East–west investigation",
   signal:"Unusual SMB connections between internal hosts",
   observe:"Review service destinations, timing and whether the hosts belong to an approved workflow.",
   assess:"A service connection alone does not prove lateral movement or compromise.",
   respond:"Escalate to a defender for authentication and endpoint evidence."},
  {key:"burst_ddos",name:"DDoS Burst",category:"Volumetric traffic",
   signal:"A burst of traffic directed at a service",
   observe:"Review bursts in packets/sec, source diversity, flow counts and service health.",
   assess:"Separate legitimate flash crowds from attack-labelled samples using independent evidence.",
   respond:"Review rate limits or upstream protection; this website sends no attack traffic."},
  {key:"dns_tunnel",name:"DNS Tunnel",category:"Unknown-pattern triage",
   signal:"Repeated DNS requests with unusual subdomain patterns",
   observe:"Check query lengths, repetition and destination resolvers with normal baselines.",
   assess:"Unusual DNS content is an investigation lead, not proof of tunnelling.",
   respond:"Krishna: route unfamiliar signals for analyst triage, not silent learning or blocking."},
  {key:"c2_beacon",name:"C2 Beacon",category:"Temporal anomaly",
   signal:"Near-periodic outbound connections",
   observe:"Check inter-arrival times, duration, destination stability and approved background jobs.",
   assess:"Confirm with host/process evidence before claiming command and control.",
   respond:"Investigate destination context; containment requires a reviewed policy."},
  {key:"exfil_spike",name:"Exfil Spike",category:"Egress investigation",
   signal:"A sudden rise in outbound bytes",
   observe:"Inspect per-host egress rates, service destination and authorized transfers.",
   assess:"Do not equate high volume with exfiltration without independent evidence.",
   respond:"Review user/data context and authorize any restricted egress policy separately."},
  {key:"clean_baseline",name:"Clean Baseline",category:"Control scenario",
   signal:"Stable expected network activity",
   observe:"Compare ordinary flow volume, services and temporal variation.",
   assess:"Check for unexplained changes; do not label baseline traffic malicious.",
   respond:"No intervention. Continue monitoring and keep false-positive controls in view."}
]);

function addHostedDefenceLab(){
  const lab=document.getElementById("lab");
  const cards=document.querySelectorAll("#attacks button");
  if(!lab||cards.length!==DEFENCE_WALKTHROUGHS.length||
     document.getElementById("hosted-defence-lab"))return;
  const eyebrow=lab.querySelector(".panel-head .eyebrow");
  if(eyebrow)eyebrow.textContent="02 / INTERACTIVE DEFENCE WALKTHROUGH";
  const heading=lab.querySelector(".panel-head h2");
  if(heading)heading.textContent="Explore the attack scenarios.";
  const intro=lab.querySelector(":scope > p.muted");
  if(intro)intro.textContent=
    "Click any scenario to inspect its defensive signals, investigation and gated response. Browser-only dry run: no attack packets, trained-model inference, blocked requests, or sensor telemetry are generated by these buttons.";

  const panel=document.createElement("section");
  panel.id="hosted-defence-lab";
  panel.className="hosted-lab-detail";
  panel.setAttribute("aria-label","Interactive defensive scenario walkthrough");
  panel.innerHTML='<div class="hosted-lab-top"><span class="hosted-lab-pill">BROWSER DEMO · NOT LIVE DATA</span><span id="hosted-lab-selection">Choose a scenario above</span></div>'
    +'<h3 id="hosted-lab-title">Explore a defender workflow</h3>'
    +'<p id="hosted-lab-description" class="muted">The cards above open a safe, interactive explanation of the selected scenario. No requests are sent to an attack endpoint.</p>'
    +'<div class="hosted-lab-steps">'
    +'<article><small>01 · OBSERVE</small><p id="hosted-lab-observe">Select a scenario</p></article>'
    +'<article><small>02 · ASSESS</small><p id="hosted-lab-assess">Evidence must be checked</p></article>'
    +'<article><small>03 · REVIEW RESPONSE</small><p id="hosted-lab-respond">No automatic containment</p></article></div>'
    +'<p class="hosted-lab-boundary">DEMO BOUNDARY · No real SYN flood, scan, DDoS, malware traffic, Garuda prediction, firewall block, or database event is created by clicking. Real model forecasts appear only in the independent sensor panels.</p>'
    +'<div id="hosted-lab-campaign" aria-live="polite"></div>';
  const attackGrid=document.getElementById("attacks");
  attackGrid.after(panel);
  const value=(id,content)=>{
    const el=panel.querySelector("#"+id);
    if(el)el.textContent=content;
  };
  const progress=document.getElementById("progress");
  let chosen=-1;
  function selectScenario(index,fromCampaign=false){
    if(!Number.isInteger(index)||index<0||index>=DEFENCE_WALKTHROUGHS.length)return;
    chosen=index;
    const s=DEFENCE_WALKTHROUGHS[index];
    cards.forEach((button,i)=>{
      button.classList.toggle("hosted-demo-selected",i===index);
      button.setAttribute("aria-pressed",i===index?"true":"false");
    });
    value("hosted-lab-selection",(index+1)+"/"+DEFENCE_WALKTHROUGHS.length+" · "+s.category);
    value("hosted-lab-title",s.name+" · defender walkthrough");
    value("hosted-lab-description","Scenario label: "+s.signal+". Example investigation path only; no packets or predictions generated.");
    value("hosted-lab-observe",s.observe);
    value("hosted-lab-assess",s.assess);
    value("hosted-lab-respond",s.respond);
    if(progress)progress.textContent=
      "BROWSER DEMO · "+s.name+" selected. This does not run the private attack lab, alter real sensor charts, or count as a blocked attack.";
    if(!fromCampaign)panel.querySelector("#hosted-lab-campaign").replaceChildren();
  }
  cards.forEach((button,i)=>{
    button.disabled=false;
    button.removeAttribute("aria-disabled");
    button.title="Open safe browser-only defensive walkthrough — no attack traffic";
    // Overwrite the local-only /bridge/simulate handler installed earlier.
    button.onclick=()=>selectScenario(i);
    const tag=button.querySelector("span");
    if(tag)tag.textContent="DEFENDER DEMO ↗";
  });
  const campaign=document.getElementById("campaign");
  if(campaign){
    campaign.disabled=false;
    campaign.removeAttribute("aria-disabled");
    campaign.textContent="Explore all 8 scenarios ↗";
    campaign.title="Review all eight defensive scenarios, without network attacks";
    campaign.onclick=()=>{
      selectScenario(0,true);
      const list=document.createElement("ol");
      list.className="hosted-lab-campaign-list";
      for(const [i,s] of DEFENCE_WALKTHROUGHS.entries()){
        const li=document.createElement("li");
        const button=document.createElement("button");
        button.type="button";
        button.textContent=s.name+" · "+s.category;
        button.onclick=()=>selectScenario(i,true);
        li.append(button);
        list.append(li);
      }
      const root=panel.querySelector("#hosted-lab-campaign");
      root.replaceChildren(list);
      panel.scrollIntoView({behavior:"smooth",block:"center"});
      if(progress)progress.textContent=
        "BROWSER DEMO · Eight defensive walkthroughs loaded. Zero attack traffic, zero real model calls, zero containment.";
    };
  }
  const replay=document.getElementById("manual-replay");
  if(replay){
    replay.disabled=false;
    replay.removeAttribute("aria-disabled");
    replay.textContent="Open scenario demo ↗";
    replay.title="Open browser-only defence walkthrough; not a PCAP replay";
    replay.onclick=()=>{
      selectScenario(chosen>=0?chosen:0);
      lab.scrollIntoView({behavior:"smooth",block:"start"});
    };
  }
  if(progress)progress.textContent=
    "Interactive defence walkthrough ready · 8 scenarios. DEMO ONLY — no attack traffic or Garuda inference on click.";
}


// Live evidence observability: heartbeats and forecasts are distinct facts.
// A refresh timer changes "age since verified heartbeat", not model values.
// A pulse is logged only when the authenticated Render heartbeat moves forward.
function addOperationalHeartbeatPanel(){
  if(document.getElementById("operational-heartbeat"))return;
  const panel=document.createElement("section");
  panel.id="operational-heartbeat";
  panel.className="panel ops-live-panel";
  panel.setAttribute("aria-label","Verified network sensor heartbeat and model freshness");
  panel.innerHTML='<div class="panel-head"><div><span class="eyebrow">LIVE OPERATIONAL TELEMETRY · REAL RENDER SENSOR HEARTBEATS</span><h2>Optional packet-model research feed</h2></div><span id="ops-heartbeat-pill" class="ops-state-pill">Checking backend</span></div>'
    +'<p class="muted">This panel updates from authenticated local sensor heartbeats. It is separate from Garuda forecasts; the model score changes only when a completed PCAP is actually processed.</p>'
    +'<div class="ops-grid">'
    +'<article><small>CAPTURE WORKER</small><strong id="ops-worker">Checking</strong><span id="ops-worker-detail">No verified packet status yet</span></article>'
    +'<article><small>LAST VERIFIED HEARTBEAT</small><strong id="ops-heartbeat-age">—</strong><span>Updated by sensor ~every 30 seconds</span></article>'
    +'<article><small>LAST MODEL FORECAST</small><strong id="ops-forecast-age">—</strong><span id="ops-forecast-detail">No prediction received</span></article>'
    +'<article><small>FORECAST INPUT SUPPORT</small><strong id="ops-support">—</strong><span>Not a confirmed attack classification</span></article></div>'
    +'<div class="ops-pulse-head"><span>Authenticated heartbeat observations <b id="ops-observation-count">0</b> (this browser tab)</span><span id="ops-pulse-caption">No heartbeat recorded</span></div>'
    +'<div id="ops-heartbeat-trace" class="ops-heartbeat-trace" role="img" aria-label="Observed authenticated sensor heartbeats; each lit tick is a genuine new heartbeat"></div>'
    +'<div class="ops-age-track"><span id="ops-age-fill"></span></div>'
    +'<p class="ops-proof-note" id="ops-proof-note">Waiting for a genuine sensor heartbeat. There is no synthetic packet count, attack alert, or prediction animation.</p>';
  const metrics=document.querySelector(".metrics");
  if(metrics)metrics.after(panel);
  else document.querySelector("main")?.prepend(panel);
  const $=id=>panel.querySelector("#"+id);
  const history=[];
  let lastHeartbeatTimestamp=null;
  let lastPoll=null;
  let lastForecast=null;
  let baseAge=null;
  let observedAt=0;
  function put(id,value){const el=$(id);if(el)el.textContent=value;}
  function age(base){return Number.isFinite(base)?Math.max(0,base+(Date.now()-observedAt)/1000):null;}
  function render(){
    const d=lastPoll||{};
    const live=d.backend==="online"&&(d.sensor==="capturing"||d.sensor==="processing")&&
      age(baseAge)!==null&&age(baseAge)<90;
    panel.classList.toggle("ops-is-online",live);
    panel.classList.toggle("ops-is-offline",!live);
    put("ops-heartbeat-pill",live?"SENSOR "+d.sensor.toUpperCase()+" · VERIFIED":
      d.backend==="offline"?"CLOUD FEED OFFLINE":
      d.sensor==="stale"?"SENSOR HEARTBEAT STALE":"AWAITING SENSOR");
    put("ops-worker",live?d.sensor.toUpperCase():
      d.sensor==="stale"?"STALE":d.backend==="offline"?"OFFLINE":"NOT CONNECTED");
    put("ops-worker-detail",live?
      "Authorized local network sensor · "+d.captureSeconds+"-second completed batches":
      "No currently verified fresh capture process");
    const hb=age(baseAge);
    put("ops-heartbeat-age",hb===null?"—":Math.floor(hb)+"s ago");
    const fb=d.forecast==="waiting"||d.forecast==="disabled"?null:age(d.forecastAge);
    put("ops-forecast-age",fb===null?"—":Math.floor(fb)+"s ago");
    put("ops-forecast-detail",!lastForecast?"Waiting for completed model output":
      (fb!==null&&fb>120?"STALE last estimate":"Last closed-capture estimate")+
        " · "+lastForecast.score.toFixed(1)+"% advisory");
    put("ops-support",lastForecast?
      (lastForecast.supported?"REPORTED":"UNVERIFIED"):"AWAITING");
    put("ops-observation-count",String(history.length));
    put("ops-pulse-caption",history.length?
      "Latest actual heartbeat at "+new Date(history[history.length-1]).toLocaleTimeString():
      "No heartbeat recorded");
    const fill=$("ops-age-fill");
    if(fill)fill.style.width=hb===null?"0%":Math.min(100,hb/30*100).toFixed(1)+"%";
    put("ops-proof-note",live?
      "Packet capture process is alive. Age bar tracks seconds since the last VERIFIED heartbeat; it resets only on a new authenticated heartbeat. Garuda model outputs arrive only after completed capture batches.":
      d.backend==="offline"?"Render telemetry unreachable. The last prediction, if any, is historical.":
      "No fresh sensor heartbeat. Old risk scores must not be interpreted as live detections.");
  }
  const trace=$("ops-heartbeat-trace");
  function showPulses(){
    if(!trace)return;
    trace.replaceChildren();
    const count=Math.min(history.length,24);
    for(let i=0;i<24;i++){
      const item=document.createElement("span");
      item.className="ops-pulse-tick"+(i<24-count?"":" ops-pulse-observed")+
        (count>0&&i===23?" ops-pulse-new":"");
      item.title=i<24-count?"No observed pulse":"Authenticated heartbeat observed";
      trace.append(item);
    }
  }
  showPulses();
  document.addEventListener("krishna:forecast-received",event=>{
    const d=event.detail||{};
    if(!Number.isFinite(d.score))return;
    lastForecast={score:d.score,supported:d.supported===true};
    render();
  });
  document.addEventListener("krishna:sensor-status",event=>{
    const d=event.detail||{};
    lastPoll=d;
    observedAt=Date.now();
    baseAge=Number.isFinite(d.sensorAge)&&d.sensorAge>=0?d.sensorAge:null;
    // d.sensorAge comes from authenticated heartbeat persisted in PostgreSQL.
    // Repeated browser polls of the SAME heartbeat are not new pulses.
    if(d.backend==="online"&&["capturing","processing","stale"].includes(d.sensor)&&baseAge!==null){
      const estimated=observedAt-baseAge*1000;
      if(lastHeartbeatTimestamp===null||estimated-lastHeartbeatTimestamp>10000){
        lastHeartbeatTimestamp=estimated;
        history.push(estimated);
        if(history.length>24)history.shift();
        showPulses();
      }
    }
    render();
  });
  window.setInterval(render,1000);
  render();
}


// SAFE PUBLIC DEFENCE CHECK: real HTTP status codes from the Vercel backend
// against disposable dummy records. These are intentionally few and bounded:
// no scanning, data exfiltration, destructive SQL, flood or unauthorized users.
function addRealHttpDefenceProof(){
  if(document.getElementById("live-defence-proof"))return;
  const lab=document.getElementById("lab");
  if(!lab)return;
  const root=document.createElement("section");
  root.id="live-defence-proof";
  root.className="panel live-defence-proof";
  root.setAttribute("aria-label","Real HTTP defence tests using synthetic dummy records");
  root.innerHTML='<div class="panel-head"><div><span class="eyebrow">REAL HTTP DEFENCE CHECK · DUMMY RECORDS ONLY</span><h2>Verify actual requests are blocked.</h2></div><span class="pill">SERVER-SIDE RESULTS</span></div>'
   +'<p class="muted">Unlike the browser-only attack walkthrough, these buttons send a few real HTTPS requests to a protected synthetic fixture on this Vercel website. HTTP 403 means this request was denied. It does not prove Garuda predicted the attack or protected unrelated production endpoints.</p>'
   +'<div class="live-defence-actions"><button id="run-safe-http-probes" type="button" class="primary">Run 5 safe HTTP tests ↗</button><span id="live-defence-progress" role="status">Not run yet</span></div>'
   +'<div class="table-wrap"><table><thead><tr><th>TEST (DUMMY INPUT)</th><th>ACTUAL HTTP</th><th>SERVER / EDGE</th><th>RESULT</th></tr></thead><tbody id="live-defence-rows"><tr><td colspan="4">Click to verify actual allow/deny responses on your deployment.</td></tr></tbody></table></div>'
   +'<p class="metric-note">Enforcement lanes: Arjuna = fixed known signatures, Krishna = structural anomaly review, Sudarshan = dummy resource scope control. Garuda is separate shadow-only capture forecasting, not the source of these blocks. No IP lockdown is triggered.</p>';
  lab.after(root);
  const tests=[
   {label:"Benign public dummy",record:"demo-public",expect:200},
   {label:"SQL injection probe",record:"' OR 1=1--",expect:403},
   {label:"Cross-site scripting probe",record:"<script>alert(1)</script>",expect:403},
   {label:"Unknown structure probe",record:"__proto__[isAdmin]",expect:403},
   {label:"Unauthorized dummy record",record:"demo-private",expect:403},
  ];
  const button=root.querySelector("#run-safe-http-probes");
  const rows=root.querySelector("#live-defence-rows");
  const status=root.querySelector("#live-defence-progress");
  button.addEventListener("click",async()=>{
    button.disabled=true;
    rows.replaceChildren();
    let verified=0;
    for(const item of tests){
      const tr=document.createElement("tr");
      const name=document.createElement("td");
      const code=document.createElement("td");
      const lane=document.createElement("td");
      const outcome=document.createElement("td");
      name.textContent=item.label;
      code.textContent="…";
      lane.textContent="Pending";
      outcome.textContent="Waiting";
      tr.append(name,code,lane,outcome);
      rows.append(tr);
      try{
        const response=await fetch("/api/security-check?record="+encodeURIComponent(item.record),{
          method:"GET",credentials:"omit",cache:"no-store",
          signal:AbortSignal.timeout(10000),
        });
        code.textContent=String(response.status);
        const header=response.headers.get("X-Krishna-Lane");
        lane.textContent=header||"EDGE / UNKNOWN";
        const ok=response.status===item.expect;
        outcome.textContent=ok?
          "PASS · actual HTTP response matched":"REVIEW · unexpected HTTP response";
        tr.classList.toggle("live-defence-pass",ok);
        if(ok)verified++;
      }catch{
        code.textContent="Network error";
        lane.textContent="No reliable response";
        outcome.textContent="NOT VERIFIED";
      }
      status.textContent="Completed "+(tests.indexOf(item)+1)+"/"+tests.length+
        " checks; "+verified+" matched expectations";
    }
    status.textContent="HTTP checks verified "+verified+"/"+tests.length+
      "; these prove bounded fixture rules, not full-site attack protection";
    button.disabled=false;
  });
}

function boot(){
  document.body.classList.add("vercel-shadow-only");
  const chartFoot=document.querySelectorAll(".chart-foot span");
  if(chartFoot[0])chartFoot[0].textContent="Actual model horizons from last completed PCAP";
  if(chartFoot[1])chartFoot[1].textContent="Refreshes only when a real forecast arrives · heartbeat above is separate";
  addHttpTrafficPanel();
  addCloudMonitoringPanel();
  addOperationalHeartbeatPanel();
  void recordFirstPartyPageRequest();
  const reason="Unavailable on the Vercel static deployment; run the authorized private Garuda model laboratory separately.";
  // The live sensor feed is supported; arbitrary model upload and recorded
  // attack campaigns require a separate authenticated inference service.
  setDisabled("analyze-file",reason);
  addHostedDefenceLab();
  addRealHttpDefenceProof();
  const status=document.getElementById("upload-status");
  if(status)status.textContent="Model file analysis requires a private inference backend; unavailable on this public static site.";
  // Hosted defence demo updates the lab progress independently. The real
  // capture feed, risk gauge, model counters and event ledger remain untouched.
  const head=document.getElementById("console-build");
  if(head)head.textContent="VERCEL · CLOUD MONITORING";
  const info=document.getElementById("live-sensor-message");
  if(info)info.textContent="Cloud request monitoring runs independently. Packet forecasting is optional and requires genuine supported captures; no replay is used as live traffic.";
}
if(document.readyState==="loading")document.addEventListener("DOMContentLoaded",boot,{once:true});
else boot();
})();
