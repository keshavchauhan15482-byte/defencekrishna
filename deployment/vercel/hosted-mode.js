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


function addSensorActivationPanel(){
  if(document.getElementById("sensor-activation-panel"))return;
  const panel=document.createElement("section");
  panel.className="panel";
  panel.id="sensor-activation-panel";
  panel.setAttribute("aria-label","Activate the genuine authorized packet sensor");
  // Fixed, authored markup only; backend-derived values are always inserted
  // with textContent. No endpoint, user data or secret enters the DOM.
  panel.innerHTML='<div class="panel-head"><div><span class="eyebrow">ACTIVATE GENUINE PCAP SENSOR · LOCAL MAC PERMISSION REQUIRED</span><h2>Start real network forecasting</h2></div><span class="pill" id="sensor-activation-state">Checking sensor status</span></div>'
    +'<p class="muted">Vercel and Render can show real forecasts but cannot access packets from your Mac. Start the separate, authorized packet sensor on a network interface you own or are permitted to monitor. This does not test or attack other websites.</p>'
    +'<div style="display:flex;flex-wrap:wrap;gap:16px;margin:16px 0">'
    +'<div><small>CLOUD BACKEND</small><div id="sensor-activation-backend">Checking</div></div>'
    +'<div><small>LOCAL SENSOR</small><div id="sensor-activation-process">Not started</div></div>'
    +'<div><small>MODEL FORECAST</small><div id="sensor-activation-forecast">No captured forecast</div></div></div>'
    +'<p class="muted">On your Mac Terminal, inside your authorized copy of this GitHub repository:</p>'
    +'<div style="display:flex;align-items:center;gap:12px;flex-wrap:wrap"><code id="sensor-activation-command" style="white-space:normal;overflow-wrap:anywhere;padding:12px;border:1px solid #3d4551;border-radius:8px">bash scripts/start-garuda-sensor-macos.sh</code>'
    +'<button type="button" id="sensor-activation-copy">Copy Mac command</button></div>'
    +'<p class="muted">First-time setup needs a repository clone, a locally entered Render sensor token, and macOS capture permission. The script asks you to confirm your chosen interface. No secret is entered into this website.</p>'
    +'<p><a href="https://github.com/keshavchauhan15482-byte/defencekrishna/blob/main/docs/release/packet_sensor_macos.md" target="_blank" rel="noopener noreferrer">Full one-time Mac setup guide</a></p>'
    +'<p class="muted">Packet-trained Garuda uses 600-second completed captures and 60/120/180/240-second future risk horizons. Sensor heartbeat is not AI detection; original model weights are unchanged.</p>';
  const existing=document.getElementById("live-telemetry");
  if(existing)existing.after(panel);
  else document.querySelector("main")?.append(panel);

  const button=panel.querySelector("#sensor-activation-copy");
  button?.addEventListener("click",async()=>{
    try{
      if(!navigator.clipboard?.writeText)throw Error("Clipboard not available");
      await navigator.clipboard.writeText("bash scripts/start-garuda-sensor-macos.sh");
      button.textContent="Copied";
    }catch{
      button.textContent="Select and copy the command above";
    }
  });
  const set=(id,value)=>{
    const el=panel.querySelector("#"+id);
    if(el)el.textContent=value;
  };
  document.addEventListener("krishna:sensor-status",ev=>{
    const d=ev.detail||{};
    if(d.backend!=="online"){
      set("sensor-activation-backend","Unavailable");
      set("sensor-activation-process","Not verifiable");
      set("sensor-activation-forecast","Not verifiable");
      set("sensor-activation-state","Cloud feed offline");
      return;
    }
    set("sensor-activation-backend","Render + PostgreSQL connected");
    const sensorState=d.sensor;
    const capture=Number.isSafeInteger(d.captureSeconds)?d.captureSeconds+"s batches":"capture interval unknown";
    if(sensorState==="capturing"||sensorState==="processing"){
      set("sensor-activation-process",sensorState+" · "+capture);
      set("sensor-activation-state","Authenticated sensor "+sensorState);
    }else if(sensorState==="stale"){
      set("sensor-activation-process","Last heartbeat stale; recheck Mac");
      set("sensor-activation-state","Sensor heartbeat stale");
    }else{
      set("sensor-activation-process","No authenticated Mac sensor");
      set("sensor-activation-state","Waiting for local capture");
    }
    const forecast=d.forecast;
    set("sensor-activation-forecast",forecast==="near_live"?"Recent real forecast received":
      forecast==="stale"?"Last forecast stale":
      forecast==="waiting"?"No genuine forecast received":"Not available");
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

function boot(){
  document.body.classList.add("vercel-shadow-only");
  addHttpTrafficPanel();
  addSensorActivationPanel();
  void recordFirstPartyPageRequest();
  const reason="Unavailable on the Vercel static deployment; run the authorized private Garuda model laboratory separately.";
  // The live sensor feed is supported; arbitrary model upload and recorded
  // attack campaigns require a separate authenticated inference service.
  setDisabled("analyze-file",reason);
  addHostedDefenceLab();
  const status=document.getElementById("upload-status");
  if(status)status.textContent="Model file analysis requires a private inference backend; unavailable on this public static site.";
  // Hosted defence demo updates the lab progress independently. The real
  // capture feed, risk gauge, model counters and event ledger remain untouched.
  const head=document.getElementById("console-build");
  if(head)head.textContent="VERCEL · SHADOW SENSOR";
  const info=document.getElementById("live-sensor-message");
  if(info)info.textContent="Waiting for Render telemetry relay and an authorized completed-capture sensor. No replay is used as live traffic.";
}
if(document.readyState==="loading")document.addEventListener("DOMContentLoaded",boot,{once:true});
else boot();
})();
