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

function boot(){
  document.body.classList.add("vercel-shadow-only");
  addHttpTrafficPanel();
  addSensorActivationPanel();
  void recordFirstPartyPageRequest();
  const reason="Unavailable on the Vercel static deployment; run the authorized private Garuda model laboratory separately.";
  // The live sensor feed is supported; arbitrary model upload and recorded
  // attack campaigns require a separate authenticated inference service.
  setDisabled("analyze-file",reason);
  setDisabled("campaign",reason);
  setDisabled("manual-replay",reason);
  document.querySelectorAll("#attacks button").forEach(button=>{
    button.disabled=true;
    button.setAttribute("aria-disabled","true");
    button.title=reason;
  });
  const status=document.getElementById("upload-status");
  if(status)status.textContent="Model file analysis requires a private inference backend; unavailable on this public static site.";
  const progress=document.getElementById("progress");
  if(progress)progress.textContent="Recorded Attack Lab disabled in hosted shadow-only mode; no HTTP block is claimed.";
  const head=document.getElementById("console-build");
  if(head)head.textContent="VERCEL · SHADOW SENSOR";
  const info=document.getElementById("live-sensor-message");
  if(info)info.textContent="Waiting for Render telemetry relay and an authorized completed-capture sensor. No replay is used as live traffic.";
}
if(document.readyState==="loading")document.addEventListener("DOMContentLoaded",boot,{once:true});
else boot();
})();
