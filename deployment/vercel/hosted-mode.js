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

function boot(){
  document.body.classList.add("vercel-shadow-only");
  addHttpTrafficPanel();
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
