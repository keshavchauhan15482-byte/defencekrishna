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
function boot(){
  document.body.classList.add("vercel-shadow-only");
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
