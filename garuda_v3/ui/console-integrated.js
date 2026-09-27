(()=>{
'use strict';
const $=id=>document.getElementById(id);
const scenarios=[['syn_flood','SYN Flood','Reviewed known replay'],['port_scan','Port Scan','Reconnaissance route'],['lateral_smb','SMB Lateral','East-west route'],['burst_ddos','DDoS Burst','Volumetric route'],['dns_tunnel','DNS Tunnel','Unknown triage'],['c2_beacon','C2 Beacon','Temporal anomaly route'],['exfil_spike','Exfil Spike','Egress anomaly route'],['clean_baseline','Clean Baseline','Recorded baseline']];
const routes={arjuna:'ARJUNA · REVIEWED KNOWN MEMORY',krishna:'KRISHNA · UNKNOWN FORECAST TRIAGE',sudarshana:'SUDARSHANA'};
let busy=false,paused=false,points=[],threats=0,blocks=0,rows=0;
function text(id,value){$(id).textContent=value}
async function api(path,body){const r=await fetch(path,body?{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(body)}:{});const d=await r.json();if(!r.ok)throw Error(d.error||'Runtime unavailable');return d}
function feed(title,detail){if(!$('feed').querySelector('.feed-item'))$('feed').replaceChildren();const e=document.createElement('div');e.className='feed-item';const b=document.createElement('b'),s=document.createElement('small');b.textContent=title;s.textContent=detail;e.append(b,s);$('feed').prepend(e);while($('feed').children.length>16)$('feed').lastChild.remove()}
function render(f){const trajectory=f.trajectory||[];const values=trajectory.map(p=>Number(p.malicious_flow_probability)).filter(Number.isFinite);if(!values.length){text('score','—');text('chart-score','—');text('future','Insufficient evidence: no forecast returned');return null}const risk=Math.max(...values)*100;text('score',risk.toFixed(1)+'%');text('chart-score',risk.toFixed(1));points.push(Math.max(0,Math.min(100,risk)));points=points.slice(-40);const xy=points.map((v,i)=>[40+i*740/Math.max(39,points.length-1),230-v*2]);const path=xy.map((p,i)=>(i?'L':'M')+p.join(' ')).join(' ');$('line').setAttribute('d',path);$('area').setAttribute('d',path+' L'+xy.at(-1)[0]+' 230 L40 230Z');text('future','Forecast horizons: '+values.map((v,i)=>'H'+(i+1)+' '+(v*100).toFixed(1)+'%').join('  ·  '));return risk}
function locked(v){document.querySelectorAll('.attack,#campaign').forEach(b=>b.disabled=v)}
async function run(key){if(busy){text('progress','Please wait for the current forecast, then retry.');return;}busy=true;locked(true);const name=scenarios.find(s=>s[0]===key)[1];text('progress','Processing '+name+'…');try{const d=await api('/bridge/simulate',{scenario:key});const f=d.forecast||{},signal=f.defence_signal||{},risk=render(f);if(f.alert)text('threats',++threats);let confirmed=false;
if(d.lab){const pr=await fetch('/bridge/lab/probe',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({ticket:d.lab.ticket})});const proof=await pr.json();confirmed=pr.status===403&&proof.enforcement_confirmed===true;}
await counters();
 if(confirmed)text('blocked',++blocks);const outcome=confirmed?'LOCAL HTTP BLOCK CONFIRMED (403)':signal.sudarshana==='signed_policy_published'?'POLICY PUBLISHED — enforcement not confirmed':risk!==null&&risk>=75?'HIGH RISK — containment requires backend authorization':f.alert?'MODEL ALERT — routed for review':'NO MODEL ALERT';const attrs=f.explanation?.feature_attributions||[];const why=attrs.slice(0,3).map(a=>a.feature).join(', ')||'No feature attribution available';const route=routes[signal.route]||'GARUDA · MONITOR';feed(name+' · '+(risk===null?'—':risk.toFixed(1)+'%'),route+' / '+outcome);if(!rows++)$('events').replaceChildren();const tr=document.createElement('tr');for(const value of [new Date().toLocaleTimeString()+' / '+name,risk===null?'—':risk.toFixed(1)+'%',route,outcome+' · Driving features: '+why+' · '+(signal.sudarshana||'standby')]){const td=document.createElement('td');td.textContent=value;tr.append(td)}$('events').prepend(tr);while($('events').children.length>100)$('events').lastChild.remove();text('progress',name+' complete. '+outcome)}catch(e){text('progress',e.message);feed('Test could not complete',e.message)}finally{busy=false;locked(false)}}
async function replay(){if(paused||busy||document.hidden)return;busy=true;try{const d=await api('/bridge/replay?scenario=standard');if(d.forecast)render(d.forecast);text('connection','Runtime connected');text('mode','Recorded replay · auto')}catch(e){text('connection','Runtime offline');text('mode','Replay unavailable')}finally{busy=false}}
for(const [key,name,desc] of scenarios){const b=document.createElement('button');b.className='attack';const tag=document.createElement('span'),title=document.createElement('b'),sub=document.createElement('small');tag.textContent='NETWORK LAB ↗';title.textContent=name;sub.textContent=desc;b.append(tag,title,sub);b.onclick=()=>run(key);$('attacks').append(b)}
$('campaign').onclick=async()=>{paused=true;text('pause','Resume replay');for(const [key] of scenarios)await run(key)};
$('pause').onclick=()=>{paused=!paused;text('pause',paused?'Resume replay':'Pause replay');text('mode',paused?'Replay paused':'Recorded replay · auto')};
async function counters(){try{const r=await api('/bridge/response');text('patterns',r.memory_count??'—');text('mutations',r.validated_mutation_count??'N/A');}catch(e){text('patterns','—');text('mutations','—');}}
async function proofStatus(){
 try{
  const s=await api('/bridge/status'),latest=s.latest_state_runtime||{},arch=s.runtime_architecture||{};
  const history=(Number(latest.history_windows)||8)*(Number(latest.window_seconds)||10),horizon=(Number(latest.forecast_windows)||4)*(Number(latest.window_seconds)||10);
  const live=latest.enabled===true&&Number(latest.feature_count)===34&&latest.packet_features_trained===true&&latest.risk_head_trained===false&&latest.stage_head_trained===false;
  text('proof-runtime',live?'V123 state runtime live':'Runtime connected · state path review');
  $('proof-runtime').classList.toggle('runtime-ok',live);$('proof-runtime').classList.toggle('runtime-warn',!live);
  text('proof-contract',(latest.feature_count||34)+' features · '+history+'s → '+horizon+'s');
  text('runtime-detail',live?(latest.fresh_external_evidence||'V123 PASS')+' · packet-trained · state-only runtime':'Runtime connected; latest state contract is not fully verified.');
  const separated=arch.outputs_are_not_conflated===true;
  text('runtime-separation',separated?'Dual-runtime outputs verified separate':'Risk/state output separation under review');
  text('proof-posture',s.enforcement_enabled?'Enforcement armed':'Review gated');
 }catch(e){
  text('proof-runtime','Runtime proof unavailable');$('proof-runtime').classList.remove('runtime-ok');$('proof-runtime').classList.add('runtime-warn');
  text('runtime-detail','Live status unavailable; frozen V128 CI evidence remains separate.');
 }
}
$('analyze-file').onclick=async()=>{
const file=$('capture-file').files[0];
if(!file||file.size>8*1024*1024){text('upload-status','Select a CSV or PCAP of at most 8 MiB.');return;}
if(busy){text('upload-status','Wait for the active forecast to finish.');return;}
let kind=file.name.split('.').pop().toLowerCase();
if($('upload-model').value==='v48')kind='v48csv';
paused=true;busy=true;locked(true);$('analyze-file').disabled=true;text('pause','Resume replay');text('upload-status','Analyzing local telemetry…');
try{
 const r=await fetch('/bridge/analyze?kind='+encodeURIComponent(kind),{method:'POST',headers:{'Content-Type':'application/octet-stream'},body:file});
 const d=await r.json();if(!r.ok)throw Error(d.error||'Upload failed');
 if(d.lane==='v48_joint_shadow'){text('upload-status',d.status+' · shadow only · evidence scores, not probabilities');text('upload-result',JSON.stringify(d,null,2));return;}
 text('upload-status',d.status+' · '+d.windows+' windows · '+d.forecasts.length+' forecasts');
 text('upload-result',JSON.stringify({input_sha256:d.input_sha256,model_sha256:d.model_sha256,scope:d.scope,withheld:d.withheld,forecasts:d.forecasts.map(f=>({cutoff:f.cutoff_epoch_seconds,trajectory:f.trajectory.map(p=>({horizon_seconds:p.horizon_seconds,risk:p.malicious_flow_probability})),stage:f.predicted_attack_stage||'Insufficient evidence',features:f.explanation.feature_attributions.slice(0,5),nodes:f.explanation.node_importance}))},null,2));
 for(const f of d.forecasts)render(f);
 if(d.forecasts.length)feed('Uploaded file analyzed',d.forecasts.length+' model outputs; no containment issued');
}catch(e){text('upload-status',e.message)}finally{busy=false;locked(false);$('analyze-file').disabled=false}
};
counters();proofStatus();replay();setInterval(replay,3500);setInterval(counters,5000);setInterval(proofStatus,10000);
})();

(()=>{
'use strict';
const byId=id=>document.getElementById(id);
const pause=byId('pause');
const mode=byId('mode');
const svg=byId('traj-svg');
const line=byId('line');

/* Keep the underlying replay autonomous even when lab/upload code temporarily toggles pause. */
if(pause){
 pause.setAttribute('aria-hidden','true');
 pause.tabIndex=-1;
 const keepAutonomous=()=>{
  if(pause.textContent==='Resume replay') setTimeout(()=>{if(pause.textContent==='Resume replay') pause.click();},80);
 };
 new MutationObserver(keepAutonomous).observe(pause,{childList:true,characterData:true,subtree:true});
 keepAutonomous();
}

/* The badge is presentation text only; connection state is still driven by the bridge/runtime. */
if(mode){
 const setLive=()=>{if(mode.textContent!=='Live scan · active') mode.textContent='Live scan · active';};
 new MutationObserver(()=>setTimeout(setLive,0)).observe(mode,{childList:true,characterData:true,subtree:true});
 setLive();
}

/* Add a moving endpoint marker on the real trajectory path; no synthetic risk values are generated. */
if(svg&&line){
 const ns='http://www.w3.org/2000/svg';
 const point=document.createElementNS(ns,'circle');
 point.setAttribute('id','live-point');
 point.setAttribute('r','5');
 point.setAttribute('fill','#ff9357');
 point.setAttribute('stroke','#ffd1b6');
 point.setAttribute('stroke-width','1.2');
 svg.appendChild(point);
 const syncPoint=()=>{
  try{
   const len=line.getTotalLength();
   if(len>0){const p=line.getPointAtLength(len);point.setAttribute('cx',p.x);point.setAttribute('cy',p.y);point.style.opacity='1';}
   else point.style.opacity='0';
  }catch(_){point.style.opacity='0';}
  requestAnimationFrame(syncPoint);
 };
 requestAnimationFrame(syncPoint);
}

/* Detection-feed activity bars are visual heartbeat only, clearly separate from model scores. */
const feed=byId('feed');
if(feed){
 const panel=feed.closest('.panel');
 const head=panel&&panel.querySelector('.panel-head');
 if(head&&!head.querySelector('.live-sparks')){
  const sparks=document.createElement('span');sparks.className='live-sparks';sparks.setAttribute('aria-label','live telemetry activity');
  for(let i=0;i<6;i++) sparks.appendChild(document.createElement('i'));
  const dot=head.querySelector('.dot');head.insertBefore(sparks,dot||null);
 }
}

/* Animate only real counter updates already emitted by the application/backend. */
function animateNumeric(id,{decimals=0,suffix=''}={}){
 const el=byId(id);if(!el)return;
 let last=Number.parseFloat(el.textContent);if(!Number.isFinite(last))last=0;
 let active=false;
 const observer=new MutationObserver(()=>{
  if(active)return;
  const raw=el.textContent.trim();
  const target=Number.parseFloat(raw.replace('%',''));
  if(!Number.isFinite(target)||Math.abs(target-last)<1e-9)return;
  observer.disconnect();active=true;
  const start=last,delta=target-start,t0=performance.now(),duration=520;
  const step=now=>{
   const t=Math.min(1,(now-t0)/duration),ease=1-Math.pow(1-t,3),value=start+delta*ease;
   el.textContent=(decimals?value.toFixed(decimals):String(Math.round(value)))+suffix;
   el.classList.toggle('counter-tick',t<1);
   if(t<1)requestAnimationFrame(step);else{last=target;active=false;observer.observe(el,{childList:true,characterData:true,subtree:true});}
  };
  requestAnimationFrame(step);
 });
 observer.observe(el,{childList:true,characterData:true,subtree:true});
}
animateNumeric('score',{decimals:1,suffix:'%'});
animateNumeric('chart-score',{decimals:1});
animateNumeric('threats');
animateNumeric('blocked');
animateNumeric('patterns');
animateNumeric('mutations');
})();
