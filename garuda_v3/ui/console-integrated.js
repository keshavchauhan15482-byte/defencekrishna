(()=>{
'use strict';
const $=id=>document.getElementById(id);
const scenarios=[['syn_flood','SYN Flood','Reviewed known replay'],['port_scan','Port Scan','Reconnaissance route'],['lateral_smb','SMB Lateral','East-west route'],['burst_ddos','DDoS Burst','Volumetric route'],['dns_tunnel','DNS Tunnel','Unknown triage'],['c2_beacon','C2 Beacon','Temporal anomaly route'],['exfil_spike','Exfil Spike','Egress anomaly route'],['clean_baseline','Clean Baseline','Recorded baseline']];
const routes={arjuna:'ARJUNA · REVIEWED KNOWN MEMORY',krishna:'KRISHNA · UNKNOWN FORECAST TRIAGE',sudarshana:'SUDARSHANA'};
const MAX_POINTS=48;
const MOTION_MS=220;
const REPLAY_MS=2600;
let busy=false,points=[],threats=0,blocks=0,rows=0;
let liveTimer=null;
let hasLiveTarget=false;
let lastLiveValue=0;
let targetLiveValue=0;
let lastFutureText='Waiting for forecast horizons…';
let scanPhase=0;
const metricAnimations=new Map();

function text(id,value){const el=$(id);if(el)el.textContent=value}
async function api(path,body){const r=await fetch(path,body?{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(body)}:{});const d=await r.json();if(!r.ok)throw Error(d.error||'Runtime unavailable');return d}

function feed(title,detail){
 const root=$('feed');if(!root)return;
 if(!root.querySelector('.feed-item'))root.replaceChildren();
 const e=document.createElement('div');e.className='feed-item';
 const b=document.createElement('b'),s=document.createElement('small');
 b.textContent=title;s.textContent=detail;e.append(b,s);root.prepend(e);
 while(root.children.length>16)root.lastChild.remove();
}

function clampRisk(value){return Math.max(0,Math.min(100,Number(value)||0))}
function formatMetric(value,decimals,suffix){return (decimals?value.toFixed(decimals):String(Math.round(value)))+suffix}
function animateMetric(id,target,{decimals=0,suffix=''}={}){
 const el=$(id);if(!el)return;
 const numeric=Number(target);
 if(!Number.isFinite(numeric)){
  const existing=metricAnimations.get(id);if(existing)existing.cancelled=true;
  metricAnimations.delete(id);el.textContent=String(target);return;
 }
 const raw=Number.parseFloat(el.textContent.replace('%',''));
 const start=Number.isFinite(raw)?raw:numeric;
 const previous=metricAnimations.get(id);if(previous)previous.cancelled=true;
 if(Math.abs(numeric-start)<1e-9){el.textContent=formatMetric(numeric,decimals,suffix);return;}
 const state={cancelled:false};metricAnimations.set(id,state);
 const t0=performance.now(),duration=520;
 const step=now=>{
  if(state.cancelled)return;
  const t=Math.min(1,(now-t0)/duration),ease=1-Math.pow(1-t,3),value=start+(numeric-start)*ease;
  el.textContent=formatMetric(value,decimals,suffix);
  el.classList.toggle('counter-tick',t<1);
  if(t<1)requestAnimationFrame(step);else{metricAnimations.delete(id);el.classList.remove('counter-tick');}
 };
 requestAnimationFrame(step);
}

function drawPoints(series){
 const line=$('line'),area=$('area');if(!line||!area)return;
 if(!series.length){line.setAttribute('d','');area.setAttribute('d','');return;}
 const denom=Math.max(1,MAX_POINTS-1);
 const xy=series.map((v,i)=>[40+i*740/denom,230-clampRisk(v)*2]);
 const path=xy.map((p,i)=>(i?'L':'M')+p.join(' ')).join(' ');
 line.setAttribute('d',path);
 area.setAttribute('d',path+' L'+xy.at(-1)[0]+' 230 L'+xy[0][0]+' 230Z');
 const point=$('live-point');
 if(point){const p=xy.at(-1);point.setAttribute('cx',p[0]);point.setAttribute('cy',p[1]);point.style.opacity='1';}
}

function seedLiveGraph(value){points=Array(MAX_POINTS).fill(clampRisk(value));drawPoints(points)}
function pushLivePoint(value){points.push(clampRisk(value));if(points.length>MAX_POINTS)points=points.slice(-MAX_POINTS);drawPoints(points)}
function setLiveScore(value){const v=clampRisk(value);text('score',v.toFixed(1)+'%');text('chart-score',v.toFixed(1))}
function updateScanBeam(){
 scanPhase=(scanPhase+0.018)%1;
 const beam=$('scan-line');if(!beam)return;
 const x=40+scanPhase*740;beam.setAttribute('x1',x.toFixed(1));beam.setAttribute('x2',x.toFixed(1));
}

function liveStatus(){
 if(!hasLiveTarget)return 'Scanning network state';
 if(targetLiveValue>=75)return 'Elevated forecast · scanning next state';
 if(targetLiveValue>=40)return 'Temporal drift · evaluating progression';
 return 'Baseline watch · scanning next state';
}

function startLiveGraph(){
 if(liveTimer)return;
 liveTimer=setInterval(()=>{
  updateScanBeam();
  if(document.hidden||!hasLiveTarget)return;
  const delta=targetLiveValue-lastLiveValue;
  lastLiveValue=Math.abs(delta)<0.04?targetLiveValue:lastLiveValue+delta*0.18;
  setLiveScore(lastLiveValue);
  pushLivePoint(lastLiveValue);
  text('live-state',liveStatus());
 },MOTION_MS);
}

function render(f){
 const trajectory=f.trajectory||[];
 const values=trajectory.map(p=>Number(p.malicious_flow_probability)*100).filter(Number.isFinite);
 if(!values.length){text('future','Insufficient evidence: no forecast returned');return null;}
 const risk=clampRisk(Math.max(...values));
 targetLiveValue=risk;
 lastFutureText='Forecast horizons: '+values.map((v,i)=>'H'+(i+1)+' '+clampRisk(v).toFixed(1)+'%').join('  ·  ');
 text('future',lastFutureText);
 if(!hasLiveTarget){hasLiveTarget=true;lastLiveValue=risk;seedLiveGraph(risk);setLiveScore(risk);}
 return risk;
}

function locked(v){document.querySelectorAll('.attack,#campaign').forEach(b=>b.disabled=v)}

async function run(key){
 if(busy){text('progress','Please wait for the current forecast, then retry.');return;}
 busy=true;locked(true);
 const scenario=scenarios.find(s=>s[0]===key),name=scenario?scenario[1]:key;
 text('progress','Processing '+name+'…');
 try{
  const d=await api('/bridge/simulate',{scenario:key});
  const f=d.forecast||{},signal=f.defence_signal||{},risk=render(f);
  if(f.alert){threats+=1;animateMetric('threats',threats);}
  let confirmed=false;
  if(d.lab){
   const pr=await fetch('/bridge/lab/probe',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({ticket:d.lab.ticket})});
   const proof=await pr.json();confirmed=pr.status===403&&proof.enforcement_confirmed===true;
  }
  await counters();
  if(confirmed){blocks+=1;animateMetric('blocked',blocks);}
  const outcome=confirmed?'LOCAL HTTP BLOCK CONFIRMED (403)':signal.sudarshana==='signed_policy_published'?'POLICY PUBLISHED — enforcement not confirmed':risk!==null&&risk>=75?'HIGH RISK — containment requires backend authorization':f.alert?'MODEL ALERT — routed for review':'NO MODEL ALERT';
  const attrs=f.explanation?.feature_attributions||[];
  const why=attrs.slice(0,3).map(a=>a.feature).join(', ')||'No feature attribution available';
  const route=routes[signal.route]||'GARUDA · MONITOR';
  feed(name+' · '+(risk===null?'—':risk.toFixed(1)+'%'),route+' / '+outcome);
  if(!rows++)$('events').replaceChildren();
  const tr=document.createElement('tr');
  for(const value of [new Date().toLocaleTimeString()+' / '+name,risk===null?'—':risk.toFixed(1)+'%',route,outcome+' · Driving features: '+why+' · '+(signal.sudarshana||'standby')]){const td=document.createElement('td');td.textContent=value;tr.append(td)}
  $('events').prepend(tr);while($('events').children.length>100)$('events').lastChild.remove();
  text('progress',name+' complete. '+outcome);
 }catch(e){text('progress',e.message);feed('Test could not complete',e.message)}
 finally{busy=false;locked(false)}
}

async function replay(){
 if(busy||document.hidden)return;
 busy=true;
 try{
  const d=await api('/bridge/replay?scenario=standard');
  if(d.forecast)render(d.forecast);
  text('connection','Runtime connected');text('mode','Live scan · active');text('live-state',liveStatus());
 }catch(e){
  text('connection','Runtime offline');text('mode','Live scan · reconnecting');text('live-state','Waiting for runtime');
 }finally{busy=false}
}

for(const [key,name,desc] of scenarios){
 const b=document.createElement('button');b.className='attack';
 const tag=document.createElement('span'),title=document.createElement('b'),sub=document.createElement('small');
 tag.textContent='NETWORK LAB ↗';title.textContent=name;sub.textContent=desc;b.append(tag,title,sub);b.onclick=()=>run(key);$('attacks').append(b);
}
$('campaign').onclick=async()=>{for(const [key] of scenarios)await run(key)};

async function counters(){
 try{
  const r=await api('/bridge/response');
  animateMetric('patterns',r.memory_count??'—');
  animateMetric('mutations',r.validated_mutation_count??'N/A');
 }catch(e){text('patterns','—');text('mutations','—')}
}

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
 if(!file||file.size>72*1024*1024){text('upload-status','Select a CSV or PCAP of at most 72 MiB.');return;}
 if(busy){text('upload-status','Wait for the active forecast to finish.');return;}
 let kind=file.name.split('.').pop().toLowerCase();
 if($('upload-model').value==='v48')kind='v48csv';
 busy=true;locked(true);$('analyze-file').disabled=true;text('upload-status','Analyzing local telemetry…');
 try{
  const r=await fetch('/bridge/analyze?kind='+encodeURIComponent(kind),{method:'POST',headers:{'Content-Type':'application/octet-stream'},body:file});
  const d=await r.json();if(!r.ok)throw Error(d.error||'Upload failed');
  if(d.lane==='v48_joint_shadow'){text('upload-status',d.status+' · shadow only · evidence scores, not probabilities');text('upload-result',JSON.stringify(d,null,2));return;}
  renderLatestState(d.latest_state_forecast);
  text('upload-status',d.status+' · '+d.windows+' windows · '+d.forecasts.length+' forecasts');
  text('upload-result',JSON.stringify({input_sha256:d.input_sha256,model_sha256:d.model_sha256,scope:d.scope,withheld:d.withheld,forecasts:d.forecasts.map(f=>({cutoff:f.cutoff_epoch_seconds,trajectory:f.trajectory.map(p=>({horizon_seconds:p.horizon_seconds,risk:p.malicious_flow_probability})),stage:f.predicted_attack_stage||'Insufficient evidence',features:f.explanation.feature_attributions.slice(0,5),nodes:f.explanation.node_importance}))},null,2));
  for(const f of d.forecasts)render(f);
  if(d.forecasts.length)feed('Uploaded file analyzed',d.forecasts.length+' model outputs; no containment issued');
 }catch(e){text('upload-status',e.message)}
 finally{busy=false;locked(false);$('analyze-file').disabled=false}
};

function renderLatestState(state){
 if(!state)return;
 text('latest-state-status',state.status+' · state-only model; risk and future-stage heads are not promoted');
 const horizons=state.trajectory||[];
 const feature=(state.feature_names||[]).indexOf('bytes_log');
 const svg=$('latest-state-line');
 if(svg)svg.setAttribute('d',horizons.map((p,i)=>{const value=Number(p.state_vector[feature]);return (i?'L':'M')+(40+i*240)+','+(210-Math.max(0,Math.min(1,value))*180)}).join(' '));
 text('latest-state-detail',JSON.stringify({model:state.model,model_sha256:state.model_sha256,cutoff:state.cutoff_epoch_seconds,observed:state.ingestion,candidate_decision_forecast:state.candidate_decision_forecast,horizons:horizons.map(p=>({seconds:p.horizon_seconds,bytes_log:p.state_vector[feature]})),reason:state.reason,automatic_containment:state.automatic_containment},null,2));
}

startLiveGraph();
counters();proofStatus();replay();
setInterval(replay,REPLAY_MS);
setInterval(counters,5000);
setInterval(proofStatus,10000);
})();
