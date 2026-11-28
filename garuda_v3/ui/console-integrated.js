(()=>{
'use strict';
const $=id=>document.getElementById(id);
const scenarios=[['syn_flood','SYN Flood','Reviewed known replay'],['port_scan','Port Scan','Reconnaissance route'],['lateral_smb','SMB Lateral','East-west route'],['burst_ddos','DDoS Burst','Volumetric route'],['dns_tunnel','DNS Tunnel','Unknown triage'],['c2_beacon','C2 Beacon','Temporal anomaly route'],['exfil_spike','Exfil Spike','Egress anomaly route'],['clean_baseline','Clean Baseline','Recorded baseline']];
const routes={arjuna:'ARJUNA · REVIEWED KNOWN MEMORY',krishna:'KRISHNA · UNKNOWN FORECAST TRIAGE',sudarshana:'SUDARSHANA'};
const MAX_POINTS=48;
const MOTION_MS=220;
const SENSOR_POLL_MS=IS_HOSTED_POLL_INTERVAL();
function IS_HOSTED_POLL_INTERVAL(){return document.getElementById('hosting-boundary')?5000:2600;}
// Vercel runs only a cloud telemetry relay; the local Python model endpoints
// (/bridge/status, /bridge/response) must not be checked as cloud health.
const IS_HOSTED_RELAY=!!document.getElementById('hosting-boundary');
let busy=false,points=[],threats=0,blocks=0,rows=0;
let liveTimer=null;
let hasLiveTarget=false;
let lastLiveValue=0;
let targetLiveValue=0;
let lastFutureText='Waiting for forecast horizons…';
let liveCursor=0,livePollBusy=false;
let lastSensorForecast=null;
let hostedForecastEvent=null,hostedFeed=null,hostedClock=null,hostedClockAt=0;
let observedRiskHistory=[];
let lastReceiptSignature=null;
function plotPremium(id,points,color){
 const line=$(id+'-line'),area=$(id+'-area'),dots=$(id+'-dots');
 if(!line||!area||!dots)return;
 const path=points.map((p,i)=>(i?'L':'M')+p.x.toFixed(2)+' '+p.y.toFixed(2)).join(' ');
 line.setAttribute('d',path);
 area.setAttribute('d',points.length>1?path+' L'+points.at(-1).x.toFixed(2)+' 98 L'+points[0].x.toFixed(2)+' 98 Z':'');
 dots.replaceChildren();
 const ns='http://www.w3.org/2000/svg';
 for(const p of points){
  const c=document.createElementNS(ns,'circle');c.setAttribute('cx',p.x);c.setAttribute('cy',p.y);
  c.setAttribute('r',p===points.at(-1)?'3.8':'2.3');c.setAttribute('fill',color);c.setAttribute('stroke','#101722');c.setAttribute('stroke-width','1');
  const t=document.createElementNS(ns,'title');t.textContent=p.label;c.append(t);dots.append(c);
 }
}
const RECEIPT_LABELS={DEMO_SYN_FLOOD:'SYN Flood · demo policy',DEMO_PORT_SCAN:'Port Scan · demo policy',DEMO_LATERAL_SMB:'SMB Lateral · demo policy',DEMO_DDOS_BURST:'DDoS Burst · demo policy',DEMO_DNS_TUNNEL:'DNS Tunnel · demo policy',DEMO_C2_BEACON:'C2 Beacon · demo policy',DEMO_EXFIL_SPIKE:'Exfil Spike · demo policy',SQLI_SIGNATURE:'SQL injection signature',XSS_SIGNATURE:'Cross-site scripting signature',TRAVERSAL_SIGNATURE:'Path traversal signature',COMMAND_SIGNATURE:'Command injection signature',HISTORICAL_DANGER_PATTERN:'Known danger pattern',STRUCTURAL_ANOMALY_REVIEW:'Structural anomaly',HISTORICAL_STRUCTURE_REVIEW:'Historical structural anomaly',FIXTURE_SCOPE_DENIED:'Restricted dummy-record access',UNSPECIFIED_RULE:'Guard rule · reason unavailable'};
function renderDefenceReceipts(d,risk,forecast){
 const root=$('defence-receipts');if(!root)return;
 const ok=d?.source==='server_recorded_fixture_denials'&&d.scope==='synthetic_fixture_only'&&Array.isArray(d.events)&&d.events.length<=12;
 text('defence-feed-status',ok?'Live receipts':'Unavailable');
 const obs=risk?.is_prediction===false&&Number.isSafeInteger(risk.score)?risk.score+'/100':'Unavailable';
 const projected=forecast?.is_attack_probability===false&&Number.isSafeInteger(forecast.score)?forecast.score+'/100':'Unavailable';
 text('defence-feed-context','Current global observed risk: '+obs+' · conditional HTTP +60s: '+projected+' (not tied to any event)');
 const sig=ok?JSON.stringify(d.events):'offline';
 if(sig===lastReceiptSignature)return;lastReceiptSignature=sig;root.replaceChildren();
 if(!ok||!d.events.length){const p=document.createElement('p');p.className='muted';p.textContent=ok?'No recorded fixture denials in the last 30 minutes.':'Receipt feed unavailable; no block claim.';root.append(p);return;}
 for(const e of d.events){
  if(!Object.hasOwn(RECEIPT_LABELS,e.reason)||!['ARJUNA','KRISHNA','SUDARSHAN'].includes(e.lane)||e.decision!=='DENY'||e.status!==403)continue;
  const card=document.createElement('article');card.className='defence-receipt';card.dataset.lane=e.lane;
  const title=document.createElement('div');title.className='receipt-title';
  const name=document.createElement('span');name.textContent=RECEIPT_LABELS[e.reason];
  const badge=document.createElement('span');badge.className='receipt-denied';badge.textContent='BLOCKED · 403';title.append(name,badge);
  const meta=document.createElement('p');meta.className='receipt-meta';meta.textContent='By '+e.lane+' · '+new Date(e.observed_at*1000).toLocaleTimeString()+' · receipt #'+e.id;
  const prediction=document.createElement('p');prediction.className='receipt-prediction';prediction.textContent='Event prediction: unavailable · no verified correlation';
  card.append(title,meta,prediction);root.append(card);
 }
}

function renderHttpForecast(d){
 const valid=d?.source==='recorded_http_traffic_forecast_v1'&&d.condition==='no_new_fixture_denials'&&d.is_attack_probability===false&&Number.isSafeInteger(d.score)&&Array.isArray(d.trajectory)&&d.trajectory.length===4;
 if(!valid){text('http-forecast-score','—');text('http-forecast-status','Unavailable');text('http-forecast-detail','Insufficient history or offline');text('http-forecast-points','Waiting for fresh recorded history.');text('http-forecast-audit','Not an attack probability.');plotPremium('http-forecast',[],'#ff985d');return;}
 text('http-forecast-score',String(d.score));text('http-forecast-detail','Conditional · no new fixture denials');
 text('http-forecast-status',d.method.toUpperCase()+' · experimental');
 text('http-forecast-points',d.trajectory.map(p=>'+'+p.horizon_seconds+'s: '+p.conditional_index+'/100 · '+p.expected_page_requests+' expected page requests').join('  |  '));
 text('http-forecast-audit',d.history_minutes+' closed minutes · '+d.audit_samples+' historical one-step comparisons · EWMA MAE '+d.ewma_mae+' vs persistence '+d.persistence_mae+'. Conditional on no new fixture denials; not an attack probability.');
 plotPremium('http-forecast',d.trajectory.map(p=>({x:34+(p.horizon_seconds-60)*390/240,y:98-p.conditional_index*.88,label:'+'+p.horizon_seconds+'s: '+p.conditional_index+'/100 conditional index'})),'#ff985d');
}
function renderObservedRisk(d){
 const valid=d?.source==='observed_fixture_http_index'&&d.is_prediction===false&&Number.isSafeInteger(d.score)&&d.score>=0&&d.score<=100;
 if(!valid){text('observed-risk-score','—');text('observed-risk-state','Unavailable');text('observed-risk-detail','No verified observation');observedRiskHistory=[];plotPremium('observed-risk',[],'#39d5ff');return;}
 text('observed-risk-score',String(d.score));text('observed-risk-state',d.score>=35?'Elevated fixture activity':'Low observed fixture activity');text('observed-risk-detail',d.denials_recent_minute_buckets+' recent fixture denials · not prediction');
 if(!Number.isFinite(d.observed_at))return;
 if(observedRiskHistory.at(-1)?.at!==d.observed_at)observedRiskHistory.push({at:d.observed_at,score:d.score});
 observedRiskHistory=observedRiskHistory.filter(p=>p.at>=d.observed_at-180&&p.at<=d.observed_at).slice(-36);
 plotPremium('observed-risk',observedRiskHistory.map(p=>({x:424-(d.observed_at-p.at)*390/180,y:98-p.score*.88,label:new Date(p.at*1000).toLocaleTimeString()+' · '+p.score+'/100 observed index'})),'#39d5ff');
}
let scanPhase=0;
const metricAnimations=new Map();

function text(id,value){const el=$(id);if(el)el.textContent=value}
async function api(path,body){const r=await fetch(path,body?{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(body)}:{cache:'no-store',signal:AbortSignal.timeout(25000)});const d=await r.json();if(!r.ok)throw Error(d.error||'Runtime unavailable');return d}

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
 if(!series.length){line.setAttribute('d','');area.setAttribute('d','');const point=$('live-point');if(point)point.style.opacity='0';return;}
 // Each plotted point is a model estimate. Stretch the four REAL forecast
 // horizons across the width instead of leaving a single dot at the edge.
 const denom=Math.max(1,series.length-1);
 const xy=series.map((v,i)=>[40+i*740/denom,230-clampRisk(v)*2]);
 const path=xy.map((p,i)=>(i?'L':'M')+p.join(' ')).join(' ');
 line.setAttribute('d',path);
 area.setAttribute('d',path+' L'+xy.at(-1)[0]+' 230 L'+xy[0][0]+' 230Z');
 const point=$('live-point');
 if(point){const p=xy.at(-1);point.setAttribute('cx',p[0]);point.setAttribute('cy',p[1]);point.style.opacity='1';}
}

// No fake prefilled model scores are allowed on Vercel.
function seedLiveGraph(value){if(!IS_HOSTED_RELAY){points=Array(MAX_POINTS).fill(clampRisk(value));drawPoints(points)}}
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
  // Moving the scan decoration must not manufacture new measurements.
  // Graph points are appended only when a distinct sensor event arrives.
 },MOTION_MS);
}

function render(f,source='lab'){
 const trajectory=f.trajectory||[];
 const values=trajectory.map(p=>Number(p.malicious_flow_probability)*100).filter(Number.isFinite);
 if(!values.length){text('future','Insufficient evidence: no forecast returned');return null;}
 const risk=clampRisk(Math.max(...values));
 lastFutureText='MODEL OUTPUT · future horizons: '+values.map((v,i)=>'+'+String(trajectory[i].horizon_seconds)+'s '+clampRisk(v).toFixed(1)+'%').join('  ·  ');
 text('future',lastFutureText);
 // The global gauge and timeline belong exclusively to real capture events.
 if(source==='sensor'){
  targetLiveValue=risk;
  hasLiveTarget=true;
  lastLiveValue=risk;
  setLiveScore(risk);
  if(IS_HOSTED_RELAY)drawPoints(values);
  else pushLivePoint(risk);
 }
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
 if(busy)return;
 busy=true;
 try{
  const d=await api('/bridge/replay?scenario=standard');
  if(d.forecast)render(d.forecast,'replay');
  text('mode','RECORDED DEMO · NOT LIVE');
  text('live-sensor-message','Recorded replay displayed in forecast details. It is not live traffic.');
 }catch(e){
  text('live-sensor-message','Recorded replay unavailable: '+e.message);
 }finally{busy=false}
}

function refreshHostedForecast(){
 if(!IS_HOSTED_RELAY||!globalThis.KrishnaForecastView)return;
 const now=hostedClock===null?NaN:hostedClock+(performance.now()-hostedClockAt)/1000;
 const feed=hostedFeed?{...hostedFeed,sensor_status:{...hostedFeed.sensor_status,sensor_age_seconds:Number.isFinite(hostedFeed.sensor_status?.sensor_age_seconds)?hostedFeed.sensor_status.sensor_age_seconds+(performance.now()-hostedClockAt)/1000:null}}:null;
 const view=globalThis.KrishnaForecastView.classify(hostedForecastEvent,feed,now);
 const event=hostedForecastEvent,root=$('prediction'),metric=$('score')?.closest('article');
 const runtime=feed?.packet_runtime,heartbeat=feed?.sensor_status;
 const sensorLive=['capturing','processing'].includes(heartbeat?.state)&&Number.isFinite(heartbeat.sensor_age_seconds)&&heartbeat.sensor_age_seconds>=0&&heartbeat.sensor_age_seconds<90;
 text('packet-model-ready',runtime?.status==='ready'?'Checkpoint loaded':runtime?.status==='busy'?'Inference busy':'Not verified');
 text('packet-source-ready',sensorLive?'Authenticated · '+heartbeat.state:heartbeat?.state==='stale'?'Stale heartbeat':'Awaiting authorized source');
 text('packet-support-ready',runtime?.support_gate_configured===true?'Validation gate configured':runtime?.support_gate_configured===false?'Not fitted':'Unknown');
 text('packet-history-ready',Number.isFinite(runtime?.history_seconds)?runtime.history_seconds+'s closed history':'—');
 const blockers=[];
 if(!sensorLive)blockers.push('No fresh authorized packet source');
 if(runtime?.support_gate_configured===false)blockers.push('Cloud checkpoint lacks fitted support gate');
 if(runtime?.status!=='ready')blockers.push('Cloud readiness not verified');
 const archived=event&&Number.isFinite(event.cutoff_epoch_seconds)&&Array.isArray(event.trajectory)&&now>=event.cutoff_epoch_seconds+event.trajectory.at(-1)?.horizon_seconds;
 const status=view.active?'ACTIVE ADVISORY':!feed?.online?'OFFLINE':!sensorLive?'AWAITING FRESH PACKETS':archived?'EXPIRED':view.state;
 if(root)root.dataset.forecastState=view.state;
 if(metric)metric.classList.toggle('forecast-stale',!view.active);
 text('forecast-status',view.active?'ACTIVE ADVISORY':status+' · NO LIVE PREDICTION');
 text('forecast-unavailable',view.active?'':(blockers.length?blockers.join(' · '):view.reason)+'. Packet prediction withheld; HTTP forecast remains independent.');
 text('forecast-cutoff',event&&Number.isFinite(event.cutoff_epoch_seconds)?'Capture: '+new Date(event.cutoff_epoch_seconds*1000).toLocaleString():'');
 text('forecast-expiry',view.active?'Expires in '+Math.max(0,Math.ceil(view.expiresAt-now))+'s':'');
 const label=metric?.querySelector('label'),hint=metric?.querySelector('small');
 if(label)label.textContent=view.active?'PACKET AI ADVISORY SCORE':'PACKET AI FORECAST SCORE';
 if(hint)hint.textContent=view.active?view.reason:status+' · no live packet score';
 const chart=$('traj-svg');
 if(view.active){
   const risk=Math.max(...view.remaining.map(p=>p.malicious_flow_probability))*100;
   setLiveScore(risk);
   text('live-state','SUPPORTED · ADVISORY ONLY');
 }else{
   text('score','—');text('chart-score','—');
   text('live-state',status+' · NOT LIVE');
 }
 if(event&&Array.isArray(event.trajectory)){
   const values=event.trajectory.map(p=>p.malicious_flow_probability*100);
   drawPoints(view.active?values:[]);
   text('future','ARCHIVED MODEL OUTPUT · '+(event.supported?'support flag reported':'input support unverified')+' · '+event.trajectory.map(p=>'+'+p.horizon_seconds+'s '+(p.malicious_flow_probability*100).toFixed(1)+'%').join(' · '));
   text('packet-horizons',view.active?view.remaining.map(p=>'+'+p.horizon_seconds+'s: '+(p.malicious_flow_probability*100).toFixed(1)+'%').join(' · '):'');
 }else{
   drawPoints([]);text('future','No archived model result.');text('packet-horizons','');
 }
 if(chart)chart.setAttribute('aria-label',view.active?'Supported advisory model forecast horizons':'No active forecast; archived model values are textual only');
}
async function pollLive(){
 if(livePollBusy||document.hidden)return;
 livePollBusy=true;
 try{
  const d=await api('/bridge/live/events?after='+liveCursor);
  if(IS_HOSTED_RELAY){
   if(!Number.isSafeInteger(d.cursor)||d.cursor<0||!Number.isFinite(d.server_epoch_seconds))throw Error('Invalid cloud forecast clock or cursor');
   if(d.cursor<liveCursor){liveCursor=0;hostedForecastEvent=null;lastSensorForecast=null;}
   hostedClock=d.server_epoch_seconds;hostedClockAt=performance.now();
   hostedFeed={online:true,state:d.state,gap:d.gap,sensor_status:d.sensor_status,packet_runtime:d.packet_runtime};
   renderObservedRisk(d.fixture_risk);
   renderHttpForecast(d.http_forecast);
   renderDefenceReceipts(d.fixture_receipts,d.fixture_risk,d.http_forecast);
   const heartbeat=d.sensor_status||{};
   document.dispatchEvent(new CustomEvent('krishna:sensor-status',{detail:{
     backend:'online',
     sensor:['absent','capturing','processing','stale'].includes(heartbeat.state)?
       heartbeat.state:'absent',
     captureSeconds:Number.isSafeInteger(heartbeat.capture_seconds)?
       heartbeat.capture_seconds:null,
     sensorAge:Number.isFinite(heartbeat.sensor_age_seconds)?
       heartbeat.sensor_age_seconds:null,
     forecast:['waiting','near_live','stale','disabled'].includes(d.state)?
       d.state:'waiting',
     forecastAge:Number.isFinite(d.sensor_age_seconds)?d.sensor_age_seconds:null
   }}));
  }
  if(d.site_activity && d.site_activity.is_model_input===false){
   document.dispatchEvent(new CustomEvent('krishna:site-activity',{detail:d.site_activity}));
  }
  if(d.gap)feed('Sensor event gap','Older samples expired from bounded in-memory event feed');
  for(const event of d.events||[]){
   if(event.id<=liveCursor)continue;
   liveCursor=event.id;
   if(event.kind!=='forecast')continue;
   if(IS_HOSTED_RELAY)hostedForecastEvent=event;
   else render({trajectory:event.trajectory},'sensor');
   lastSensorForecast={score:event.score,supported:event.supported===true,
     cutoffEpoch:event.cutoff_epoch_seconds,id:event.id};
   if(IS_HOSTED_RELAY){
     document.dispatchEvent(new CustomEvent('krishna:forecast-received',{detail:{
       id:event.id,score:event.score,supported:event.supported===true,
       alert:event.alert===true,cutoffEpoch:event.cutoff_epoch_seconds
     }}));
   }
   if(event.alert&&(!IS_HOSTED_RELAY||globalThis.KrishnaForecastView?.classify(event,hostedFeed,hostedClock).active)){threats+=1;animateMetric('threats',threats);}
   const scope=event.supported?'Support flag reported':'UNVERIFIED INPUT SUPPORT';
   feed('Sensor capture · '+event.score.toFixed(1)+'%','Advisory shadow forecast · '+scope+' · No automatic action');
   if(!rows++)$('events').replaceChildren();
   const tr=document.createElement('tr');
   for(const value of [new Date(event.cutoff_epoch_seconds*1000).toLocaleTimeString()+' / SENSOR',
      event.score.toFixed(1)+'%','GARUDA · SHADOW',
      'Completed PCAP/CSV capture · '+scope+' · NO CONTAINMENT']){
     const td=document.createElement('td');td.textContent=value;tr.append(td);
   }
   $('events').prepend(tr);while($('events').children.length>100)$('events').lastChild.remove();
  }
  if(IS_HOSTED_RELAY){
    const metric=$('score')?.closest('article');
    const metricLabel=metric?.querySelector('label');
    const metricHint=metric?.querySelector('small');
    if(metricLabel)metricLabel.textContent=lastSensorForecast?
      'LAST MODEL ESTIMATE':'FORECAST · AWAITING CAPTURE';
    if(metricHint)metricHint.textContent=!lastSensorForecast?
      'No forecast received; sensor heartbeat is separate':
      (lastSensorForecast.supported?'Input support reported':'INPUT SUPPORT UNVERIFIED')+
      (d.state==='stale'?' · HISTORICAL / STALE':
        d.state==='near_live'?' · recent capture':' · not live');
    if(metric)metric.classList.toggle('forecast-stale',
      Boolean(lastSensorForecast)&&d.state!=='near_live');
    const chart=$('traj-svg');
    if(chart)chart.setAttribute('aria-label',lastSensorForecast?
      'Four genuine future risk horizon estimates from the last completed PCAP; '+
        (d.state==='stale'?'stale; ':'')+
        (lastSensorForecast.supported?'input support reported':'input support unverified'):
      'Waiting for real model forecast; no fabricated graph points');
    const observed=$('threats')?.closest('article')?.querySelector('small');
    if(observed)observed.textContent='Advisory flags · not confirmed attacks';
  }
  const states={
    disabled:['Sensor not configured','DISABLED · NO LIVE DATA'],
    waiting:['Waiting for completed capture','WAITING FOR SENSOR'],
    stale:['Sensor data stale','STALE · LAST CAPTURE'],
    near_live:['Near-live sensor connected','NEAR-LIVE · SHADOW ONLY'],
  };
  const pair=states[d.state]||states.waiting;
  if(IS_HOSTED_RELAY){
   const heartbeat=d.sensor_status||{},present=heartbeat.state==='capturing'||heartbeat.state==='processing';
   const cloudState=d.state==='near_live'?'Backend linked · real capture received':
     present?'Backend linked · sensor '+heartbeat.state:
     d.state==='stale'?'Backend linked · forecast stale':'Backend linked · waiting for sensor';
   text('connection',cloudState);
   text('mode',d.state==='near_live'?'RENDER CONNECTED · SHADOW AI':
     present?'RENDER CONNECTED · SENSOR '+heartbeat.state.toUpperCase():
     'RENDER CONNECTED · SENSOR WAITING');
   text('proof-runtime',present?'Render online · packet sensor '+heartbeat.state:
     'Render telemetry connected · PostgreSQL available');
   text('runtime-detail',present?
     'Authorized packet sensor last heartbeat '+heartbeat.sensor_age_seconds+'s ago; '+heartbeat.capture_seconds+'s capture batches. Garuda forecasts appear only after a completed compatible capture.':
     'Cloud relay is online. Garuda inference requires a separate authorized packet sensor; recorded replay is not live.');
   text('proof-posture','SHADOW ONLY · NO AUTO BLOCK');
   const proof=$('proof-runtime');
   if(proof){proof.classList.add('runtime-ok');proof.classList.remove('runtime-warn');}
  }else{
   text('connection',pair[0]);
   text('mode',pair[1]);
  }
  text('live-sensor-message',
       d.state==='near_live'?'Last authenticated capture received '+d.sensor_age_seconds+'s ago. Advisory only; no automatic containment.':
       d.state==='stale'?'No recent sensor capture. Last update '+d.sensor_age_seconds+'s ago; existing score is historical.':
       d.state==='disabled'?'Set GARUDA_LIVE_SENSOR_TOKEN and start the local live_publisher. Auto-replay is disabled.':
       IS_HOSTED_RELAY&&['capturing','processing'].includes(d.sensor_status?.state)?
       'Private sensor is '+d.sensor_status.state+' real packets ('+d.sensor_status.capture_seconds+'s batches). No model output has been fabricated.':
       'No real captures received yet. Auto-replay is disabled.');
  text('live-state',
    d.state==='near_live'?'NEW CLOSED-CAPTURE MODEL FORECAST · ADVISORY':
    d.state==='stale'?'STALE LAST FORECAST · LIVE SENSOR STATUS SEPARATE':
    IS_HOSTED_RELAY&&['capturing','processing'].includes(d.sensor_status?.state)?
    'Real packet sensor '+d.sensor_status.state+' · awaiting forecast':pair[1]);
  if(IS_HOSTED_RELAY)refreshHostedForecast();
 }catch(e){
  if(IS_HOSTED_RELAY){
   document.dispatchEvent(new CustomEvent('krishna:sensor-status',{detail:{backend:'offline',sensor:'unavailable',forecast:'unavailable'}}));
  }
  text('connection',IS_HOSTED_RELAY?'Render telemetry unavailable':'Sensor feed offline');
  text('mode','OFFLINE · NO LIVE DATA');
  if(IS_HOSTED_RELAY){
   text('proof-runtime','Render telemetry unavailable');
   text('runtime-detail','Cloud API health check failed. Historical model evidence is separate; live model output is not confirmed.');
   const proof=$('proof-runtime');
   if(proof){proof.classList.remove('runtime-ok');proof.classList.add('runtime-warn');}
  }
  if(IS_HOSTED_RELAY&&lastSensorForecast){
    const metric=$('score')?.closest('article');
    if(metric)metric.classList.add('forecast-stale');
    const hint=metric?.querySelector('small');
    if(hint)hint.textContent='Cloud feed offline · last score historical';
  }
  text('live-sensor-message','Live endpoint unavailable: '+e.message);
  if(IS_HOSTED_RELAY){hostedFeed=null;refreshHostedForecast();renderObservedRisk(null);renderHttpForecast(null);renderDefenceReceipts(null,null,null);}
 }finally{livePollBusy=false}
}

function addSensorPanel(){
 const root=document.createElement('section');root.id='live-telemetry';root.className='panel';
 root.innerHTML='<div class="panel-head"><div><span class="eyebrow">NEAR-LIVE TELEMETRY · SHADOW ONLY</span><h2>Real capture sensor status</h2></div><button type="button" id="manual-replay" class="primary">Recorded demo (manual)</button></div><p class="muted" id="live-sensor-message">Checking local sensor feed… No data is simulated.</p><p class="muted">A completed capture must contain genuine recent timestamps. Forecasts are advisory and cannot authorize Arjuna, Krishna or Sudarshana containment.</p>';
 const metrics=document.querySelector('.metrics');
 if(metrics)metrics.after(root);
 else document.querySelector('main')?.prepend(root);
 const demo=$('manual-replay');if(demo)demo.onclick=replay;
 const alertLabel=$('threats')?.closest('article')?.querySelector('label');
 if(alertLabel)alertLabel.textContent=IS_HOSTED_RELAY?
   'ADVISORY MODEL FLAGS':'MODEL ALERTS · LAB + SENSOR';
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

addSensorPanel();
startLiveGraph();
if(IS_HOSTED_RELAY){
 text('patterns','—');
 text('mutations','—');
 text('proof-runtime','Checking Render telemetry relay');
 text('runtime-detail','The cloud relay delivers stored metadata; the trained Garuda model remains on an authorized capture sensor.');
 text('proof-posture','SHADOW ONLY · NO AUTO BLOCK');
}else{
 counters();
 proofStatus();
 setInterval(counters,5000);
 setInterval(proofStatus,10000);
}
pollLive();
setInterval(pollLive,SENSOR_POLL_MS);
if(IS_HOSTED_RELAY)setInterval(refreshHostedForecast,1000);
})();
