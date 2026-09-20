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
$('analyze-file').onclick=async()=>{
const file=$('capture-file').files[0];
if(!file||file.size>8*1024*1024){text('upload-status','Select a CSV or PCAP of at most 8 MiB.');return;}
if(busy){text('upload-status','Wait for the active forecast to finish.');return;}
const kind=file.name.split('.').pop().toLowerCase();
paused=true;busy=true;locked(true);$('analyze-file').disabled=true;text('pause','Resume replay');text('upload-status','Analyzing local telemetry…');
try{
 const r=await fetch('/bridge/analyze?kind='+encodeURIComponent(kind),{method:'POST',headers:{'Content-Type':'application/octet-stream'},body:file});
 const d=await r.json();if(!r.ok)throw Error(d.error||'Upload failed');
 text('upload-status',d.status+' · '+d.windows+' windows · '+d.forecasts.length+' forecasts');
 text('upload-result',JSON.stringify({input_sha256:d.input_sha256,model_sha256:d.model_sha256,scope:d.scope,withheld:d.withheld,forecasts:d.forecasts.map(f=>({cutoff:f.cutoff_epoch_seconds,trajectory:f.trajectory.map(p=>({horizon_seconds:p.horizon_seconds,risk:p.malicious_flow_probability})),stage:f.predicted_attack_stage||'Insufficient evidence',features:f.explanation.feature_attributions.slice(0,5),nodes:f.explanation.node_importance}))},null,2));
 for(const f of d.forecasts)render(f);
 if(d.forecasts.length)feed('Uploaded file analyzed',d.forecasts.length+' model outputs; no containment issued');
}catch(e){text('upload-status',e.message)}finally{busy=false;locked(false);$('analyze-file').disabled=false}
};
counters();replay();setInterval(replay,3500);setInterval(counters,5000);
})();
