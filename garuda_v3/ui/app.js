'use strict';

const $ = id => document.getElementById(id);
let token = '', role = '', last = null, busy = false, connected = false, responseState = null;
let benchmarkData = null, lastRefreshAt = 0;
const riskHistory = [];
let gaugeCurrent = 0, gaugeTarget = 0;

const pct = v => v == null || !Number.isFinite(Number(v)) ? '—' : (100 * Number(v)).toFixed(1) + '%';
function text(id, value){ const el=$(id); if(el) el.textContent=value; }
function notice(message){ text('noticeText', message); }
function empty(parent, message){ if(!parent) return; parent.replaceChildren(); const d=document.createElement('div'); d.className='emptyRow'; d.textContent=message; parent.append(d); }

async function api(path, body, raw=false){
  const options={headers:{Authorization:'Bearer '+token}};
  if(body!==undefined){
    options.method='POST';
    options.body=raw?body:JSON.stringify(body);
    options.headers['Content-Type']=raw?'application/octet-stream':'application/json';
  }
  const r=await fetch(path,options);
  const d=await r.json();
  if(!r.ok) throw Error(d.error||'Request could not be completed');
  return d;
}
async function run(fn){
  if(busy) return;
  busy=true; document.body.classList.add('busy');
  try{ await fn(); }
  catch(e){ notice(e && e.message ? e.message : 'Operation failed'); }
  finally{ busy=false; document.body.classList.remove('busy'); }
}

async function status(){
  const s=await api('/api/status');
  role=s.role||'';
  const model=s.model||{};
  const horizon=(Number(model.horizon)||0)*(Number(model.window_seconds)||0);
  text('horizon',horizon?horizon+'s':'—');
  text('audit',s.audit_integrity?'AUDIT CHAIN VERIFIED':'AUDIT INTEGRITY FAILURE');
  text('healthState',s.audit_integrity?'Runtime healthy':'Integrity review');
  text('modelState',(model.architecture||model.model_type||'GNN + LSTM').toString().replaceAll('_',' ').toUpperCase());
  text('runtimeMode',s.enforcement_enabled?'ENFORCE':'REVIEW');
  if($('mode') && model.mode) $('mode').value=model.mode;
  for(const id of ['contain','kill','approve','escalate']) if($(id)) $(id).disabled=role!=='operator';

  const policies=Array.isArray(s.policies)?s.policies:[];
  if($('policies')){
    $('policies').replaceChildren();
    for(const p of policies){
      const row=document.createElement('div'); row.className='policyrow';
      const label=document.createElement('span');
      label.textContent=(p.target||'scoped target')+' · expires '+new Date(Number(p.expires||0)*1000).toLocaleTimeString()+' · proxy confirmation required';
      const button=document.createElement('button'); button.textContent='Revoke'; button.disabled=role!=='operator';
      button.onclick=()=>run(async()=>{await api('/api/policy/revoke',{id:p.id});await refresh();notice('Policy revoked.');});
      row.append(label,button); $('policies').append(row);
    }
    if(!policies.length) empty($('policies'),'No active signed policies.');
  }
  lastRefreshAt=Date.now();
  return s;
}

async function response(){
  const r=await api('/api/response'); responseState=r;
  const armed=!!r.armed, events=Array.isArray(r.events)?r.events:[], memory=Array.isArray(r.memory)?r.memory:[];
  text('responseMode',armed?'Lab armed':'Review only');
  text('responseCaption',armed?'Scoped target · '+r.armed.target:'Operator authorization required');
  text('armStatus',armed?'ARMED · '+r.armed.target:'DISARMED');
  if($('arm')) $('arm').disabled=role!=='operator'||!r.lab_enabled;
  if($('disarm')) $('disarm').disabled=role!=='operator'||!armed;
  text('eventCount',events.length+' EVENTS'); text('memoryCount',memory.length+' REVIEWED');
  text('arjunaState',memory.length+' reviewed fingerprints');
  text('krishnaState',events.filter(e=>e.review_status==='pending').length+' pending reviews');
  const newest=events[0];
  document.querySelectorAll('.defenceCard').forEach(el=>el.classList.toggle('highlight',!!newest&&el.dataset.layer===newest.route));
  if(newest){ text('garudaState',newest.forecast_alert?'Forecast signal emitted':'Below alert threshold'); text('sudarshanaState',String(newest.sudarshana||'standing_by').replaceAll('_',' ')); }

  if($('events')){
    $('events').replaceChildren();
    const selected=$('reviewEvent')?.value||'';
    if($('reviewEvent')) $('reviewEvent').replaceChildren(new Option('Select an alert signal',''));
    for(const e of events){
      const row=document.createElement('div'); row.className='event';
      const mark=document.createElement('span'); mark.className='eventMark'; mark.textContent=String(e.route||'?').slice(0,1).toUpperCase();
      const body=document.createElement('div');
      const title=document.createElement('strong'); title.textContent=String(e.route||'unknown').toUpperCase()+' / '+String(e.classification||'unclassified').replaceAll('_',' ');
      const detail=document.createElement('p'); detail.textContent=String(e.sudarshana||'standing_by').replaceAll('_',' ')+(e.target?' · '+e.target:'')+' · '+String(e.id||'').slice(0,8);
      body.append(title,detail);
      const right=document.createElement('div'); const risk=document.createElement('div'); risk.className='risk'; risk.textContent=pct(e.risk);
      const time=document.createElement('time'); time.textContent=new Date(Number(e.created||0)*1000).toLocaleTimeString(); right.append(risk,time);
      row.append(mark,body,right); $('events').append(row);
      if(e.forecast_alert && $('reviewEvent')) $('reviewEvent').append(new Option(String(e.id||'').slice(0,8)+' · '+String(e.route||'')+' · '+pct(e.risk),e.id));
    }
    if(!events.length) empty($('events'),'No recorded signals. Run a capture forecast to begin.');
    if($('reviewEvent')){
      if([...$('reviewEvent').options].some(o=>o.value===selected)) $('reviewEvent').value=selected;
      else if($('reviewEvent').options.length>1) $('reviewEvent').selectedIndex=1;
    }
  }
  if($('memory')){
    $('memory').replaceChildren();
    for(const m of memory){
      const d=document.createElement('div'); d.className='memoryItem'; d.textContent=m.attack_type||'Reviewed threat';
      const small=document.createElement('small'); small.textContent='Exact fingerprint · '+String(m.fingerprint||'').slice(0,20); d.append(small); $('memory').append(d);
    }
    if(!memory.length) empty($('memory'),'No reviewed response fingerprints in this runtime session.');
  }
  lastRefreshAt=Date.now();
  return r;
}
async function refresh(){ await status(); await response(); }

async function evidence(){
  const b=await api('/api/benchmarks'); benchmarkData=b;
  if($('metrics')){
    $('metrics').replaceChildren();
    for(const key of ['logistic_regression','lstm','gnn_lstm']){
      const m=b.models?.[key]; if(!m) continue;
      const tr=document.createElement('tr');
      const values=[key.replaceAll('_',' ').toUpperCase(),...['f1','precision','recall','fpr'].map(k=>pct(m[k]?.mean)+' ± '+((m[k]?.sd||0)*100).toFixed(2)+' pp'),m.state_mse?m.state_mse.mean.toFixed(6)+' ± '+m.state_mse.sd.toFixed(6):'—'];
      for(const v of values){const td=document.createElement('td');td.textContent=v;tr.append(td);} $('metrics').append(tr);
    }
  }
  text('persistenceMse',Number(b.persistence_mse).toFixed(6));
  text('evidenceLimit',b.scope+' Pre-compromise warning is not established. Persistence state MSE '+Number(b.persistence_mse).toFixed(6)+'.');
  drawBenchmarkChart();
  return b;
}

function canvasSize(c){
  const rect=c.getBoundingClientRect(),d=Math.min(devicePixelRatio||1,2);
  const w=Math.max(1,Math.round(rect.width*d)),h=Math.max(1,Math.round(rect.height*d));
  if(c.width!==w||c.height!==h){c.width=w;c.height=h;}
  const ctx=c.getContext('2d'); ctx.setTransform(d,0,0,d,0,0); return [ctx,rect.width,rect.height];
}

/* ---------- 3D topology ---------- */
let graph=null,yaw=.4,pitch=.3,zoom=1,rotating=!matchMedia('(prefers-reduced-motion: reduce)').matches,drag=null,selectedNode=null,projected=[];
function setGraph(g){
  graph=g; selectedNode=null; if($('nodeDetail')) $('nodeDetail').hidden=true;
  if(!g||!Array.isArray(g.mask)||!g.mask.length) return;
  const mask=g.mask.at(-1),adj=g.adj.at(-1),ids=mask.map((v,i)=>v?i:-1).filter(i=>i>=0); let edges=0;
  for(const i of ids) for(const j of ids) if(adj[i][j]>0) edges++;
  text('nodeCount',String(ids.length)); text('nodeCaption',g.mode==='host'?'Actual observed endpoints':'Protocol / service incidence nodes');
  text('graphType',String(g.mode||'service').toUpperCase()+' GRAPH · '+ids.length+' ACTIVE NODES'); text('edgeCount',edges+' observed directed edges');
  const end=(Number(g.times?.at(-1)||0)+Number(g.window_seconds||0))*1000; text('cutoff',end?new Date(end).toISOString().replace('T',' ').slice(0,19)+' UTC':'No observation cutoff');
  if($('graphEmpty')) $('graphEmpty').hidden=true;
  if($('nodeTable')){$('nodeTable').replaceChildren();for(const i of ids){const row=document.createElement('div');row.textContent=(g.node_names?.[i]||'node '+i)+' · incoming weight '+adj[i].reduce((a,b)=>a+b,0);$('nodeTable').append(row);}}
}
function project(x,y,z,w,h){const xx=x*Math.cos(yaw)-z*Math.sin(yaw),zz=x*Math.sin(yaw)+z*Math.cos(yaw),yy=y*Math.cos(pitch)-zz*Math.sin(pitch),depth=y*Math.sin(pitch)+zz*Math.cos(pitch);const scale=470/(640+depth)*zoom;return{x:w/2+xx*scale,y:h*.49+yy*scale,z:depth,scale};}
function drawGraph(){
  const c=$('graph'); if(!c) return; const [ctx,w,h]=canvasSize(c); ctx.clearRect(0,0,w,h);
  const bg=ctx.createRadialGradient(w*.5,h*.44,10,w*.5,h*.5,Math.max(w,h)*.7); bg.addColorStop(0,'rgba(25,55,55,.26)');bg.addColorStop(.45,'rgba(8,20,25,.08)');bg.addColorStop(1,'rgba(3,6,10,0)');ctx.fillStyle=bg;ctx.fillRect(0,0,w,h);
  ctx.lineWidth=.65;ctx.strokeStyle='rgba(90,150,132,.16)';const extent=Math.min(w*.5,330);
  for(let k=-5;k<=5;k++)for(const axis of [0,1]){const a=axis?project(k*58,145,-extent,w,h):project(-extent,145,k*58,w,h),b=axis?project(k*58,145,extent,w,h):project(extent,145,k*58,w,h);ctx.beginPath();ctx.moveTo(a.x,a.y);ctx.lineTo(b.x,b.y);ctx.stroke();}
  if(!graph) return;
  const mask=graph.mask.at(-1),adj=graph.adj.at(-1),ids=mask.map((v,i)=>v?i:-1).filter(i=>i>=0),points={};const radius=Math.min(w*.34,225);
  ids.forEach((id,j)=>{const v=ids.length===1?0:1-2*j/(ids.length-1),r=Math.sqrt(Math.max(0,1-v*v)),angle=j*2.399963;points[id]=project(radius*r*Math.cos(angle),radius*v*.68,radius*r*Math.sin(angle),w,h);});
  for(const i of ids)for(const j of ids){if(!adj[i][j])continue;const a=points[j],b=points[i];if(i===j){ctx.strokeStyle='rgba(123,241,200,.25)';ctx.beginPath();ctx.arc(a.x+8,a.y-7,9,0,Math.PI*1.7);ctx.stroke();continue;}const active=i===selectedNode||j===selectedNode;ctx.strokeStyle=active?'rgba(123,241,200,.78)':'rgba(103,151,143,.27)';ctx.lineWidth=active?1.5:Math.min(2,.55+Math.log1p(adj[i][j])/10);ctx.beginPath();ctx.moveTo(a.x,a.y);ctx.lineTo(b.x,b.y);ctx.stroke();}
  projected=ids.map(id=>({id,...points[id]})).sort((a,b)=>b.z-a.z);
  for(const p of projected){const service=graph.mode==='service'&&p.id>=3,color=service?'#79a7ff':'#7bf1c8';ctx.shadowColor=color;ctx.shadowBlur=p.id===selectedNode?24:13;ctx.fillStyle=color;ctx.globalAlpha=Math.max(.48,Math.min(1,1-p.z/520));ctx.beginPath();ctx.arc(p.x,p.y,(p.id===selectedNode?7:4)*p.scale+1,0,Math.PI*2);ctx.fill();ctx.shadowBlur=0;ctx.globalAlpha=1;if(ids.length<=15||p.id===selectedNode){ctx.font='10px ui-monospace,monospace';ctx.fillStyle='#9cb0bd';ctx.textAlign=p.x<w/2?'right':'left';ctx.fillText(graph.node_names?.[p.id]||'node '+p.id,p.x+(p.x<w/2?-12:12),p.y+4);}}
}
let lastFrame=0;function graphAnimate(now){if(now-lastFrame>32&&!document.hidden){if(rotating&&!drag)yaw+=.0026;drawGraph();lastFrame=now;}requestAnimationFrame(graphAnimate);}requestAnimationFrame(graphAnimate);
if($('graph')){
  $('graph').addEventListener('pointerdown',e=>{drag={x:e.clientX,y:e.clientY,startX:e.clientX,startY:e.clientY};$('graph').setPointerCapture(e.pointerId);});
  $('graph').addEventListener('pointermove',e=>{if(!drag)return;yaw+=(e.clientX-drag.x)*.008;pitch=Math.max(-1,Math.min(1,pitch+(e.clientY-drag.y)*.006));drag.x=e.clientX;drag.y=e.clientY;});
  $('graph').addEventListener('pointerup',e=>{if(drag&&Math.hypot(e.clientX-drag.startX,e.clientY-drag.startY)<8){const r=$('graph').getBoundingClientRect(),found=projected.slice().reverse().find(p=>Math.hypot(p.x-(e.clientX-r.left),p.y-(e.clientY-r.top))<16);selectedNode=found?found.id:null;$('nodeDetail').hidden=!found;if(found)text('nodeDetail',(graph.node_names?.[found.id]||'node '+found.id)+' · observed node');}drag=null;});
  $('graph').addEventListener('pointercancel',()=>drag=null);
}
function rotationButton(){if(!$('rotate'))return;$('rotate').textContent=rotating?'Ⅱ':'▷';$('rotate').setAttribute('aria-label',rotating?'Pause graph rotation':'Resume graph rotation');$('rotate').setAttribute('aria-pressed',String(!rotating));}rotationButton();
if($('rotate')) $('rotate').onclick=()=>{rotating=!rotating;rotationButton();};if($('zoomIn')) $('zoomIn').onclick=()=>zoom=Math.min(1.8,zoom+.15);if($('zoomOut')) $('zoomOut').onclick=()=>zoom=Math.max(.55,zoom-.15);if($('resetView')) $('resetView').onclick=()=>{yaw=.4;pitch=.3;zoom=1;};

/* ---------- gauge + charts ---------- */
function gaugeColor(v){return v>=.75?'#ff6b86':v>=.5?'#f3c677':'#7bf1c8';}
function drawGauge(){
  const c=$('riskGauge'); if(!c) return; const [ctx,w,h]=canvasSize(c);ctx.clearRect(0,0,w,h);
  const cx=w/2,cy=h*.66,r=Math.min(w*.36,h*.52),start=Math.PI*.78,end=Math.PI*2.22,span=end-start;
  ctx.lineCap='round';ctx.lineWidth=Math.max(11,r*.095);ctx.strokeStyle='rgba(255,255,255,.075)';ctx.beginPath();ctx.arc(cx,cy,r,start,end);ctx.stroke();
  const grad=ctx.createLinearGradient(cx-r,0,cx+r,0);grad.addColorStop(0,'#7bf1c8');grad.addColorStop(.58,'#f3c677');grad.addColorStop(1,'#ff6b86');ctx.strokeStyle=grad;ctx.shadowColor=gaugeColor(gaugeCurrent);ctx.shadowBlur=16;ctx.beginPath();ctx.arc(cx,cy,r,start,start+span*Math.max(0,Math.min(1,gaugeCurrent)));ctx.stroke();ctx.shadowBlur=0;
  for(let i=0;i<=4;i++){const a=start+span*i/4,x1=cx+Math.cos(a)*(r-18),y1=cy+Math.sin(a)*(r-18),x2=cx+Math.cos(a)*(r-28),y2=cy+Math.sin(a)*(r-28);ctx.strokeStyle='rgba(185,204,216,.35)';ctx.lineWidth=1;ctx.beginPath();ctx.moveTo(x1,y1);ctx.lineTo(x2,y2);ctx.stroke();ctx.fillStyle='#718493';ctx.font='9px ui-monospace,monospace';ctx.textAlign='center';ctx.fillText((i*25)+'%',cx+Math.cos(a)*(r-43),cy+Math.sin(a)*(r-43)+3);}
  text('gaugeValue',connected?pct(gaugeCurrent):'—');text('gaugeLabel',!connected?'NO FORECAST':gaugeCurrent>=.75?'HIGH SIGNAL':gaugeCurrent>=.5?'ELEVATED':'OBSERVED');
}
function gaugeLoop(){gaugeCurrent+=(gaugeTarget-gaugeCurrent)*.075;if(Math.abs(gaugeCurrent-gaugeTarget)<.0005)gaugeCurrent=gaugeTarget;drawGauge();requestAnimationFrame(gaugeLoop);}requestAnimationFrame(gaugeLoop);
function pushRisk(value,source){if(!Number.isFinite(value))return;riskHistory.push({value,time:Date.now(),source});while(riskHistory.length>36)riskHistory.shift();drawActivitySpark();}
function drawActivitySpark(){
  const c=$('activitySpark');if(!c)return;const[ctx,w,h]=canvasSize(c);ctx.clearRect(0,0,w,h);const l=20,r=w-18,t=18,b=h-20;ctx.strokeStyle='rgba(255,255,255,.06)';ctx.lineWidth=1;for(let i=0;i<4;i++){const y=t+(b-t)*i/3;ctx.beginPath();ctx.moveTo(l,y);ctx.lineTo(r,y);ctx.stroke();}if(!riskHistory.length)return;const pts=riskHistory.map((d,i)=>[l+(r-l)*i/Math.max(1,riskHistory.length-1),b-(b-t)*d.value]);const fill=ctx.createLinearGradient(0,t,0,b);fill.addColorStop(0,'rgba(123,241,200,.20)');fill.addColorStop(1,'rgba(123,241,200,0)');ctx.beginPath();ctx.moveTo(l,b);pts.forEach(p=>ctx.lineTo(...p));ctx.lineTo(r,b);ctx.closePath();ctx.fillStyle=fill;ctx.fill();ctx.strokeStyle='#7bf1c8';ctx.lineWidth=2;ctx.beginPath();pts.forEach((p,i)=>i?ctx.lineTo(...p):ctx.moveTo(...p));ctx.stroke();const p=pts.at(-1);ctx.fillStyle=gaugeColor(riskHistory.at(-1).value);ctx.shadowColor=ctx.fillStyle;ctx.shadowBlur=12;ctx.beginPath();ctx.arc(p[0],p[1],4,0,Math.PI*2);ctx.fill();ctx.shadowBlur=0;
}
function drawTimeline(f){
  const c=$('timeline');if(!c)return;const[ctx,w,h]=canvasSize(c);ctx.clearRect(0,0,w,h);const l=42,r=w-20,t=24,b=h-35;ctx.font='9px ui-monospace,monospace';ctx.textAlign='right';for(let p=0;p<=100;p+=25){const y=b-(b-t)*p/100;ctx.strokeStyle='rgba(255,255,255,.07)';ctx.lineWidth=.7;ctx.beginPath();ctx.moveTo(l,y);ctx.lineTo(r,y);ctx.stroke();ctx.fillStyle='#708493';ctx.fillText(p+'%',l-7,y+3);}if(!f||!Array.isArray(f.trajectory))return;const points=f.trajectory.map((v,i)=>[l+(r-l)*i/Math.max(f.trajectory.length-1,1),b-Number(v.malicious_flow_probability||0)*(b-t)]),fill=ctx.createLinearGradient(0,t,0,b);fill.addColorStop(0,'rgba(123,241,200,.22)');fill.addColorStop(1,'rgba(123,241,200,.005)');ctx.beginPath();ctx.moveTo(l,b);points.forEach(p=>ctx.lineTo(...p));ctx.lineTo(r,b);ctx.closePath();ctx.fillStyle=fill;ctx.fill();ctx.setLineDash([4,5]);ctx.strokeStyle='#f3c677';ctx.beginPath();ctx.moveTo(l,b-Number(f.threshold||0)*(b-t));ctx.lineTo(r,b-Number(f.threshold||0)*(b-t));ctx.stroke();ctx.setLineDash([]);ctx.strokeStyle='#7bf1c8';ctx.lineWidth=2.2;ctx.beginPath();points.forEach((p,i)=>i?ctx.lineTo(...p):ctx.moveTo(...p));ctx.stroke();points.forEach(([x,y],i)=>{ctx.fillStyle='#7bf1c8';ctx.beginPath();ctx.arc(x,y,3.7,0,Math.PI*2);ctx.fill();ctx.fillStyle='#8095a3';ctx.textAlign=i===0?'left':i===points.length-1?'right':'center';ctx.fillText('+'+f.trajectory[i].horizon_seconds+'s',x,b+22);});
}
function drawBenchmarkChart(){
  const c=$('benchmarkChart');if(!c||!benchmarkData)return;const[ctx,w,h]=canvasSize(c);ctx.clearRect(0,0,w,h);const l=48,r=w-20,t=24,b=h-45,keys=['logistic_regression','lstm','gnn_lstm'],labels=['LOGISTIC','LSTM','GNN + LSTM'],series=[['f1','#7bf1c8'],['recall','#79a7ff'],['fpr','#ff6b86']];ctx.font='9px ui-monospace,monospace';ctx.textAlign='right';for(let p=0;p<=100;p+=25){const y=b-(b-t)*p/100;ctx.strokeStyle='rgba(255,255,255,.065)';ctx.beginPath();ctx.moveTo(l,y);ctx.lineTo(r,y);ctx.stroke();ctx.fillStyle='#708493';ctx.fillText(p+'%',l-8,y+3);}const group=(r-l)/keys.length,barW=Math.min(24,group*.14);keys.forEach((key,gi)=>{const m=benchmarkData.models?.[key];if(!m)return;const gx=l+group*gi+group/2;series.forEach(([name,color],si)=>{const v=Math.max(0,Math.min(1,Number(m[name]?.mean||0))),x=gx+(si-1)*barW*1.35-barW/2,y=b-v*(b-t);ctx.fillStyle=color;ctx.globalAlpha=.92;ctx.fillRect(x,y,barW,b-y);ctx.globalAlpha=1;});ctx.fillStyle='#92a5b3';ctx.textAlign='center';ctx.fillText(labels[gi],gx,b+23);});
}

function render(result){
  last=result; if(result?.graph) setGraph(result.graph); if($('download')) $('download').disabled=false;
  const f=result?.forecast; if($('horizonValues')) $('horizonValues').replaceChildren();
  if(!f){gaugeTarget=0;text('peak','—');text('forecastLarge','—');text('source','SUBMITTED OBSERVATION');text('signalBadge','WITHHELD');$('signalBadge')?.classList.remove('alert');text('stage','Insufficient stage evidence');text('stageText','No forecast is available for this capture.');text('provenance','');empty($('features'),'No feature attribution available.');drawTimeline(null);notice(result?.inference_unavailable_reason||'Forecast withheld.');return;}
  const trajectory=Array.isArray(f.trajectory)?f.trajectory:[],peak=Math.max(0,...trajectory.map(x=>Number(x.malicious_flow_probability||0)));gaugeTarget=peak;pushRisk(peak,f.data_source||'unknown');
  text('peak',pct(peak));text('forecastLarge',pct(peak));text('source',String(f.data_source||'observed').replaceAll('_',' ').toUpperCase());text('signalBadge',f.alert?'ALERT SIGNAL':'BELOW THRESHOLD');$('signalBadge')?.classList.toggle('alert',!!f.alert);drawTimeline(f);
  const src=String(f.data_source||'');text('demoDataMode',src.startsWith('uploaded_')?'UPLOADED CAPTURE':'RECORDED REPLAY');
  for(const t of trajectory){const d=document.createElement('div'),s=document.createElement('span');s.textContent='+'+t.horizon_seconds+' SECONDS';d.append(s,document.createTextNode(pct(t.malicious_flow_probability)));$('horizonValues')?.append(d);}
  text('stage',f.predicted_attack_stage||f.stage_hint?.title||'Insufficient stage evidence');text('stageText',f.predicted_attack_stage?f.stage_status:'Heuristic-based, not ML-trained. '+(f.stage_hint?.rule||'')+' '+(f.stage_hint?.caveat||''));
  const v15=f.garuda_v15;if(v15){const gate=v15.autonomous_unknown_containment_approved?'APPROVED':'SHADOW ONLY';text('provenance',(f.uncertainty||'')+' · runtime SHA-256 '+String(f.model_sha256||'').slice(0,14)+'… · V15 LSTM recall '+pct(v15.lstm?.recall)+' · observed FPR '+pct(v15.lstm?.observed_fpr));text('evidenceLimit','GARUDA V15 · X-IIoTID · 8 min history → 4 min future malicious-traffic · untouched test '+v15.test_support.n+' ('+v15.test_support.benign+' benign / '+v15.test_support.attack+' attack) · clean-history future-positive n='+v15.clean_history_future_positive_n+' · network-only audit '+(v15.network_only_feature_audit_passed?'PASS':'PENDING')+' · live-schema compatibility '+(v15.runtime_graph_schema_compatible?'PASS':'PENDING')+' · unknown auto-containment '+gate+'. Pre-compromise lead time is not verified.');}else{text('provenance',(f.uncertainty||'')+' · SHA-256 '+String(f.model_sha256||'').slice(0,20)+'…');}
  if($('features')){$('features').replaceChildren();for(const item of (f.explanation?.feature_attributions||[]).slice(0,7)){const row=document.createElement('div');row.className='feature';const label=document.createElement('span');label.textContent=String(item.feature||'feature').replaceAll('_',' ');const track=document.createElement('div');track.className='track';const bar=document.createElement('div');bar.className='bar';bar.style.width=Math.max(0,Math.min(100,100*Number(item.magnitude_fraction||0)))+'%';track.append(bar);const v=document.createElement('span');v.textContent=pct(item.magnitude_fraction);row.append(label,track,v);$('features').append(row);}if(!$('features').children.length)empty($('features'),'No feature attribution returned for this forecast.');}
  text('garudaState',f.alert?'Forecast signal emitted':'Below alert threshold');
  lastRefreshAt=Date.now();
  notice('Forecast rendered from '+String(f.data_source||'observed data').replaceAll('_',' ')+(f.defence_signal?' · routed to '+String(f.defence_signal.route||'').toUpperCase():'')+(v15&&!v15.autonomous_unknown_containment_approved?' · unknown auto-containment remains shadow-only':''));
}

/* ---------- interactions ---------- */
if($('sessionToggle')) $('sessionToggle').onclick=()=>{if($('sessionPanel')){$('sessionPanel').hidden=!$('sessionPanel').hidden;if(!$('sessionPanel').hidden)$('token')?.focus();}};
if($('sessionForm')) $('sessionForm').onsubmit=e=>{e.preventDefault();run(async()=>{
  token=$('token').value.trim();await refresh();await evidence();connected=true;$('connection')?.classList.add('connected');text('connection',role==='operator'?'Operator connected':'Viewer connected');text('sessionToggle','Session settings');$('token').value='';$('sessionPanel').hidden=true;for(const id of ['replay','alertReplay','hostReplay','analyze'])if($(id))$(id).disabled=false;
  try{notice('Secure session connected. Loading one recorded replay into the command centre…');render(await api('/api/replay'));await refresh();notice('Command centre ready. Visuals update in real time; current model input is recorded replay, not live customer telemetry.');}catch(_){notice('Connected locally as '+role+'. Choose a recorded replay or upload observed telemetry.');}
});};
for(const [id,path] of [['replay','/api/replay'],['alertReplay','/api/replay?scenario=alert'],['hostReplay','/api/replay?scenario=hosts']]) if($(id)) $(id).onclick=()=>run(async()=>{notice('Running recorded graph through Garuda…');render(await api(path));await refresh();});
if($('file')) $('file').onchange=()=>text('fileName',$('file').files[0]?.name||'No file selected');
if($('analyze')) $('analyze').onclick=()=>run(async()=>{const f=$('file').files[0];if(!f)throw Error('Choose a CSV or classic PCAP file.');if(f.size>72*1024*1024)throw Error('Capture exceeds the 72 MiB upload limit.');notice('Parsing observed traffic and building graph…');render(await api('/api/analyze?type='+(f.name.toLowerCase().endsWith('.pcap')?'pcap':'csv')+'&mode='+$('mode').value,f,true));await refresh();});
if($('contain')) $('contain').onclick=()=>run(async()=>{const r=await api('/api/policy/create',{target:$('target').value.trim(),ttl:Number($('ttl').value),reason:$('reason').value.trim()});await refresh();notice(r.enforcement||'Policy proposed.');});
if($('arm')) $('arm').onclick=()=>run(async()=>{const r=await api('/api/response/arm',{target:$('target').value.trim(),ttl:Number($('ttl').value),duration:120});await refresh();notice('Lab response armed for '+r.target+'.');});
if($('disarm')) $('disarm').onclick=()=>run(async()=>{await api('/api/response/disarm',{});await refresh();notice('Disarmed. Existing policies keep their TTL unless emergency revoke is used.');});
if($('kill')) $('kill').onclick=()=>run(async()=>{await api('/api/policy/kill',{});await refresh();notice('Automation disarmed and v3 policies revoked.');});
if($('reviewForm')) $('reviewForm').onsubmit=e=>{e.preventDefault();run(async()=>{if(!$('reviewEvent').value)throw Error('Select an alert signal.');const r=await api('/api/response/approve',{id:$('reviewEvent').value,attack_type:$('attackType').value.trim(),evidence:$('reviewEvidence').value.trim()});await response();notice(r.scope||'Fingerprint approved.');});};
if($('escalate')) $('escalate').onclick=()=>run(async()=>{if(!$('reviewEvent').value)throw Error('Select a signal and provide incident evidence.');await api('/api/response/escalate',{id:$('reviewEvent').value,evidence:$('reviewEvidence').value.trim()});await refresh();notice('Operator-reported breach evidence recorded.');});
if($('download')) $('download').onclick=()=>{if(!last)return;const url=URL.createObjectURL(new Blob([JSON.stringify(last,null,2)],{type:'application/json'})),a=document.createElement('a');a.href=url;a.download='krishna-garuda-forecast.json';a.click();setTimeout(()=>URL.revokeObjectURL(url),1000);};

function clock(){text('clock',new Date().toISOString().slice(11,19)+' UTC');if(lastRefreshAt)text('refreshAge',Math.max(0,Math.round((Date.now()-lastRefreshAt)/1000))+'s ago');}clock();setInterval(clock,1000);
setInterval(()=>{if(connected&&!busy&&!document.hidden)run(refresh);},5000);
window.addEventListener('resize',()=>{drawTimeline(last?.forecast||null);drawActivitySpark();drawBenchmarkChart();drawGauge();});
requestAnimationFrame(()=>{drawTimeline(null);drawActivitySpark();drawGauge();});
const observer=new IntersectionObserver(entries=>{for(const e of entries)if(e.isIntersecting)document.querySelectorAll('.mainNav a').forEach(a=>a.classList.toggle('active',a.getAttribute('href')==='#'+e.target.id));},{rootMargin:'-15% 0px -65% 0px'});
for(const id of ['overview','telemetry','response','evidence']) if($(id)) observer.observe($(id));
