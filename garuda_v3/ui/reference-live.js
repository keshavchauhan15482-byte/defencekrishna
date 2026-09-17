(() => {
'use strict';
const $=id=>document.getElementById(id);
const pct=v=>Number.isFinite(Number(v))?(Number(v)*100).toFixed(1)+'%':'—';
let token=sessionStorage.getItem('garuda_token')||'';
let connected=false, role='', paused=false, busy=false;
let lastResult=null, lastForecast=null, lastGraph=null, lastStatus=null, lastResponse=null, benchmarks=null;
let gaugeCurrent=0, gaugeTarget=0, riskHistory=[];
let start=Date.now(), selectedMode='service';

function toast(message,error=false){
  const el=$('toast'); if(!el)return;
  el.textContent=message; el.classList.toggle('error',error); el.hidden=false;
  clearTimeout(toast._t); toast._t=setTimeout(()=>el.hidden=true,3600);
}
function text(id,value){const el=$(id);if(el)el.textContent=value;}
function fit(){
  const stage=$('stage'),fitEl=$('fit'); if(!stage||!fitEl)return;
  const s=Math.min(innerWidth/1536,innerHeight/1024);
  stage.style.transform=`scale(${s})`;
  fitEl.style.width=`${1536*s}px`; fitEl.style.height=`${1024*s}px`;
}
addEventListener('resize',fit); fit();

async function api(path,body,raw=false){
  const options={headers:{Authorization:'Bearer '+token}};
  if(body!==undefined){
    options.method='POST'; options.body=raw?body:JSON.stringify(body);
    options.headers['Content-Type']=raw?'application/octet-stream':'application/json';
  }
  const r=await fetch(path,options);
  let d={}; try{d=await r.json();}catch{}
  if(!r.ok)throw Error(d.error||`Request failed (${r.status})`);
  return d;
}
async function guarded(fn){
  if(busy)return;
  busy=true;document.body.classList.add('busy');
  try{await fn();}catch(e){toast(e?.message||'Operation failed',true);}
  finally{busy=false;document.body.classList.remove('busy');}
}
function setConnection(ok){
  connected=ok;
  const btn=$('sessionToggle');
  if(btn)btn.classList.toggle('disconnected',!ok);
  text('connectionText',ok?(role==='operator'?'Operator connected':'Viewer connected'):'Disconnected');
  text('kpiRuntime',ok?'Runtime healthy':'Awaiting connection');
}
function openSession(){ $('sessionModal').hidden=false; setTimeout(()=>$('tokenInput')?.focus(),20); }
function closeSession(){ $('sessionModal').hidden=true; }

async function connect(){
  const entered=$('tokenInput').value.trim();
  if(entered){token=entered;sessionStorage.setItem('garuda_token',token);}
  if(!token)throw Error('Paste a local viewer or operator token.');
  const s=await api('/api/status'); role=s.role||''; lastStatus=s; setConnection(true); closeSession();
  await Promise.all([loadResponse(),loadBenchmarks()]);
  await loadReplay('standard');
  toast('Garuda command deck connected.');
}
async function loadStatus(){
  if(!connected)return;
  const s=await api('/api/status'); lastStatus=s; role=s.role||role;
  const model=s.model||s.runtime_model||{};
  const horizon=(Number(model.horizon)||0)*(Number(model.window_seconds)||0);
  text('kpiHorizon',horizon?horizon+'s':'—');
  text('kpiPosture',s.enforcement_enabled?'Enforcement enabled':'Review only');
  text('kpiRuntime',s.audit_integrity?'Runtime Healthy':'Integrity Review');
  text('analysisWindow',model.window_seconds?model.window_seconds+'s':'—');
  text('analysisModel',String(model.architecture||model.model_type||'Runtime model').replaceAll('_',' '));
  setConnection(true);
}
async function loadResponse(){
  if(!connected)return;
  const r=await api('/api/response');lastResponse=r;
  const events=Array.isArray(r.events)?r.events:[], memory=Array.isArray(r.memory)?r.memory:[];
  text('arjunaCount',String(memory.length));
  text('krishnaCount',String(events.filter(e=>e.review_status==='pending').length));
  const policies=Array.isArray(lastStatus?.policies)?lastStatus.policies:[];
  text('sudarshanaCount',String(policies.length));
  const latest=events[0];
  const row=$('latestAlert');
  if(row){
    const spans=row.querySelectorAll('span');
    if(latest){
      const ts=Number(latest.created||0)*1000;
      spans[0].textContent=ts?new Date(ts).toLocaleTimeString():'—';
      spans[1].textContent=latest.target||'Observed graph';
      spans[2].textContent=String(latest.classification||latest.route||'forecast signal').replaceAll('_',' ');
      spans[3].textContent=pct(latest.risk);
      spans[4].textContent=String(latest.review_status||latest.sudarshana||'recorded').replaceAll('_',' ');
    }else{
      spans[0].textContent='—';spans[1].textContent='—';spans[2].textContent='No recorded signals';spans[3].textContent='—';spans[4].textContent='Waiting';
    }
  }
}
async function loadBenchmarks(){
  if(!connected)return;
  const b=await api('/api/benchmarks');benchmarks=b;
  const model=b.models?.gnn_lstm||b.models?.lstm||null;
  const mse=model?.state_mse?.mean;
  const persistence=Number(b.persistence_mse);
  const improvement=(Number.isFinite(mse)&&Number.isFinite(persistence)&&persistence>0)?(persistence-mse)/persistence:null;
  const recall=model?.recall?.mean;
  text('mseValue',Number.isFinite(mse)?Number(mse).toFixed(4):'—');
  text('improveValue',Number.isFinite(improvement)?(improvement*100).toFixed(1)+'%':'—');
  text('recallValue',Number.isFinite(recall)?(recall*100).toFixed(1)+'%':'—');
  if($('mseBar'))$('mseBar').style.setProperty('--v',Number.isFinite(mse)&&Number.isFinite(persistence)&&persistence>0?Math.max(8,Math.min(100,100*(1-mse/persistence)))+'%':'0%');
  if($('improveBar'))$('improveBar').style.setProperty('--v',Number.isFinite(improvement)?Math.max(0,Math.min(100,improvement*100*4))+'%':'0%');
  if($('recallBar'))$('recallBar').style.setProperty('--v',Number.isFinite(recall)?Math.max(0,Math.min(100,recall*100))+'%':'0%');
}
async function loadReplay(scenario='standard'){
  if(!connected){openSession();return;}
  const result=await api('/api/replay?scenario='+encodeURIComponent(scenario));
  render(result);
}
async function analyzeFile(file){
  if(!connected){openSession();return;}
  const ext=file.name.toLowerCase().endsWith('.pcap')?'pcap':'csv';
  const result=await api(`/api/analyze?type=${ext}&mode=${selectedMode}`,file,true);
  render(result);
  toast('Capture analyzed locally.');
}

function canvasSize(c){
  const rect=c.getBoundingClientRect(),d=Math.min(devicePixelRatio||1,2);
  const w=Math.max(1,Math.round(rect.width*d)),h=Math.max(1,Math.round(rect.height*d));
  if(c.width!==w||c.height!==h){c.width=w;c.height=h;}
  const ctx=c.getContext('2d');ctx.setTransform(d,0,0,d,0,0);return[ctx,rect.width,rect.height];
}
function riskColor(v){return v>=.75?'#ff5d75':v>=.5?'#ffbd4a':v>=.25?'#a14cff':'#4df2c4';}
function drawGauge(){
  const c=$('gauge');if(!c)return;const[ctx,w,h]=canvasSize(c);ctx.clearRect(0,0,w,h);
  const cx=w/2,cy=h*.58,r=Math.min(w*.39,h*.45),start=Math.PI*.76,end=Math.PI*2.24,span=end-start;
  ctx.lineCap='round';ctx.lineWidth=13;ctx.strokeStyle='rgba(77,94,151,.23)';ctx.beginPath();ctx.arc(cx,cy,r,start,end);ctx.stroke();
  const grad=ctx.createLinearGradient(cx-r,cy,cx+r,cy);grad.addColorStop(0,'#4df2c4');grad.addColorStop(.36,'#27e6ff');grad.addColorStop(.68,'#6d68ff');grad.addColorStop(1,'#d65aff');
  ctx.strokeStyle=grad;ctx.shadowColor=riskColor(gaugeCurrent);ctx.shadowBlur=18;ctx.beginPath();ctx.arc(cx,cy,r,start,start+span*Math.max(0,Math.min(1,gaugeCurrent)));ctx.stroke();ctx.shadowBlur=0;
  ctx.fillStyle='#9fb0d0';ctx.font='8px ui-monospace,monospace';ctx.textAlign='center';
  for(let i=0;i<5;i++){const a=start+span*i/4;ctx.fillText(i*25+'%',cx+Math.cos(a)*(r-30),cy+Math.sin(a)*(r-30)+3);}
}
function drawSpark(){
  const c=$('spark');if(!c)return;const[ctx,w,h]=canvasSize(c);ctx.clearRect(0,0,w,h);
  if(!riskHistory.length)return;
  const vals=riskHistory.slice(-14),min=0,max=Math.max(.05,...vals);
  const g=ctx.createLinearGradient(0,0,w,0);g.addColorStop(0,'#a14cff');g.addColorStop(1,'#27e6ff');
  ctx.strokeStyle=g;ctx.lineWidth=1.7;ctx.beginPath();
  vals.forEach((v,i)=>{const x=i*w/Math.max(1,vals.length-1),y=h-2-(h-4)*(v-min)/(max-min||1);i?ctx.lineTo(x,y):ctx.moveTo(x,y);});ctx.stroke();
}
function drawForecast(){
  const c=$('forecast');if(!c)return;const[ctx,w,h]=canvasSize(c);ctx.clearRect(0,0,w,h);
  const l=34,r=w-14,t=18,b=h-24;
  ctx.strokeStyle='rgba(83,107,169,.20)';ctx.lineWidth=1;ctx.font='7px ui-monospace,monospace';ctx.fillStyle='#7083aa';ctx.textAlign='left';
  for(let p=0;p<=100;p+=25){const y=b-(b-t)*p/100;ctx.beginPath();ctx.moveTo(l,y);ctx.lineTo(r,y);ctx.stroke();ctx.fillText(p+'%',3,y+3);}
  if(!lastForecast?.trajectory?.length)return;
  const tr=lastForecast.trajectory,pts=tr.map((v,i)=>[l+(r-l)*i/Math.max(1,tr.length-1),b-Number(v.malicious_flow_probability||0)*(b-t)]);
  const grad=ctx.createLinearGradient(l,0,r,0);grad.addColorStop(0,'#27e6ff');grad.addColorStop(.55,'#6876ff');grad.addColorStop(1,'#bd4cff');
  ctx.strokeStyle=grad;ctx.lineWidth=2.2;ctx.beginPath();pts.forEach((p,i)=>i?ctx.lineTo(...p):ctx.moveTo(...p));ctx.stroke();
  pts.forEach((p,i)=>{ctx.fillStyle=i===pts.length-1?'#bd4cff':'#27e6ff';ctx.shadowColor=ctx.fillStyle;ctx.shadowBlur=8;ctx.beginPath();ctx.arc(p[0],p[1],3.4,0,Math.PI*2);ctx.fill();ctx.shadowBlur=0;});
  ctx.fillStyle='#7185ad';ctx.font='7px ui-monospace,monospace';ctx.textAlign='center';tr.forEach((v,i)=>ctx.fillText('+'+v.horizon_seconds+'s',pts[i][0],h-7));
  if(Number.isFinite(Number(lastForecast.threshold))){const y=b-Number(lastForecast.threshold)*(b-t);ctx.setLineDash([4,4]);ctx.strokeStyle='rgba(255,189,74,.8)';ctx.beginPath();ctx.moveTo(l,y);ctx.lineTo(r,y);ctx.stroke();ctx.setLineDash([]);}
}
function graphInfo(g){
  if(!g?.mask?.length||!g?.adj?.length)return{ids:[],edges:0};
  const mask=g.mask.at(-1),adj=g.adj.at(-1),ids=mask.map((v,i)=>v?i:-1).filter(i=>i>=0);let edges=0;
  ids.forEach(i=>ids.forEach(j=>{if(Number(adj[i]?.[j]||0)>0)edges++;}));
  return{ids,edges,adj};
}
function drawTopology(){
  const c=$('topology');if(!c)return;const[ctx,w,h]=canvasSize(c);ctx.clearRect(0,0,w,h);
  if(!lastGraph)return;
  const{ids,adj}=graphInfo(lastGraph);if(!ids.length)return;
  const center=[w*.47,h*.5],rad=Math.min(w,h)*.36;
  const pts={};ids.forEach((id,k)=>{const a=-Math.PI/2+k*Math.PI*2/ids.length+(k%2)*.12;const rr=rad*(.70+.25*((k*37)%7)/6);pts[id]=[center[0]+Math.cos(a)*rr,center[1]+Math.sin(a)*rr];});
  ctx.lineWidth=.8;
  ids.forEach(i=>ids.forEach(j=>{if(!Number(adj[i]?.[j]||0))return;ctx.strokeStyle='rgba(79,112,192,.28)';ctx.beginPath();ctx.moveTo(...pts[i]);ctx.lineTo(...pts[j]);ctx.stroke();}));
  const alert=!!lastForecast?.alert;
  ids.forEach((id,k)=>{const p=pts[id];const service=String(lastGraph.mode||'service')==='service';let color=service?(k<3?'#4b8cff':k%3===0?'#a14cff':'#4df2c4'):(k%2?'#a14cff':'#4b8cff');if(alert&&k===ids.length-1)color='#ff5d75';ctx.shadowColor=color;ctx.shadowBlur=12;ctx.fillStyle=color;ctx.beginPath();ctx.arc(p[0],p[1],4.2,0,Math.PI*2);ctx.fill();ctx.shadowBlur=0;});
}
function animate(){
  gaugeCurrent+=(gaugeTarget-gaugeCurrent)*.08;
  drawGauge();drawSpark();drawForecast();drawTopology();
  requestAnimationFrame(animate);
}
requestAnimationFrame(animate);

function render(result){
  lastResult=result;lastGraph=result?.graph||null;lastForecast=result?.forecast||null;
  const ginfo=graphInfo(lastGraph);
  text('nodesCount',ginfo.ids.length||'—');text('kpiNodes',ginfo.ids.length||'—');text('connCount',ginfo.edges||'—');
  const f=lastForecast;
  if(!f){
    gaugeTarget=0;text('riskValue','—');text('kpiRisk','—');text('peak','—');text('trend','—');text('statusText','WITHHELD');text('suspiciousCount','—');
    toast(result?.inference_unavailable_reason||'Forecast unavailable for this capture.',true);return;
  }
  const trajectory=Array.isArray(f.trajectory)?f.trajectory:[];
  const peak=Math.max(0,...trajectory.map(x=>Number(x.malicious_flow_probability||0)));
  gaugeTarget=peak;riskHistory.push(peak);while(riskHistory.length>30)riskHistory.shift();
  text('riskValue',pct(peak));text('kpiRisk',pct(peak));text('peak',pct(peak));
  text('trend',riskHistory.length>1?(peak>=riskHistory.at(-2)?'↑ rising':'↓ falling'):'stable');
  text('statusText',f.alert?'ALERT':'NORMAL');text('riskBadge',peak>=.75?'HIGH':peak>=.5?'ELEVATED':'LOW');
  text('suspiciousCount',f.alert?'1':'0');
  const src=String(f.data_source||lastGraph?.data_source||'recorded_replay').replaceAll('_',' ');
  text('analysisSource',src);
  text('analysisDataset',String(f.dataset||f.garuda_v15?.dataset||'Runtime replay'));
  text('analysisWindow',(lastGraph?.window_seconds||lastStatus?.model?.window_seconds)?String(lastGraph?.window_seconds||lastStatus?.model?.window_seconds)+'s':'—');
  text('analysisModel',String(lastStatus?.model?.architecture||lastStatus?.model?.model_type||'Garuda runtime').replaceAll('_',' '));
}
async function refresh(){
  if(!connected||paused)return;
  await Promise.all([loadStatus(),loadResponse()]);
}

$('sessionToggle')?.addEventListener('click',openSession);
$('sessionClose')?.addEventListener('click',closeSession);
$('sessionModal')?.addEventListener('click',e=>{if(e.target===$('sessionModal'))closeSession();});
$('sessionForm')?.addEventListener('submit',e=>{e.preventDefault();guarded(connect);});
$('demoBtn')?.addEventListener('click',()=>guarded(()=>loadReplay('standard')));
$('pauseBtn')?.addEventListener('click',()=>{paused=!paused;text('pauseBtn',paused?'▶ Resume':'Ⅱ Pause');toast(paused?'UI refresh paused.':'UI refresh resumed.');});
$('stopBtn')?.addEventListener('click',()=>{paused=true;text('pauseBtn','▶ Resume');toast('UI refresh paused; no backend policy was changed.');});
$('newBtn')?.addEventListener('click',()=>{if(!connected){openSession();return;}$('captureInput')?.click();});
$('captureInput')?.addEventListener('change',()=>{const file=$('captureInput').files?.[0];if(file)guarded(()=>analyzeFile(file));$('captureInput').value='';});

setInterval(()=>{text('clock',new Date().toLocaleTimeString([], {hour12:false}));const sec=Math.floor((Date.now()-start)/1000),m=String(Math.floor(sec/60)).padStart(2,'0'),s=String(sec%60).padStart(2,'0');text('runtimeClock',`00:${m}:${s}`);},1000);
setInterval(()=>guarded(refresh),5000);

if(token){
  $('tokenInput').value=token;
  guarded(async()=>{try{await connect();}catch(e){sessionStorage.removeItem('garuda_token');token='';setConnection(false);openSession();toast(e.message,true);}});
}else{
  setConnection(false);openSession();
}
})();
