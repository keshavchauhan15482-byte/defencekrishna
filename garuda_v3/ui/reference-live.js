'use strict';
(function(){
  if(!document.body.classList.contains('refExact')) return;

  const oldStatus = status;
  status = async function(){
    const s = await oldStatus();
    const model = s.model || {};
    const seconds = (Number(model.horizon)||0) * (Number(model.window_seconds)||0);
    text('horizonKpi', seconds ? seconds+'s' : '—');
    if($('datasetName')) text('datasetName', String(model.dataset || model.training_dataset || 'Runtime evidence').replaceAll('_',' '));
    return s;
  };

  const oldResponse = response;
  response = async function(){
    const r = await oldResponse();
    const events = Array.isArray(r.events) ? r.events : [];
    text('suspiciousCount', String(events.filter(e=>e.forecast_alert).length));
    return r;
  };

  const oldSetGraph = setGraph;
  setGraph = function(g){
    oldSetGraph(g);
    if(g && Array.isArray(g.mask) && g.mask.length){
      const ids = g.mask.at(-1).map((v,i)=>v?i:-1).filter(i=>i>=0);
      text('observedNodesValue', String(ids.length));
    } else text('observedNodesValue','—');
  };

  const oldPushRisk = pushRisk;
  pushRisk = function(value, source){
    const prev = riskHistory.length ? Number(riskHistory.at(-1).value) : null;
    oldPushRisk(value, source);
    if(prev == null || !Number.isFinite(prev)) text('trendValue','—');
    else {
      const d = Number(value)-prev;
      text('trendValue',(d>0?'↑ ':d<0?'↓ ':'→ ')+(Math.abs(d)*100).toFixed(1)+'%');
    }
  };

  const oldRender = render;
  render = function(result){
    oldRender(result);
    const f=result?.forecast;
    if(f && $('datasetName')){
      const src=String(f.data_source||'Runtime evidence').replaceAll('_',' ');
      text('datasetName',src.toUpperCase());
    }
  };

  function refCanvas(c){
    const rect=c.getBoundingClientRect(),d=Math.min(devicePixelRatio||1,2);
    const w=Math.max(1,Math.round(rect.width*d)),h=Math.max(1,Math.round(rect.height*d));
    if(c.width!==w||c.height!==h){c.width=w;c.height=h;}
    const ctx=c.getContext('2d');ctx.setTransform(d,0,0,d,0,0);return [ctx,rect.width,rect.height];
  }

  drawGauge = function(){
    const c=$('riskGauge'); if(!c) return;
    const [ctx,w,h]=refCanvas(c);ctx.clearRect(0,0,w,h);
    const cx=w/2,cy=h*.60,r=Math.min(w*.38,h*.43),start=Math.PI*.82,end=Math.PI*2.18,span=end-start;
    ctx.lineCap='round';
    ctx.lineWidth=Math.max(12,r*.105);ctx.strokeStyle='rgba(63,80,132,.28)';ctx.beginPath();ctx.arc(cx,cy,r,start,end);ctx.stroke();
    const grad=ctx.createLinearGradient(cx-r,cy,cx+r,cy);grad.addColorStop(0,'#35f1c8');grad.addColorStop(.28,'#2ac8ff');grad.addColorStop(.56,'#427dff');grad.addColorStop(.82,'#8a54ff');grad.addColorStop(1,'#d44dff');ctx.strokeStyle=grad;ctx.shadowColor='#5c6cff';ctx.shadowBlur=18;ctx.beginPath();ctx.arc(cx,cy,r,start,end);ctx.stroke();ctx.shadowBlur=0;
    for(let i=0;i<=4;i++){
      const a=start+span*i/4,x1=cx+Math.cos(a)*(r-17),y1=cy+Math.sin(a)*(r-17),x2=cx+Math.cos(a)*(r-27),y2=cy+Math.sin(a)*(r-27);
      ctx.strokeStyle='rgba(196,212,250,.45)';ctx.lineWidth=1;ctx.beginPath();ctx.moveTo(x1,y1);ctx.lineTo(x2,y2);ctx.stroke();
      ctx.fillStyle='#8496bd';ctx.font='8px ui-monospace,monospace';ctx.textAlign='center';ctx.fillText((i*25)+'%',cx+Math.cos(a)*(r-41),cy+Math.sin(a)*(r-41)+3);
    }
    const v=Math.max(0,Math.min(1,gaugeCurrent));const a=start+span*v;const mx=cx+Math.cos(a)*r,my=cy+Math.sin(a)*r;
    ctx.fillStyle='#55f6c7';ctx.shadowColor='#55f6c7';ctx.shadowBlur=16;ctx.beginPath();ctx.arc(mx,my,5,0,Math.PI*2);ctx.fill();ctx.shadowBlur=0;
    text('gaugeValue',connected?pct(gaugeCurrent):'—');
    text('gaugeLabel',!connected?'NO FORECAST':gaugeCurrent>=.75?'HIGH':gaugeCurrent>=.5?'ELEVATED':'LOW');
  };

  drawTimeline = function(f){
    const c=$('timeline');if(!c)return;const[ctx,w,h]=refCanvas(c);ctx.clearRect(0,0,w,h);
    const l=28,r=w-8,t=8,b=h-18;ctx.font='6px ui-monospace,monospace';ctx.textAlign='right';
    for(let p=0;p<=100;p+=25){const y=b-(b-t)*p/100;ctx.strokeStyle='rgba(67,94,157,.22)';ctx.lineWidth=.7;ctx.beginPath();ctx.moveTo(l,y);ctx.lineTo(r,y);ctx.stroke();ctx.fillStyle='#6f82aa';ctx.fillText(p+'%',l-4,y+2);}
    if(!f||!Array.isArray(f.trajectory)||!f.trajectory.length)return;
    const vals=f.trajectory;const pts=vals.map((v,i)=>[l+(r-l)*i/Math.max(vals.length-1,1),b-Number(v.malicious_flow_probability||0)*(b-t)]);
    const first=pts[0];ctx.strokeStyle='#25d6ff';ctx.lineWidth=2;ctx.beginPath();ctx.moveTo(l,first[1]);ctx.lineTo(first[0],first[1]);ctx.stroke();
    const fill=ctx.createLinearGradient(0,t,0,b);fill.addColorStop(0,'rgba(158,75,255,.19)');fill.addColorStop(1,'rgba(158,75,255,0)');ctx.beginPath();ctx.moveTo(first[0],b);pts.forEach(p=>ctx.lineTo(...p));ctx.lineTo(pts.at(-1)[0],b);ctx.closePath();ctx.fillStyle=fill;ctx.fill();
    ctx.setLineDash([4,4]);ctx.strokeStyle='#a94dff';ctx.lineWidth=2;ctx.beginPath();pts.forEach((p,i)=>i?ctx.lineTo(...p):ctx.moveTo(...p));ctx.stroke();ctx.setLineDash([]);
    pts.forEach(([x,y],i)=>{ctx.fillStyle=i===0?'#25d6ff':'#a94dff';ctx.shadowColor=ctx.fillStyle;ctx.shadowBlur=7;ctx.beginPath();ctx.arc(x,y,2.5,0,Math.PI*2);ctx.fill();ctx.shadowBlur=0;ctx.fillStyle='#7185ad';ctx.textAlign=i===0?'left':i===pts.length-1?'right':'center';ctx.fillText(i===0?'Now':'+'+vals[i].horizon_seconds+'s',x,b+10);});
  };

  drawGraph = function(){
    const c=$('graph');if(!c)return;const[ctx,w,h]=refCanvas(c);ctx.clearRect(0,0,w,h);
    if(!graph)return;
    const mask=graph.mask.at(-1),adj=graph.adj.at(-1),ids=mask.map((v,i)=>v?i:-1).filter(i=>i>=0);if(!ids.length)return;
    const palette=['#2c8dff','#9b4dff','#26e6de','#ff556d','#ffab2f','#4b75ff'];
    const cx=w*.43,cy=h*.47,rad=Math.min(w,h)*.31,pts={};
    ids.forEach((id,j)=>{if(j===0)pts[id]={x:cx,y:cy};else{const a=-Math.PI/2+(j-1)*Math.PI*2/Math.max(1,ids.length-1);pts[id]={x:cx+Math.cos(a)*rad*(.76+.18*((j%2))),y:cy+Math.sin(a)*rad};}});
    for(const i of ids)for(const j of ids){if(!adj[i][j]||i===j)continue;const a=pts[i],b=pts[j];ctx.strokeStyle='rgba(64,116,245,.42)';ctx.lineWidth=.8;ctx.beginPath();ctx.moveTo(a.x,a.y);ctx.lineTo(b.x,b.y);ctx.stroke();}
    ids.forEach((id,j)=>{const p=pts[id],color=palette[j%palette.length];ctx.fillStyle=color;ctx.shadowColor=color;ctx.shadowBlur=12;ctx.beginPath();ctx.arc(p.x,p.y,j===0?4.5:3.7,0,Math.PI*2);ctx.fill();ctx.shadowBlur=0;});
  };

  requestAnimationFrame(()=>{drawGauge();drawTimeline(last?.forecast||null);drawGraph();});
})();
