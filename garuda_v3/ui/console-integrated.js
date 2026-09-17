(function(){
  'use strict';

  var NETWORK_SCENARIOS = [
    {key:'syn_flood',    icon:'🌊', name:'SYN Flood',   sub:'KNOWN · memory route', kind:'known'},
    {key:'port_scan',    icon:'🔎', name:'Port Scan',   sub:'KNOWN · recon',        kind:'known'},
    {key:'lateral_smb',  icon:'↔️', name:'SMB Lateral', sub:'KNOWN · east-west',     kind:'known'},
    {key:'burst_ddos',   icon:'⚡', name:'DDoS Burst',  sub:'KNOWN · volumetric',    kind:'known'},
    {key:'dns_tunnel',   icon:'🧬', name:'DNS Tunnel',  sub:'UNKNOWN · anomaly',     kind:'unknown'},
    {key:'c2_beacon',    icon:'📡', name:'C2 Beacon',   sub:'UNKNOWN · temporal',    kind:'unknown'},
    {key:'exfil_spike',  icon:'📤', name:'Exfil Spike', sub:'UNKNOWN · egress',      kind:'unknown'},
    {key:'clean_baseline',icon:'🟢',name:'Clean',       sub:'RECORDED · baseline',   kind:'clean'}
  ];

  var scenarioByKey = {};
  NETWORK_SCENARIOS.forEach(function(s){ scenarioByKey[s.key] = s; });
  var busy = false;
  var waveTimers = [];

  function esc(v){
    return String(v == null ? '' : v)
      .replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;');
  }

  function firstByText(selector, text){
    var nodes = document.querySelectorAll(selector);
    for(var i=0;i<nodes.length;i++) if((nodes[i].textContent||'').indexOf(text)>=0) return nodes[i];
    return null;
  }

  function peakRisk(forecast){
    var vals = ((forecast||{}).trajectory||[]).map(function(p){
      var v = Number(p.malicious_flow_probability || 0);
      return isFinite(v) ? v : 0;
    });
    if(!vals.length) return 0;
    return Math.max.apply(Math, vals);
  }

  function trajectoryPct(forecast){
    return ((forecast||{}).trajectory||[]).map(function(p){
      var v = Number(p.malicious_flow_probability || 0);
      return Math.max(0, Math.min(100, (isFinite(v)?v:0) * 100));
    });
  }

  function labelForRoute(route){
    if(route === 'arjuna') return 'ARJUNA · REVIEWED KNOWN MEMORY';
    if(route === 'krishna') return 'KRISHNA · UNKNOWN FORECAST TRIAGE';
    if(route === 'sudarshana') return 'SUDARSHANA · OPERATOR ESCALATION';
    return 'GARUDA · BELOW ALERT THRESHOLD';
  }

  function containmentLabel(signal){
    var state = (signal && signal.sudarshana) || 'standby';
    if(state === 'signed_policy_published') return 'SIGNED CONTAINMENT PUBLISHED';
    if(state === 'awaiting_authorization') return 'AWAITING OPERATOR AUTHORIZATION';
    if(state === 'standby_unapproved_forecast') return 'STANDBY · UNKNOWN AUTO-CONTAINMENT GATE CLOSED';
    return String(state).replace(/_/g,' ').toUpperCase();
  }

  function injectRouteStrip(){
    if(document.getElementById('garuda-route-strip')) return;
    var attackTitle = firstByText('.ptitle','ATTACK TEST BENCH');
    if(!attackTitle) return;
    var strip = document.createElement('div');
    strip.id = 'garuda-route-strip';
    strip.className = 'garuda-route-strip';
    strip.innerHTML =
      '<div class="route-node garuda active" data-route="garuda"><b>GARUDA AI</b><span>forecast / detect</span></div>'+
      '<div class="route-arrow">→</div>'+
      '<div class="route-split">'+
        '<div class="route-node arjuna" data-route="arjuna"><b>ARJUNA</b><span>known / reviewed memory</span></div>'+
        '<div class="route-node krishna" data-route="krishna"><b>KRISHNA</b><span>unknown / triage</span></div>'+
      '</div>'+
      '<div class="route-arrow">→</div>'+
      '<div class="route-node sudarshana" data-route="sudarshana"><b>SUDARSHANA</b><span>scoped containment</span></div>';
    attackTitle.insertAdjacentElement('afterend',strip);
  }

  function setRoute(route, sudarshanaState){
    document.querySelectorAll('#garuda-route-strip .route-node').forEach(function(n){n.classList.remove('active','standby');});
    var g = document.querySelector('#garuda-route-strip [data-route="garuda"]');
    if(g) g.classList.add('active');
    if(route === 'arjuna' || route === 'krishna' || route === 'sudarshana'){
      var r = document.querySelector('#garuda-route-strip [data-route="'+route+'"]');
      if(r) r.classList.add('active');
    }
    var s = document.querySelector('#garuda-route-strip [data-route="sudarshana"]');
    if(s){
      if(sudarshanaState === 'signed_policy_published') s.classList.add('active');
      else s.classList.add('standby');
    }
  }

  function rebuildAttackBench(){
    var rb = document.getElementById('res-box');
    if(!rb) return;
    var grid = rb.previousElementSibling;
    if(!grid || !grid.classList.contains('atk-grid')) return;
    grid.innerHTML = '';
    NETWORK_SCENARIOS.forEach(function(s){
      var b = document.createElement('button');
      b.className = 'ab network-ab ' + (s.kind === 'clean' ? 'clean' : '');
      b.dataset.scenario = s.key;
      b.innerHTML = esc(s.icon)+' '+esc(s.name)+'<span class="ab-sub">'+esc(s.sub)+'</span>';
      b.addEventListener('click', function(){ window.sendAtk(s.key); });
      grid.appendChild(b);
    });
    var note = document.createElement('div');
    note.className = 'network-source-note';
    note.innerHTML = '<b>NETWORK LAB:</b> Garuda risk is actual model inference. Attack names are local scenario metadata. '+
      'Known scenarios are operator-reviewed exact-memory replays; unknown scenarios use fresh synthetic graph variants. '+
      'Sudarshana remains dry-run/standby unless the real runtime is explicitly armed.';
    grid.insertAdjacentElement('afterend',note);
  }

  function refreshLabels(){
    var logo = document.querySelector('.logo-main');
    if(logo) logo.innerHTML = '🦅 GARUDA <span>AI</span> · KRISHNA DEFENCE';
    var sub = document.querySelector('.logo-sub');
    if(sub) sub.textContent = 'NETWORK ATTACK FORECASTING · KNOWN/UNKNOWN ROUTING · SCOPED CONTAINMENT · SIH26153';

    var attackTitle = firstByText('.ptitle','ATTACK TEST BENCH');
    if(attackTitle) attackTitle.innerHTML = '⚔️ NETWORK ATTACK LAB <span class="ptag live">GARUDA RUNTIME · LOCAL</span>';

    var attr = firstByText('.ptitle','SHAP ATTRIBUTION');
    if(attr) attr.innerHTML = 'MODEL ATTRIBUTION <span class="ptag">Gradient × Input · PyTorch</span>';

    var hudTitle = document.querySelector('.hud-title');
    if(hudTitle) hudTitle.textContent = 'GARUDA DEFENCE CORE';
    var hudSub = document.querySelector('.hud-subtitle');
    if(hudSub) hudSub.textContent = 'GARUDA → ARJUNA / KRISHNA → SUDARSHANA';

    var gauge = document.querySelector('.gauge-title');
    if(gauge) gauge.textContent = 'GARUDA AI — MODEL RISK FORECAST';

    var streamTitle = firstByText('.shdr span','REAL-TIME SECURITY INCIDENT STREAM');
    if(streamTitle) streamTitle.textContent = 'GARUDA NETWORK DEFENCE EVENT STREAM';
  }

  function renderAttribution(forecast){
    var attrs = (((forecast||{}).explanation||{}).feature_attributions)||[];
    if(!attrs.length) return;
    var wrap = document.getElementById('shap-wrap');
    if(!wrap) return;
    wrap.innerHTML = '';
    attrs.slice(0,10).forEach(function(a,index){
      var frac = Math.max(0, Math.min(1, Number(a.magnitude_fraction)||0));
      var row = document.createElement('div');
      row.className = 'srow';
      row.innerHTML = '<div class="sname">'+esc(a.feature)+'</div>'+
        '<div class="sbar"><div class="sfill" style="width:'+Math.max(2,frac*100).toFixed(1)+'%"></div></div>'+
        '<div class="sval">'+(frac*100).toFixed(1)+'%</div>';
      wrap.appendChild(row);
    });
  }

  function renderStage(forecast){
    var box = document.getElementById('defst');
    if(!box) return;
    var hint = forecast.stage_hint;
    var stage = forecast.predicted_attack_stage;
    var text = stage ? ('Supervised stage signal: '+stage) : hint ? ('Stage hint: '+(hint.stage||hint.label||JSON.stringify(hint))) : 'No supported attack-stage signal for this forecast.';
    box.innerHTML = '<b>GARUDA STAGE EVIDENCE</b><br>'+esc(text)+'<br><span style="opacity:.65">'+esc(forecast.stage_status||'')+'</span>';
  }

  function updateForecastPanels(forecast){
    var risk = peakRisk(forecast) * 100;
    var pts = trajectoryPct(forecast);
    if(typeof window.animGauge === 'function'){
      var from = typeof window.currentGaugeVal === 'number' ? window.currentGaugeVal : 0;
      window.animGauge(from, risk, 650);
    }
    if(pts.length && typeof window.drawTraj === 'function') window.drawTraj(pts);
    renderAttribution(forecast);
    renderStage(forecast);

    var tag = document.getElementById('traj-tag');
    if(tag) tag.textContent = forecast.alert ? 'MODEL ALERT' : 'BELOW THRESHOLD';
    var trend = document.getElementById('trend-v');
    if(trend && pts.length) trend.textContent = (pts[pts.length-1] >= pts[0] ? 'RISING' : 'FALLING')+' · '+risk.toFixed(1)+'% peak';
    var breach = document.getElementById('breach-v');
    if(breach) breach.textContent = forecast.alert ? 'THRESHOLD CROSSED' : 'NOT CROSSED';
    var cont = document.getElementById('cont-v');
    if(cont) cont.textContent = containmentLabel(forecast.defence_signal||{});
  }

  function addNetworkEvent(scenario, forecast, telemetryKind){
    var sf = document.getElementById('sfeed');
    if(!sf) return;
    var placeholder = sf.querySelector('[style*="text-align:center"]');
    if(placeholder) sf.innerHTML = '';
    var signal = forecast.defence_signal || {};
    var route = signal.route || 'garuda';
    var risk = peakRisk(forecast)*100;
    var item = document.createElement('div');
    item.className = forecast.alert ? 'sitem bl' : 'sitem ps';
    var status = forecast.alert ? 'ALERT' : 'BASELINE';
    var routeColor = route==='arjuna'?'#f59e0b':route==='krishna'?'#00f2fe':route==='sudarshana'?'#ff0055':'#10b981';
    item.innerHTML =
      '<div class="sit">'+new Date().toTimeString().slice(0,8)+'</div>'+
      '<div><span class="stp '+(forecast.alert?'tbl':'tps')+'">'+status+'</span></div>'+
      '<div class="spay"><b>'+esc(scenario.name)+'</b><br><span style="font-size:9.5px;color:var(--dim2)">'+esc(telemetryKind)+' network telemetry · '+risk.toFixed(1)+'% peak</span></div>'+
      '<div><div class="sstg" style="color:'+routeColor+'">'+esc(labelForRoute(route))+'</div><div class="ssrc" style="font-size:9px;color:var(--dim2)">'+esc(containmentLabel(signal))+'</div></div>'+
      '<div class="srv" style="color:'+(forecast.alert?'#ff0055':'#10b981')+'">'+(forecast.alert?'HIGH':'LOW')+'</div>';
    sf.insertBefore(item,sf.firstChild);
    while(sf.children.length>60) sf.removeChild(sf.lastChild);
    var cnt = document.getElementById('evt-cnt');
    if(cnt){
      var n = Number((cnt.textContent.match(/\d+/)||['0'])[0])+1;
      cnt.textContent = n+' events';
    }
  }

  function showPipelineResult(scenario, payload){
    var forecast = payload.forecast || {};
    var signal = forecast.defence_signal || {};
    var route = signal.route || 'garuda';
    var risk = peakRisk(forecast)*100;
    var rb = document.getElementById('res-box');
    if(rb){
      rb.style.display = 'block';
      rb.className = forecast.alert ? 'res-box bl' : 'res-box ps';
      var middle = route === 'arjuna' ? 'ARJUNA KNOWN-MEMORY MATCH' : route === 'krishna' ? 'KRISHNA UNKNOWN TRIAGE' : 'GARUDA MONITOR';
      rb.innerHTML = '<b>🦅 GARUDA '+(forecast.alert?'ALERT':'BASELINE')+'</b> — '+esc(scenario.name)+' · '+risk.toFixed(1)+'% peak<br>'+
        '<span class="route-inline">GARUDA → <b>'+esc(middle)+'</b> → SUDARSHANA</span><br>'+
        '<span style="font-size:10px;opacity:.75">'+esc(containmentLabel(signal))+' · source: '+esc(forecast.data_source||payload.telemetry_kind||'local')+'</span>';
    }
    setRoute(route, signal.sudarshana);
    var hud = document.getElementById('hud-status-txt');
    if(hud){
      hud.textContent = forecast.alert ? (route==='arjuna'?'KNOWN BLOCK PATH':'UNKNOWN TRIAGE') : 'SECURE';
      hud.style.color = forecast.alert ? (route==='arjuna'?'#f59e0b':'#00f2fe') : '#10b981';
    }
    var shields = document.getElementById('hud-shields');
    if(shields) shields.textContent = 'GARUDA + '+(route==='arjuna'?'ARJUNA':route==='krishna'?'KRISHNA':'MONITOR')+' + SUDARSHANA';
    var verdict = document.getElementById('verdict-box');
    if(verdict){
      verdict.innerHTML = forecast.alert ?
        '✅ <b>NETWORK THREAT ROUTED</b><br>Garuda model alert → '+esc(labelForRoute(route))+'<br>🌀 Sudarshana: '+esc(containmentLabel(signal)) :
        '✅ <b>CLEAN BASELINE</b><br>Garuda remained below the configured alert threshold.';
    }
  }

  async function simulate(key){
    var scenario = scenarioByKey[key];
    if(!scenario || busy) return;
    busy = true;
    document.querySelectorAll('.network-ab').forEach(function(b){b.disabled=true;});
    if(typeof window.addLog === 'function') window.addLog('Garuda network lab: '+scenario.name+' telemetry submitted','lw');
    try{
      var r = await fetch('/bridge/simulate',{
        method:'POST',
        headers:{'Content-Type':'application/json'},
        body:JSON.stringify({scenario:key})
      });
      var data = await r.json();
      if(!r.ok) throw new Error(data.error||('HTTP '+r.status));
      var forecast = data.forecast || {};
      updateForecastPanels(forecast);
      showPipelineResult(scenario,data);
      addNetworkEvent(scenario,forecast,data.telemetry_kind||'local');
      if(typeof window.spawnAttackBlip === 'function') window.spawnAttackBlip(Boolean(forecast.alert));
      if(typeof window.addLog === 'function'){
        var route = ((forecast.defence_signal||{}).route||'garuda').toUpperCase();
        window.addLog('Garuda route: '+route+' · Sudarshana: '+containmentLabel(forecast.defence_signal||{}),'lok');
      }
    }catch(err){
      var rb = document.getElementById('res-box');
      if(rb){rb.style.display='block';rb.className='res-box bl';rb.textContent='Garuda runtime error: '+err.message;}
      if(typeof window.addLog === 'function') window.addLog('Garuda runtime error: '+err.message,'le');
    }finally{
      busy = false;
      document.querySelectorAll('.network-ab').forEach(function(b){b.disabled=false;});
    }
  }

  async function refreshRuntime(){
    try{
      var r = await fetch('/bridge/status');
      if(!r.ok) return;
      var s = await r.json();
      var badge = document.querySelector('.hb.g');
      if(badge) badge.title = 'Garuda integrated runtime connected · model '+String((s.runtime_model||s.model||{}).mode||'graph')+' · dry-run enforcement: '+(!s.enforcement_enabled);
    }catch(e){}
  }

  window.sendAtk = function(type){ return simulate(type); };
  window.runWave = function(){
    waveTimers.forEach(clearTimeout); waveTimers=[];
    ['port_scan','syn_flood','dns_tunnel','c2_beacon','lateral_smb','exfil_spike'].forEach(function(key,i){
      waveTimers.push(setTimeout(function(){ simulate(key); }, i*1450));
    });
  };
  window.runLiveSimulation = function(){ window.runWave(); };
  window.runForecast = async function(){
    try{
      var r=await fetch('/bridge/replay?scenario=standard');
      var d=await r.json();
      if(r.ok && d.forecast){ updateForecastPanels(d.forecast); setRoute((d.forecast.defence_signal||{}).route,(d.forecast.defence_signal||{}).sudarshana); }
    }catch(e){}
  };

  function rewriteJudgeCards(){
    var cards = [
      {id:'sc0',icon:'🏹',name:'Known Network Replay',desc:'Garuda → Arjuna exact reviewed memory',badge:'KNOWN ROUTE'},
      {id:'sc1',icon:'🧠',name:'Unknown Network Anomaly',desc:'Garuda → Krishna triage path',badge:'UNKNOWN ROUTE'},
      {id:'sc2',icon:'🌀',name:'Mixed Defence Campaign',desc:'Known + unknown → Sudarshana gate',badge:'FULL PIPELINE'}
    ];
    cards.forEach(function(c){
      var el=document.getElementById(c.id); if(!el)return;
      var icon=el.querySelector('div'); if(icon) icon.textContent=c.icon;
      var name=el.querySelector('.sc-name'); if(name) name.textContent=c.name;
      var desc=el.querySelector('.sc-desc'); if(desc) desc.textContent=c.desc;
      var badge=el.querySelector('.sc-badge'); if(badge) badge.textContent=c.badge;
    });
    var btn=document.getElementById('run-demo-btn');
    if(btn){ btn.textContent='▶ START NETWORK DEFENCE DEMO · GARUDA → ARJUNA / KRISHNA → SUDARSHANA'; btn.onclick=window.runWave; }
  }

  document.addEventListener('DOMContentLoaded',function(){
    refreshLabels();
    injectRouteStrip();
    rebuildAttackBench();
    rewriteJudgeCards();
    setRoute('garuda','standby');
    refreshRuntime();
    setInterval(refreshRuntime,10000);
  });
})();
