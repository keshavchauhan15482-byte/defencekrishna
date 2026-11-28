/**
 * Produce the existing premium Krishna console as a zero-dependency Vercel
 * static frontend. No model checkpoint, sensor key or Python runtime is copied.
 */
import {readFileSync, writeFileSync, mkdirSync, copyFileSync} from "node:fs";
import {resolve, dirname, join} from "node:path";
import {fileURLToPath} from "node:url";

const root=resolve(dirname(fileURLToPath(import.meta.url)),"../..");
const target=join(root,"public");
mkdirSync(target,{recursive:true});
const assets=[
  "console-integrated.css", "console-v131-overlay.css","console-v132-extra.css",
  "console-integrated.js","console-v131-overlay.js","console-v132-extra.js",
];
for (const name of assets) copyFileSync(join(root,"garuda_v3","ui",name),join(target,name));
copyFileSync(join(root,"deployment","vercel","hosted-mode.js"),join(target,"hosted-mode.js"));
copyFileSync(join(root,"deployment","vercel","lab-comparison.js"),join(target,"lab-comparison.js"));
for(const name of ["forecast-view.js","hosted-compact.css"])copyFileSync(join(root,"deployment","vercel",name),join(target,name));

let html=readFileSync(join(root,"console.html"),"utf8");
const styles=[...assets.filter(x=>x.endsWith(".css")),"hosted-compact.css"].map(x=>'<link rel="stylesheet" href="/'+x+'">').join("\n");
const scripts=["forecast-view.js",...assets.filter(x=>x.endsWith(".js")),"hosted-mode.js","lab-comparison.js"]
  .map(x=>'<script src="/'+x+'"></script>').join("\n");
if (!html.includes("</head>") || !html.includes("</body>"))throw Error("Expected console.html document");
html=html.replace("</head>",styles+"\n</head>").replace("</body>",scripts+"\n</body>");
const banner='<div id="hosting-boundary" role="status" style="padding:12px 3%;background:#1c1720;color:#f0b97e;border-bottom:1px solid #ff925455;font-size:12px">VERCEL HOSTED MODE · Hosted HTTP monitoring and request guards need no local setup. Optional packet forecasts require genuine supported captures. Attack scenarios are interactive browser-only defensive walkthroughs, not real attack executions. File analysis remains private.</div>';
const labSection='<section id="lab" class="panel">';
if (!html.includes(labSection)) throw Error("Expected Attack Lab section");
const comparison='<div id="lab-comparison" class="panel" style="scroll-margin-top:140px">'
  +'<h2>Krishna ON / OFF comparison</h2><p>OFF simulates an outage. ON checks access to two hosted dummy records.</p>'
  +'<p>Garuda forecast unavailable for this demo run.</p>'
  +'<button type="button" class="primary" disabled>Run comparison</button>'
  +'<p role="status" aria-live="polite">Loading comparison controls…</p><ol aria-label="Comparison evidence"></ol></div>';
html=html.replace(labSection,labSection+comparison);
html=html.replace("<main>",banner+"\n<main>");
html=html.replace(/<body([^>]*)>/,(_m,attrs)=>'<body'+(attrs.includes("class=")?attrs.replace(/class="([^"]*)"/,(_a,v)=>'class="'+v+' hosted-compact"'):attrs+' class="hosted-compact"')+'>');
html=html.replace(/<nav>.*?<\/nav>/,'<nav><a href="#prediction">Prediction</a><a href="#lab">Attack lab</a><a href="#live-defence-proof">HTTP defence</a><a href="#intelligence">System</a></nav>');
html=html.replace('<section class="workspace">','<section class="workspace" id="prediction" data-forecast-state="WAITING">');
html=html.replace('<div id="future" class="future">','<div id="forecast-freshness" role="status"><b id="forecast-status">Waiting for model</b><span id="forecast-cutoff"></span><span id="forecast-expiry"></span></div><div id="future" class="future">');
// Hosted-only dashboard: actual HTTP observation and model forecasting are separate.
html=html.replace('<h1>See the threat.<br><span>Before the impact.</span></h1>','<h1>See the threat. <span>Before the impact.</span></h1><div class="compact-actions"><a class="primary" href="#lab">Open Attack Lab</a><a class="primary" href="#live-defence-proof">Verify HTTP defence</a></div>');
html=html.replace('<section class="metrics">','<section class="metrics"><article><label>OBSERVED PAGE REQUESTS</label><strong id="compact-request-total">—</strong><small id="compact-request-detail">Connecting to cloud</small></article>');
html=html.replace('<div id="future" class="future">','<p id="forecast-unavailable" role="status">Waiting for a fresh, supported packet capture. Cloud HTTP activity is independent.</p><div id="future" class="future">');
html=html.replace('<section class="metrics">','<section class="metrics"><article><label>LIVE HTTP RISK INDEX</label><strong id="observed-risk-score">—</strong><small id="observed-risk-detail">Waiting for measured fixture activity</small></article>');
html=html.replace('<section class="workspace" id="prediction" data-forecast-state="WAITING">','<section class="workspace" id="prediction" data-forecast-state="WAITING"><article class="panel" id="observed-risk-panel"><div class="panel-head"><div><span class="eyebrow">LIVE HTTP OBSERVATION · NOT AI FORECAST</span><h3>Observed fixture risk</h3></div><span id="observed-risk-state" class="pill">Waiting</span></div><svg viewBox="0 0 400 100" role="img" aria-label="Observed HTTP fixture risk index history"><path d="M0 5H400 M0 50H400 M0 95H400" stroke="#ffffff22" fill="none"/><path id="observed-risk-line" fill="none" stroke="#60a5fa" stroke-width="2"/></svg><p id="observed-risk-note">Actual page-load counts and server-recorded dummy-route denials only. Not attack probability or full-site coverage.</p></article>');
html=html.replace('<section class="metrics">','<section class="metrics"><article><label>HTTP FORECAST INDEX · +60s</label><strong id="http-forecast-score">—</strong><small id="http-forecast-detail">Conditional · no new fixture denials</small></article>');
html=html.replace('LIVE FORECAST SCORE','PACKET AI FORECAST SCORE').replace('Threat trajectory','Packet AI threat trajectory');
html=html.replace('<article class="panel" id="observed-risk-panel">','<article class="panel" id="http-forecast-panel"><div class="panel-head"><div><span class="eyebrow">EXPERIMENTAL CLOUD HTTP FORECAST · NOT ATTACK PROBABILITY</span><h3>Next five minutes</h3></div><span id="http-forecast-status" class="pill">Waiting for history</span></div><svg viewBox="0 0 400 100" role="img" aria-label="Conditional HTTP forecast index"><path d="M0 5H400 M0 50H400 M0 95H400" stroke="#ffffff22" fill="none"/><path id="http-forecast-line" fill="none" stroke="#7cabff" stroke-width="2" stroke-dasharray="5 3"/></svg><p id="http-forecast-points">Waiting for recorded page activity.</p><p id="http-forecast-audit">Forecast assumes no new fixture denials. Not a prediction of new attacks.</p></article><article class="panel" id="observed-risk-panel">');
writeFileSync(join(target,"console.html"),html,"utf8");
console.log("Krishna premium console prepared for Vercel (no packet/model secrets copied)");
