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
writeFileSync(join(target,"console.html"),html,"utf8");
console.log("Krishna premium console prepared for Vercel (no packet/model secrets copied)");
