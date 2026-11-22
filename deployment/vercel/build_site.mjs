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

let html=readFileSync(join(root,"console.html"),"utf8");
const styles=assets.filter(x=>x.endsWith(".css")).map(x=>'<link rel="stylesheet" href="/'+x+'">').join("\n");
const scripts=[...assets.filter(x=>x.endsWith(".js")),"hosted-mode.js"]
  .map(x=>'<script src="/'+x+'"></script>').join("\n");
if (!html.includes("</head>") || !html.includes("</body>"))throw Error("Expected console.html document");
html=html.replace("</head>",styles+"\n</head>").replace("</body>",scripts+"\n</body>");
const banner='<div id="hosting-boundary" role="status" style="padding:12px 3%;background:#1c1720;color:#f0b97e;border-bottom:1px solid #ff925455;font-size:12px">VERCEL HOSTED MODE · Live traffic forecasts require a separately configured Render feed and owned network sensor. Recorded lab and file analysis are unavailable on this static deployment.</div>';
html=html.replace("<main>",banner+"\n<main>");
writeFileSync(join(target,"console.html"),html,"utf8");
console.log("Krishna premium console prepared for Vercel (no packet/model secrets copied)");
