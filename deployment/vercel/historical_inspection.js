"use strict";
const { Worker } = require("node:worker_threads");
let active=0;
// Invoke only after positive route schema has already rejected an input.
// A worker failure cannot allow an otherwise invalid request. No shared
// learned state, browser IP attribution or automatic promotion is performed.
async function historicalDeny(value) {
  if(typeof value!=="string" || !value.length || Buffer.byteLength(value)>512 || active>=2) return null;
  active++;
  let worker;
  try {
    worker=new Worker(require.resolve("./legacy_worker.js"),{
      workerData:{value},env:{},argv:[],execArgv:[],
      stdout:true,stderr:true,
      resourceLimits:{maxOldGenerationSizeMb:48,maxYoungGenerationSizeMb:12,stackSizeMb:2}
    });
    worker.stdout.resume(); worker.stderr.resume();
    const result=await new Promise(resolve=>{
      const timer=setTimeout(()=>resolve(null),900);
      const finish=x=>{clearTimeout(timer);resolve(x);};
      worker.once("message",finish);
      worker.once("error",()=>finish(null));
      worker.once("exit",()=>finish(null));
    });
    if(result?.status!=="danger")return null;
    return {status:403,allowed:false,lane:result.unknown?"KRISHNA":"ARJUNA",
      reason:result.unknown?"HISTORICAL_STRUCTURE_REVIEW":"HISTORICAL_DANGER_PATTERN",
      engine:"historical-passive"};
  } catch { return null; }
  finally {if(worker)try{await worker.terminate();}catch{} active--;}
}
module.exports={historicalDeny};
