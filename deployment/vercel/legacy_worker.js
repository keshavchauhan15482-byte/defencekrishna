"use strict";
// A disposable, resource-bounded worker for passive inspection of invalid
// request fields. Never load demo memory, proxy, fuzzer, or operator tokens.
const { parentPort, workerData } = require("node:worker_threads");
require("../../defence-stack-patch.js");
const { DetectionEngine } = require("../../detection-engine.js");
try {
  const value = workerData.value;
  if (typeof value !== "string" || Buffer.byteLength(value) > 512) throw Error("bounds");
  const body = JSON.stringify({payload:value});
  const result = new DetectionEngine(null).inspect({
    ip:"192.0.2.250", method:"POST", path:"/mutation-validation",
    url:"/mutation-validation", query:{}, body:{payload:value},
    rawBodyStr:body, rawBodyBytes:Buffer.byteLength(body),
    headers:{"content-type":"application/json","user-agent":"Krishna-Hosted-Passive-Inspector/1.0"},
    isLoginAttemptFailed:false
  });
  parentPort.postMessage({status:result.tier==="danger"?"danger":"not-danger",
    unknown:result.isZeroDayAnomaly===true});
} catch { parentPort.postMessage({status:"unavailable"}); }
