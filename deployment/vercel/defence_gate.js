"use strict";
/**
 * Production-safe request gate for the public *dummy* security lab and bounded
 * public API inputs. Deliberately not a substitute for the historical private
 * Arjuna/Krishna/Sudarshana proxy, nor an AI model.
 *
 * Arjuna    = deterministic known malicious patterns (blocking).
 * Krishna   = unusual structural input (review/deny on this test endpoint).
 * Sudarshan = explicit public/private dummy-record authorization boundary.
 * Garuda    = independent SHADOW_ONLY PCAP forecaster; NEVER a block authority.
 *
 * Never accepts source IPs, rate-limit keys, policies or model probabilities
 * from a browser as trustworthy enforcement instructions.
 */
const MAX_PROBE_LENGTH=512;
const DENY=Object.freeze({allowed:false,status:403});
const KNOWN=Object.freeze([
  {id:"SQLI_SIGNATURE",test:/(?:\bunion\s+(?:all\s+)?select\b|(?:'|")\s*(?:or|and)\s+(?:\d+|'[^']+')\s*=\s*(?:\d+|'[^']+')|;\s*(?:drop|alter|delete)\s+(?:table|from)\b|\b(?:sleep|benchmark)\s*\()/i},
  {id:"XSS_SIGNATURE",test:/(?:<\s*script\b|<\s*svg\b[^>]*\bonload\s*=|\bon(?:error|load|click)\s*=|javascript\s*:|<\s*iframe\b)/i},
  {id:"TRAVERSAL_SIGNATURE",test:/(?:\.\.[/\\]|%2e%2e|%252e%252e|\/etc\/passwd|\.env\b)/i},
  {id:"COMMAND_SIGNATURE",test:/(?:[;&|]\s*(?:whoami|cat|curl|wget|sh|bash|rm)\b|\$\(\s*(?:id|whoami|cat)\b)/i},
]);
const STRUCTURAL=/(?:__proto__|constructor\s*(?:\.|\[)\s*prototype|prototype\s*(?:\.|\[)\s*(?:admin|isAdmin)|\$\{[^}]{0,100}\}|%25(?:2e|3c|27))/i;
function parseRecord(request){
  const raw=typeof request.url==="string"?request.url:"/api/security-check";
  if(raw.length>2048)return {error:"REQUEST_TOO_LARGE",status:413};
  let url;
  try{url=new URL(raw,"https://security-lab.invalid");}
  catch{return {error:"INVALID_URL",status:422};}
  if(url.pathname!=="/api/security-check")
    return {error:"INVALID_ROUTE",status:404};
  const keys=[...url.searchParams.keys()];
  if(keys.length>1||keys.some(k=>k!=="record")||
     url.searchParams.getAll("record").length!==1)
    return {error:"INVALID_PARAMETERS",status:422};
  const value=url.searchParams.get("record");
  if(value===null||value.length===0||value.length>MAX_PROBE_LENGTH)
    return {error:"INVALID_INPUT",status:422};
  return {value};
}
function inspectRequest(request){
  if(request.method!=="GET")
    return {allowed:false,status:405,lane:"BOUNDARY",reason:"METHOD_NOT_ALLOWED"};
  if(request.headers?.["content-length"]&&Number(request.headers["content-length"])>0)
    return {allowed:false,status:413,lane:"BOUNDARY",reason:"GET_BODY_REJECTED"};
  const entry=parseRecord(request);
  if(entry.error)return {allowed:false,status:entry.status,lane:"BOUNDARY",reason:entry.error};
  const payload=entry.value;
  for(const rule of KNOWN){
    if(rule.test.test(payload)){
      return {...DENY,lane:"ARJUNA",reason:rule.id};
    }
  }
  if(STRUCTURAL.test(payload)||/%[a-f0-9]{2}/i.test(payload)){
    return {...DENY,lane:"KRISHNA",reason:"STRUCTURAL_ANOMALY_REVIEW"};
  }
  // The deliberately private fixture must never be revealed to browsers.
  // This is server-side object authorization, not an ML or IP-blocking claim.
  if(payload==="demo-private"||payload.startsWith("demo-private/")){
    return {...DENY,lane:"SUDARSHAN",reason:"FIXTURE_SCOPE_DENIED"};
  }
  if(payload==="demo-public"){
    return {allowed:true,status:200,lane:"ARJUNA",reason:"PUBLIC_FIXTURE_ALLOWED"};
  }
  return {allowed:false,status:404,lane:"BOUNDARY",reason:"NO_PUBLIC_FIXTURE"};
}
module.exports={inspectRequest,parseRecord,MAX_PROBE_LENGTH};