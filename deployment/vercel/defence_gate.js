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
  const supplied=url.searchParams.getAll("record");
  // Vercel serverless can attach deployment/protection routing parameters
  // to request.url and request.query. Only the explicit record key has
  // authority; all other metadata is deliberately ignored, never used.
  // Prevent duplicate/multi-value records from overriding an access decision.
  const query=(request.query&&typeof request.query==="object"&&!Array.isArray(request.query))
    ? request.query:{};
  if(supplied.length>1)
    return {error:"INVALID_PARAMETERS",status:422};
  const obj=Object.prototype.hasOwnProperty.call(query,"record")?query.record:null;
  if(obj!==null&&typeof obj!=="string")
    return {error:"INVALID_PARAMETERS",status:422};
  if(supplied.length===1&&obj!==null&&supplied[0]!==obj)
    return {error:"CONFLICTING_PARAMETERS",status:422};
  const value=supplied.length===1?supplied[0]:obj;
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
function checkKnownApiInput(value){
  // Only parse bounded, untrusted QUERY values on actual read-only API routes.
  // Never inspect model outputs or treat a risk score as enforcement authority.
  if(typeof value!=="string")return null;
  if(value.length>MAX_PROBE_LENGTH)
    return {lane:"BOUNDARY",status:422,reason:"API_INPUT_TOO_LARGE"};
  for(const rule of KNOWN){
    if(rule.test.test(value))
      return {lane:"ARJUNA",status:403,reason:rule.id};
  }
  if(STRUCTURAL.test(value))
    return {lane:"KRISHNA",status:403,reason:"STRUCTURAL_ANOMALY_REVIEW"};
  return null;
}
module.exports={inspectRequest,parseRecord,checkKnownApiInput,MAX_PROBE_LENGTH};