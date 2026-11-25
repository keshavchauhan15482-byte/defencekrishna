"use strict";
const {createPublicKey,createHash,verify}=require("node:crypto");
const {isIP}=require("node:net");
const AUDIENCE="krishna-defence-system.vercel.app";
const ROUTES=new Set(["live-events","site-activity","security-check"]);
function canonicalIp(value) {
  if(typeof value!=="string"||value.length>64||value.includes("%"))return null;
  const type=isIP(value);
  if(type===4)return value;
  if(type===6)try{return new URL("http://["+value+"]/").hostname.slice(1,-1);}catch{}
  return null;
}
function verifiedScope(env,now=Date.now()/1000) {
  // Explicit operator activation only; neither forecasts nor requests can
  // publish policy. Deployment env is a bounded snapshot, not a policy store.
  if(env.SUDARSHANA_POLICY_MODE!=="enforce"||env.SUDARSHANA_EMERGENCY_STOP==="1")return null;
  try{
    const raw=env.SUDARSHANA_SIGNED_POLICY||"", keysRaw=env.SUDARSHANA_APPROVER_KEYS||"";
    if(raw.length>8192||keysRaw.length>8192)return null;
    const envelope=JSON.parse(raw),keys=JSON.parse(keysRaw);
    if(typeof envelope.payload!=="string"||envelope.payload.length>2048||!Array.isArray(envelope.approvals)||envelope.approvals.length!==2)return null;
    const p=JSON.parse(envelope.payload);
    if(p.schema!=="krishna-scope-v1"||p.audience!==AUDIENCE||!ROUTES.has(p.route)||
      p.evidence_kind!=="operator_confirmed_escape"||typeof p.incident_ref!=="string"||
      !/^[A-Za-z0-9_-]{8,96}$/.test(p.incident_ref)||!canonicalIp(p.target_ip)||
      !Number.isSafeInteger(p.issued_at)||!Number.isSafeInteger(p.expires_at)||
      p.issued_at>now||p.expires_at<=now||p.expires_at<=p.issued_at||
      p.expires_at-p.issued_at>900)return null;
    const distinct=new Set();
    for(const a of envelope.approvals) {
      if(typeof a?.key_id!=="string"||!Object.prototype.hasOwnProperty.call(keys,a.key_id)||
        typeof a.signature!=="string"||!/^[A-Za-z0-9+/]{86}==$/.test(a.signature))return null;
      const pub=createPublicKey(keys[a.key_id]);
      if(pub.asymmetricKeyType!=="ed25519")return null;
      const fingerprint=createHash("sha256").update(pub.export({type:"spki",format:"der"})).digest("hex");
      if(distinct.has(fingerprint)||!verify(null,Buffer.from(envelope.payload),pub,Buffer.from(a.signature,"base64")))return null;
      distinct.add(fingerprint);
    }
    return p;
  }catch{return null;}
}
function scopeMatches(req,route,env=process.env,now=Date.now()/1000) {
  if(env.VERCEL!=="1"||env.VERCEL_ENV!=="production"||req.headers?.host!==AUDIENCE)return false;
  const p=verifiedScope(env,now);
  const ip=canonicalIp(req.headers?.["x-vercel-forwarded-for"]);
  return !!p&&!!ip&&p.route===route&&canonicalIp(p.target_ip)===ip;
}
function applySignedContainment(req,res,route){
  if(!scopeMatches(req,route))return false;
  res.setHeader("X-Krishna-Lane","SUDARSHAN");
  res.setHeader("X-Krishna-Decision","deny");
  res.setHeader("X-Krishna-Engine","verified-signed-scope");
  res.status(403).json({ok:false,error:"Scoped access denied",lane:"SUDARSHAN",decision:"DENY",reason:"OPERATOR_SIGNED_CONTAINMENT",automatic_ip_lockdown:false});
  return true;
}
module.exports={verifiedScope,scopeMatches,applySignedContainment};
