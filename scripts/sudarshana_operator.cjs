"use strict";
/* Local-only operator ceremony. Private keys never enter deployment env or Git.
 * Each approver independently runs keygen/sign on their own trusted machine.
 * No network calls, policy writes, automatic publishing or IP discovery.
 */
const fs=require("node:fs"),path=require("node:path");
const {generateKeyPairSync,createPrivateKey,createPublicKey,sign}=require("node:crypto");
const {isIP}=require("node:net");
const {verifiedScope}=require("../deployment/vercel/signed_scope.js");
const ROUTES=new Set(["security-check","live-events","site-activity"]);
function requireThat(ok,msg){if(!ok)throw Error(msg);}
function validId(id){return typeof id==="string"&&/^[A-Za-z0-9_-]{3,48}$/.test(id);}
function read(file,max=8192){requireThat(fs.statSync(file).size<=max,"Input too large");return fs.readFileSync(file,"utf8");}
function write(file,text){fs.writeFileSync(file,text,{mode:0o600,flag:"wx"});}
function outsideRepo(dir){
  const abs=fs.realpathSync(dir);
  const root=fs.realpathSync(path.resolve(__dirname,".."));
  requireThat(abs!==root&&!abs.startsWith(root+path.sep),"Use a private directory outside the repository");
  for(let p=abs;;p=path.dirname(p)){
    requireThat(!fs.existsSync(path.join(p,".git")),"Do not use a Git working directory");
    if(path.dirname(p)===p)break;
  }
  return abs;
}
function keygen(dir,id){
  requireThat(validId(id),"Invalid approver ID");
  fs.mkdirSync(dir,{recursive:true,mode:0o700});const target=outsideRepo(dir);
  requireThat((fs.statSync(target).mode&0o077)===0,"Key directory permissions must be 0700");
  const keys=generateKeyPairSync("ed25519");
  write(path.join(target,id+".private.pem"),keys.privateKey.export({format:"pem",type:"pkcs8"}));
  write(path.join(target,id+".public.pem"),keys.publicKey.export({format:"pem",type:"spki"}));
}
function proposal(route,ip,incidentRef,ttl,now=Math.floor(Date.now()/1000)){
  requireThat(ROUTES.has(route),"Invalid route");
  requireThat(isIP(ip)&&!ip.includes("%"),"Exact authorized client IP required");
  requireThat(/^[A-Za-z0-9_-]{8,96}$/.test(incidentRef),"Valid independently recorded incident reference required");
  requireThat(Number.isSafeInteger(ttl)&&ttl>=10&&ttl<=900,"TTL must be 10-900 seconds");
  return JSON.stringify({schema:"krishna-scope-v1",audience:"krishna-defence-system.vercel.app",route,target_ip:ip,
    incident_ref:incidentRef,evidence_kind:"operator_confirmed_escape",issued_at:now,expires_at:now+ttl});
}
function approve(payload,id,privateKeyFile){
  requireThat(validId(id),"Invalid approver ID");
  const p=JSON.parse(payload),now=Date.now()/1000;
  requireThat(p.schema==="krishna-scope-v1"&&p.audience==="krishna-defence-system.vercel.app"&&ROUTES.has(p.route)&&
    isIP(p.target_ip)&&p.evidence_kind==="operator_confirmed_escape"&&
    /^[A-Za-z0-9_-]{8,96}$/.test(p.incident_ref)&&Number.isSafeInteger(p.issued_at)&&Number.isSafeInteger(p.expires_at)&&
    p.issued_at<=now&&p.expires_at>now&&p.expires_at-p.issued_at<=900,"Invalid or expired proposal");
  requireThat((fs.statSync(privateKeyFile).mode&0o077)===0,"Private key permissions must be 0600");
  const key=createPrivateKey(read(privateKeyFile));
  requireThat(key.asymmetricKeyType==="ed25519","Ed25519 key required");
  return {key_id:id,signature:sign(null,Buffer.from(payload),key).toString("base64")};
}
function assemble(payload,approvals,publicKeys,now=Date.now()/1000){
  const env={SUDARSHANA_POLICY_MODE:"enforce",SUDARSHANA_APPROVER_KEYS:JSON.stringify(publicKeys),
    SUDARSHANA_SIGNED_POLICY:JSON.stringify({payload,approvals})};
  requireThat(verifiedScope(env,now),"Approval verification failed");
  return env;
}
function cli(args){
 const [cmd,...a]=args;
 if(cmd==="keygen"&&a.length===2){keygen(a[0],a[1]);console.log("Local key pair created. Share the public PEM only.");return;}
 if(cmd==="propose"&&a.length===6){
   const [route,ip,ref,ttl,file,consent]=a;
   requireThat(consent==="CONFIRMED_ESCAPE_AND_AUTHORIZED_TARGET","Verified incident and authorized scope confirmation required");
   write(file,proposal(route,ip,ref,Number(ttl)));console.log("Proposal created; two real independent approvals required.");return;
 }
 if(cmd==="approve"&&a.length===5){
   const [file,id,key,out,consent]=a;requireThat(consent==="INDEPENDENTLY_REVIEWED","Review incident evidence and scope before approval");
   write(out,JSON.stringify(approve(read(file),id,key)));console.log("Detached approval written; do not share the private key.");return;
 }
 if(cmd==="assemble"&&a.length===4){
   const [file,approvals,publicKeys,out]=a;
   write(out,JSON.stringify(assemble(read(file),JSON.parse(read(approvals)),JSON.parse(read(publicKeys))),null,2));
   console.log("Verified policy bundle written locally. Nothing has been deployed.");return;
 }
 throw Error("Usage: keygen DIR ID | propose ROUTE IP INCIDENT TTL OUTPUT CONFIRMED_ESCAPE_AND_AUTHORIZED_TARGET | approve PROPOSAL ID PRIVATE_KEY OUTPUT INDEPENDENTLY_REVIEWED | assemble PROPOSAL APPROVAL_ARRAY_JSON PUBLIC_KEY_MAP_JSON OUTPUT");
}
if(require.main===module){try{cli(process.argv.slice(2));}catch(e){console.error(e.message);process.exitCode=1;}}
module.exports={keygen,proposal,approve,assemble};
