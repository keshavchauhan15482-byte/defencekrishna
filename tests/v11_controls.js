'use strict';
const assert=require('node:assert/strict');
const crypto=require('node:crypto');
const fs=require('node:fs');
const os=require('node:os');
const path=require('node:path');
const {SudarshanaCore}=require('../sudarshana-core');
const {PolicyGuard}=require('../policy-guard');
const pairs={lead:crypto.generateKeyPairSync('ed25519'),ops:crypto.generateKeyPairSync('ed25519')};
const keys=Object.fromEntries(Object.entries(pairs).map(([id,p])=>[id,p.publicKey.export({format:'pem',type:'spki'})]));
const core=new SudarshanaCore({unlockPublicKeys:keys});
const checks=[];
function check(name,fn){fn();checks.push(name);}
function lock(){return core.engageScopedLockdown({scopeType:'ip',scopeValue:'127.0.0.2',incidentId:'lab',reason:'Controlled test'});}
function approval(signer,l){const a={signer,scopeKey:l.scopeKey,lockdownId:l.id,expiresAt:Date.now()+60000};return {...a,signature:crypto.sign(null,Buffer.from(JSON.stringify(a)),pairs[signer].privateKey).toString('base64')};}
let l=lock();
check('Escalation retains containment',()=>{core.evaluateAutonomousRecovery({scopeType:'ip',scopeValue:'127.0.0.2',krishnaAnalysis:{confidenceScore:0}});assert.equal(core.isUnderLockdown({ip:'127.0.0.2'}).locked,true);});
check('Unrelated client remains allowed',()=>assert.equal(core.isUnderLockdown({ip:'127.0.0.3'}).locked,false));
check('Hardcoded legacy strings rejected',()=>assert.equal(core.multiPartyUnlock({scopeType:'ip',scopeValue:'127.0.0.2',signatures:['SIG_SEC_LEAD_2026','SIG_OPS_DIR_2026']}).ok,false));
const a=approval('lead',l),b=approval('ops',l);
check('Duplicate signer rejected',()=>assert.equal(core.multiPartyUnlock({scopeType:'ip',scopeValue:'127.0.0.2',signatures:[a,a]}).ok,false));
check('Non-string signer identity rejected',()=>{
 const raw={signer:['lead'],scopeKey:l.scopeKey,lockdownId:l.id,expiresAt:Date.now()+60000};
 const forged={...raw,signature:crypto.sign(null,Buffer.from(JSON.stringify(raw)),pairs.lead.privateKey).toString('base64')};
 assert.equal(core.multiPartyUnlock({scopeType:'ip',scopeValue:'127.0.0.2',signatures:[forged,{...forged,signer:['lead']}]}).ok,false);
});
check('Two aliases of one public key are not independent approvals',()=>{
 core.unlockPublicKeys.alias=keys.lead;
 const raw={signer:'alias',scopeKey:l.scopeKey,lockdownId:l.id,expiresAt:Date.now()+60000};
 const alias={...raw,signature:crypto.sign(null,Buffer.from(JSON.stringify(raw)),pairs.lead.privateKey).toString('base64')};
 assert.equal(core.multiPartyUnlock({scopeType:'ip',scopeValue:'127.0.0.2',signatures:[a,alias]}).ok,false);
});
check('Tampered approval rejected',()=>assert.equal(core.multiPartyUnlock({scopeType:'ip',scopeValue:'127.0.0.2',signatures:[a,{...b,signature:'AAAA'}]}).ok,false));
check('Two independent approvals release scope',()=>{assert.equal(core.multiPartyUnlock({scopeType:'ip',scopeValue:'127.0.0.2',signatures:[a,b]}).ok,true);assert.equal(core.isUnderLockdown({ip:'127.0.0.2'}).locked,false);});
l=lock();
check('Previous-lock approval replay rejected',()=>assert.equal(core.multiPartyUnlock({scopeType:'ip',scopeValue:'127.0.0.2',signatures:[a,b]}).ok,false));
check('Genesis tampering detected',()=>{core.ledger[0].data.message='changed';assert.equal(core.verifyLedgerIntegrity().isValid,false);});
const rotated=new SudarshanaCore();
check('Retained ledger chain remains consistent',()=>{for(let i=0;i<205;i++)rotated._appendBlock({i});assert.equal(rotated.ledger.length,200);assert.equal(rotated.verifyLedgerIntegrity().isValid,true);assert.equal(rotated.ledger.at(-1).index,205);});
const folder=fs.mkdtempSync(path.join(os.tmpdir(),'garuda-policy-'));const file=path.join(folder,'policy.json');const secret=crypto.randomBytes(32).toString('hex');
function write(payload,signature){payload=JSON.stringify(payload);fs.writeFileSync(file,JSON.stringify({payload,signature:signature||crypto.createHmac('sha256',secret).update(payload).digest('hex')}));}
try{
 const guard=new PolicyGuard(file,secret),t=Date.now()/1000;
 const policy={version:1,issued_at:t,policies:[{id:'lab',target:'127.0.0.2',expires:t+60,status:'active'}]};
 write(policy);guard.reload();
 check('Signed scope matches',()=>assert.ok(guard.match('127.0.0.2')));
 write({...policy,policies:[]},'00');guard.reload();
 check('Tampering cannot clear last verified policy',()=>assert.ok(guard.match('127.0.0.2')));
 write({version:1,issued_at:t-1,policies:[]});guard.reload();
 check('Older signed policy cannot revoke',()=>assert.ok(guard.match('127.0.0.2')));
 write({version:1,issued_at:t+.001,policies:[]});guard.reload();
 check('Fresh signed emergency revoke works',()=>assert.equal(guard.match('127.0.0.2'),undefined));
}finally{fs.rmSync(folder,{recursive:true,force:true});}
console.log(JSON.stringify({passed:checks.length,checks,scope:'local module controls; not enterprise prevention'},null,2));
