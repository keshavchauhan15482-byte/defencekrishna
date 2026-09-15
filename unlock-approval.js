'use strict';
// Offline operator utility. Each operator signs independently; private keys stay local.
const fs=require('node:fs'),crypto=require('node:crypto');
const [keyPath,signer,scopeKey,lockdownId]=process.argv.slice(2);
if (!keyPath || !signer || !scopeKey || !lockdownId) {
  console.error('Usage: node unlock-approval.js PRIVATE_KEY_PEM SIGNER SCOPE_KEY LOCKDOWN_ID');process.exit(2);
}
const key=crypto.createPrivateKey(fs.readFileSync(keyPath));
if (key.asymmetricKeyType!=='ed25519') throw new Error('Ed25519 private key required');
const approval={signer,scopeKey,lockdownId,expiresAt:Date.now()+120000};
console.log(JSON.stringify({...approval,signature:crypto.sign(null,Buffer.from(JSON.stringify(approval)),key).toString('base64')},null,2));
