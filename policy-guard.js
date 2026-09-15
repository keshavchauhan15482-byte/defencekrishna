'use strict';
const fs = require('fs');
const crypto = require('crypto');
const net = require('net');
class PolicyGuard {
  constructor(file, key) { this.file = file; this.key = key; this.policies = []; this.status = 'disabled'; this.lastRead = 0; this.highestIssued = -Infinity; this.lastPayload = null; }
  reload() {
    if (!this.file || !this.key || this.key.length < 32) return;
    try {
      if (fs.statSync(this.file).size > 100000) throw new Error('Policy size exceeded');
      const envelope = JSON.parse(fs.readFileSync(this.file, 'utf8'));
      const expected = crypto.createHmac('sha256', this.key).update(envelope.payload).digest();
      const supplied = Buffer.from(envelope.signature, 'hex');
      if (expected.length !== supplied.length || !crypto.timingSafeEqual(expected, supplied)) throw new Error('Invalid signature');
      const data = JSON.parse(envelope.payload);
      if (data.version !== 1 || !Array.isArray(data.policies) || data.policies.length > 100 || !Number.isFinite(data.issued_at) || data.issued_at > Date.now()/1000+5) throw new Error('Invalid policy');
      if (data.issued_at < this.highestIssued || (data.issued_at === this.highestIssued && envelope.payload !== this.lastPayload)) throw new Error('Replayed policy');
      if (data.policies.some(p => !net.isIP(p.target) || !Number.isFinite(p.expires) || p.expires <= data.issued_at || p.expires - data.issued_at > 900 || p.status !== 'active')) throw new Error('Invalid scope/expiry');
      this.policies = data.policies; this.status = 'verified'; this.highestIssued = data.issued_at; this.lastPayload = envelope.payload;
    } catch (_) { this.status = this.lastPayload ? 'invalid_update_retaining_verified_policy_until_expiry' : 'invalid_or_unavailable'; }
  }
  match(ip) {
    if (Date.now() - this.lastRead > 250) { this.reload(); this.lastRead = Date.now(); }
    return this.policies.find(p => p.target === ip.replace(/^::ffff:/,'') && p.expires > Date.now()/1000);
  }
}
module.exports = { PolicyGuard };
