'use strict';

const assert = require('node:assert/strict');
require('../defence-evidence-hardening');
const { DetectionEngine } = require('../detection-engine');

function req(ip, payload) {
  const body = { payload };
  const rawBodyStr = JSON.stringify(body);
  return {
    ip,
    method: 'POST',
    path: '/api/input',
    url: '/api/input',
    query: {},
    body,
    rawBodyStr,
    rawBodyBytes: Buffer.byteLength(rawBodyStr),
    headers: { 'content-type': 'application/json', 'user-agent': 'Krishna-Structural-Regression/1.0' },
    isLoginAttemptFailed: false
  };
}

const engine = new DetectionEngine(null);
const structural = engine.inspect(req('203.0.113.80', '["constructor"]["prototype"]["isAdmin"]'));
assert.equal(structural.tier, 'danger');
assert.equal(structural.isZeroDayAnomaly, true);
assert.equal(structural.attackType, 'prototype-pollution');
assert.ok((structural.reasons || []).some(r => String(r).includes('constructor/prototype')));

const benign = engine.inspect(req('203.0.113.81', 'constructor and prototype are JavaScript programming terms'));
assert.notEqual(benign.tier, 'danger');
assert.equal(Boolean(benign.isZeroDayAnomaly), false);

console.log(JSON.stringify({
  passed: 2,
  structural: { tier: structural.tier, score: structural.score, attackType: structural.attackType },
  benign: { tier: benign.tier, score: benign.score },
  scope: 'local deterministic structural-evidence regression; not real-world zero-day proof'
}, null, 2));
