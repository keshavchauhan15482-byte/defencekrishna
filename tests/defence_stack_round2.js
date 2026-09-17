'use strict';

const assert = require('node:assert/strict');
const { mutationPolicy } = require('../defence-stack-round2-patch');
const { DetectionEngine } = require('../detection-engine');
const { CounterEngine } = require('../counter-engine');
const { BloomFilter } = require('../bloom-filter');

function request(payload, ip = '203.0.113.77') {
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
    headers: {
      'content-type': 'application/json',
      'user-agent': 'Krishna-Defence-Round2-Local-Test/1.0'
    },
    isLoginAttemptFailed: false
  };
}

function isolatedCounter() {
  const counter = new CounterEngine();
  counter.learnedPatterns = [];
  counter.attackTypeWeights = {};
  counter.sourceIncidentHistory = new Map();
  counter.bloom = new BloomFilter(8192, 4);
  counter._persist = () => {};
  return counter;
}

const checks = [];
function check(name, fn) {
  fn();
  checks.push(name);
}

check('Escaped JSON bracket-notation prototype chain routes to Krishna', () => {
  const payload = '["constructor"]["prototype"]["isAdmin"]';
  const result = new DetectionEngine(null).inspect(request(payload));
  assert.equal(result.tier, 'danger');
  assert.equal(result.isZeroDayAnomaly, true);
  assert.equal(result.attackType, 'prototype-pollution');
});

check('Mutation policy exposes explicit bounded research budget', () => {
  assert.equal(mutationPolicy.maxPerToken, 64);
  assert.equal(mutationPolicy.maxPerIncident, 256);
});

check('A deliberately complex local token cannot generate more than 64 variants', () => {
  const counter = isolatedCounter();
  const complex = "UNION SELECT username FROM users WHERE 1=1; cat ../../etc/passwd http://127.0.0.1/internal <script>alert(document.cookie)</script> constructor.prototype.isAdmin *__proto__ cmd|";
  const generated = counter._generateSyntheticMutations(complex, ['local-multi-vector-test']);
  assert.equal(generated.length, mutationPolicy.maxPerToken);
});

let learned;
check('One unknown-to-known incident stays within the 256-candidate mutation budget', () => {
  const counter = isolatedCounter();
  const payload = [
    'UNION SELECT username,password FROM users WHERE id=1',
    'UNION SELECT email,token FROM sessions WHERE 1=1',
    '<script>alert(document.cookie)</script>',
    '<script>alert(1)</script>',
    'http://127.0.0.1/internal/admin',
    '../../../../etc/passwd',
    '; cat /etc/passwd',
    '{{7*7}}'
  ].join(' ; ');

  learned = counter.learnFromIncident({
    rawInput: JSON.stringify({ payload }),
    attackTypes: ['local-multi-vector-test'],
    sourceIp: '192.0.2.180',
    confidenceScore: 96
  });

  assert.ok((learned.newlyLearned || []).length > 0);
  assert.ok(learned.mutationBudget);
  assert.equal(learned.mutationBudget.maxPerToken, 64);
  assert.equal(learned.mutationBudget.maxPerIncident, 256);
  assert.ok(learned.mutationBudget.retainedForValidation <= 256);
  assert.ok((learned.mutationCandidates || 0) <= 256);
  assert.ok((learned.mutationsValidated || 0) <= (learned.mutationCandidates || 0));
  for (const entry of learned.newlyLearned || []) {
    assert.ok((entry.syntheticMutations || []).length <= 64);
  }
});

console.log(JSON.stringify({
  status: 'PASS',
  passed: checks.length,
  checks,
  mutationPolicy,
  measuredIncident: learned ? {
    learnedRoots: (learned.newlyLearned || []).length,
    rawGeneratedBeforeBudget: learned.mutationBudget.rawGeneratedBeforeBudget,
    retainedForValidation: learned.mutationBudget.retainedForValidation,
    droppedByBudget: learned.mutationBudget.droppedByBudget,
    independentlyValidated: learned.mutationsValidated || 0,
    validationCoverage: learned.mutationValidationCoverage || 0,
    budgetExhausted: learned.mutationBudget.exhausted
  } : null,
  scope: 'owned/local deterministic defensive validation; no external target traffic'
}, null, 2));
