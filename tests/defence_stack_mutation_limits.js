'use strict';

const assert = require('node:assert/strict');
const patch = require('../defence-stack-patch');
const { CounterEngine } = require('../counter-engine');
const { DetectionEngine } = require('../detection-engine');
const { BloomFilter } = require('../bloom-filter');

function isolatedCounter() {
  const counter = new CounterEngine();
  counter.learnedPatterns = [];
  counter.attackTypeWeights = {};
  counter.sourceIncidentHistory = new Map();
  counter.bloom = new BloomFilter(8192, 4);
  counter._persist = () => {};
  return counter;
}

function request(payload, ip = '203.0.113.90') {
  const body = { payload };
  const raw = JSON.stringify(body);
  return {
    ip,
    method: 'POST',
    path: '/api/input',
    url: '/api/input',
    query: {},
    body,
    rawBodyStr: raw,
    rawBodyBytes: Buffer.byteLength(raw),
    headers: {
      'content-type': 'application/json',
      'user-agent': 'Krishna-Mutation-Limit-Test/1.0'
    },
    isLoginAttemptFailed: false
  };
}

const limits = patch.mutationLimits;
assert.deepEqual(limits, {
  maxLearnedTokensPerIncident: 8,
  maxSyntheticMutationsPerToken: 128,
  maxRawMutationCandidatesPerIncident: 1024
});

// Regression for the previously missed fifth novel structural case. The raw
// JSON representation escapes quotes, so the detector must inspect primitive
// body/query values rather than relying on serialized JSON text alone.
const novelPayload = '["constructor"]["prototype"]["isAdmin"]';
const novelVerdict = new DetectionEngine(null).inspect(request(novelPayload));
assert.equal(novelVerdict.tier, 'danger');
assert.equal(novelVerdict.isZeroDayAnomaly, true);
assert.equal(novelVerdict.attackType, 'prototype-pollution');

// A single incident may contain many suspicious substrings. Krishna may retain
// at most eight learnable roots so one request cannot cause unbounded fan-out.
const counter = isolatedCounter();
const manyXss = Array.from({ length: 20 }, (_, i) => `<script>alert(${i})</script>`).join(' ');
const roots = counter._extractTokens(JSON.stringify({ payload: manyXss }), ['xss']);
assert.ok(roots.length > 0);
assert.ok(roots.length <= limits.maxLearnedTokensPerIncident, `root cap exceeded: ${roots.length}`);

for (const root of roots) {
  const variants = counter._generateSyntheticMutations(root, ['xss']);
  assert.ok(variants.length <= limits.maxSyntheticMutationsPerToken, `per-token mutation cap exceeded: ${variants.length}`);
}

const learned = counter.learnFromIncident({
  rawInput: JSON.stringify({ payload: manyXss }),
  attackTypes: ['xss'],
  sourceIp: '192.0.2.180',
  confidenceScore: 96
});
assert.ok((learned.newlyLearned || []).length <= limits.maxLearnedTokensPerIncident);
assert.ok((learned.mutationCandidates || 0) <= limits.maxRawMutationCandidatesPerIncident);
assert.deepEqual(learned.mutationLimits, limits);

console.log(JSON.stringify({
  status: 'PASS',
  novelStructure: {
    tier: novelVerdict.tier,
    routedToKrishna: novelVerdict.isZeroDayAnomaly,
    attackType: novelVerdict.attackType
  },
  mutationLimits: limits,
  measuredIncident: {
    extractedRoots: roots.length,
    mutationCandidates: learned.mutationCandidates || 0,
    validatedForArjuna: learned.mutationsValidated || 0
  },
  scope: 'deterministic local defensive regression; no external target traffic'
}, null, 2));
