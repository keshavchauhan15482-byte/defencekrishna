'use strict';

const assert = require('node:assert/strict');
const patch = require('../defence-stack-v3-patch');
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
      'user-agent': 'Krishna-Mutation-Limit-Test/2.0'
    },
    isLoginAttemptFailed: false
  };
}

assert.deepEqual(patch.mutationBudget, { perToken: 96, perIncident: 256 });
assert.equal(patch.maxLearnedTokensPerIncident, 8);

const novelPayload = '["constructor"]["prototype"]["isAdmin"]';
const novelVerdict = new DetectionEngine(null).inspect(request(novelPayload));
assert.equal(novelVerdict.tier, 'danger');
assert.equal(novelVerdict.isZeroDayAnomaly, true);

const counter = isolatedCounter();
const manyXss = Array.from({ length: 20 }, (_, i) => `<script>alert(${i})</script>`).join(' ');
const roots = counter._extractTokens(JSON.stringify({ payload: manyXss }), ['xss']);
assert.ok(roots.length > 0);
assert.ok(roots.length <= patch.maxLearnedTokensPerIncident, `root cap exceeded: ${roots.length}`);

for (const root of roots) {
  const variants = counter._generateSyntheticMutations(root, ['xss']);
  assert.ok(variants.length <= patch.mutationBudget.perToken, `runtime per-token mutation cap exceeded: ${variants.length}`);
}

const learned = counter.learnFromIncident({
  rawInput: JSON.stringify({ payload: manyXss }),
  attackTypes: ['xss'],
  sourceIp: '192.0.2.180',
  confidenceScore: 96
});
assert.ok((learned.newlyLearned || []).length <= patch.maxLearnedTokensPerIncident);
assert.ok((learned.mutationCandidates || 0) <= patch.mutationBudget.perIncident, `runtime incident mutation cap exceeded: ${learned.mutationCandidates}`);
assert.deepEqual(learned.mutationBudget && {
  perToken: learned.mutationBudget.perToken,
  perIncident: learned.mutationBudget.perIncident
}, patch.mutationBudget);

console.log(JSON.stringify({
  status: 'PASS',
  novelStructure: {
    tier: novelVerdict.tier,
    routedToKrishna: novelVerdict.isZeroDayAnomaly,
    attackType: novelVerdict.attackType
  },
  runtimeMutationBudget: patch.mutationBudget,
  maxLearnedTokensPerIncident: patch.maxLearnedTokensPerIncident,
  measuredIncident: {
    extractedRoots: roots.length,
    generatedBeforeBudget: learned.mutationCandidatesGeneratedBeforeBudget || learned.mutationCandidates || 0,
    evaluatedCandidates: learned.mutationCandidates || 0,
    budgetWithheld: learned.mutationCandidatesBudgetWithheld || 0,
    validatedForArjuna: learned.mutationsValidated || 0,
    maxPerTokenObserved: learned.mutationBudget && learned.mutationBudget.maxPerTokenObserved
  },
  scope: 'deterministic local defensive regression; no external target traffic'
}, null, 2));
