'use strict';

const assert = require('node:assert/strict');
const patch = require('../defence-stack-v4-patch');
const { CounterEngine } = require('../counter-engine');
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

function expectedTrustedBloom(patterns) {
  const expected = new BloomFilter(8192, 4);
  const { roots, mutations } = patch.trustedTokens(patterns);
  for (const token of roots) expected.add(token);
  for (const token of mutations) expected.add(token);
  return expected;
}

const counter = isolatedCounter();
const learned = counter.learnFromIncident({
  rawInput: JSON.stringify({ payload: 'UNION SELECT username,password FROM users WHERE id=1' }),
  attackTypes: ['sql-injection'],
  sourceIp: '192.0.2.220',
  confidenceScore: 96
});

assert.ok((learned.newlyLearned || []).length > 0, 'verified incident did not create reviewed roots');
assert.ok((learned.mutationCandidates || 0) > 0, 'no mutation candidates were evaluated');
assert.ok((learned.mutationsValidated || 0) > 0, 'no mutation candidates were independently validated');

const expected = expectedTrustedBloom(counter.learnedPatterns);
assert.equal(
  counter.bloom.toBase64(),
  expected.toBase64(),
  'Bloom memory contains entries outside reviewed roots + validated mutations'
);

const trusted = learned.trustedMemory;
assert.ok(trusted, 'trusted-memory telemetry missing');
assert.equal(trusted.bloomSizeBytes, 1024, 'Bloom memory size changed unexpectedly');
assert.equal(trusted.reviewedRoots, counter.learnedPatterns.length, 'reviewed-root telemetry mismatch');
assert.ok(trusted.validatedMutations > 0, 'trusted mutation count missing');
assert.equal(trusted.trustedEntries, trusted.reviewedRoots + trusted.validatedMutations);
assert.ok(trusted.bloomBitLoad >= 0 && trusted.bloomBitLoad <= 1);
assert.ok(trusted.estimatedBloomMaybeRate >= 0 && trusted.estimatedBloomMaybeRate <= 1);

const rejectedCount = counter.learnedPatterns.reduce(
  (sum, entry) => sum + ((entry.rejectedSyntheticMutations || []).length),
  0
);
assert.ok(rejectedCount > 0, 'fixture should include at least one rejected mutation to exercise trusted-memory filtering');

const stats = counter.stats();
assert.equal(stats.trustedMemory.trustedEntries, trusted.trustedEntries);
assert.ok(!String(stats.note || '').includes('no matter how many patterns are learned'), 'legacy unbounded-memory wording survived');

const forecast = counter.getPredictiveForecast(100);
assert.ok(!String(forecast.rAndDReadinessIndex || '').includes('98.7'), 'hard-coded readiness percentage survived');
assert.match(String(forecast.rAndDReadinessIndex || ''), /validated mutation coverage/i);
assert.ok(Number.isFinite(forecast.mutationValidationCoverage));

console.log(JSON.stringify({
  status: 'PASS',
  trustedMemory: trusted,
  mutationValidation: {
    candidates: learned.mutationCandidates || 0,
    validated: learned.mutationsValidated || 0,
    rejectedEvidenceRecords: rejectedCount,
    coverage: learned.mutationValidationCoverage || 0
  },
  readinessField: forecast.rAndDReadinessIndex,
  scope: 'deterministic local defensive trusted-memory regression; no external target traffic'
}, null, 2));
