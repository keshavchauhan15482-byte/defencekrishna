'use strict';

const assert = require('node:assert/strict');
const v2 = require('../defence-stack-v2-patch');
const { DetectionEngine } = require('../detection-engine');
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

function request(payload, ip = '203.0.113.210') {
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
      'user-agent': 'Krishna-Unknown-To-Known-Contract/1.0'
    },
    isLoginAttemptFailed: false
  };
}

const payload = '["constructor"]["prototype"]["isAdmin"]';

// 1) First sighting: this curated structure is unknown to learned memory and must
// route into Krishna's unknown-analysis path.
const first = new DetectionEngine(null).inspect(request(payload));
assert.equal(first.tier, 'danger');
assert.equal(first.isZeroDayAnomaly, true);

// 2) Krishna studies the incident. Learning is allowed only after independent
// redetection and the existing confidence/poisoning gates.
const counter = isolatedCounter();
const learned = counter.learnFromIncident({
  rawInput: JSON.stringify({ payload }),
  attackTypes: ['prototype-pollution'],
  sourceIp: '192.0.2.210',
  confidenceScore: 96
});

assert.equal(learned.validationRejected, undefined);
assert.equal(learned.confidenceRejected, undefined);
assert.equal(learned.poisoningSuspected, false);
assert.equal(learned.rootValidation.tier, 'danger');
assert.ok((learned.newlyLearned || []).length > 0, 'Krishna did not create reviewed root memory');
assert.ok((learned.mutationCandidates || 0) > 0, 'Krishna generated no bounded mutation candidates');
assert.ok((learned.mutationsValidated || 0) > 0, 'no mutation passed independent validation');
assert.ok(learned.mutationBudget, 'V2 mutation budget telemetry missing');
assert.equal(learned.mutationBudget.perToken, v2.mutationBudget.perToken);
assert.equal(learned.mutationBudget.perIncident, v2.mutationBudget.perIncident);
assert.ok(learned.mutationBudget.maxPerTokenObserved <= v2.mutationBudget.perToken);
assert.ok(learned.mutationCandidates <= v2.mutationBudget.perIncident);

// 3) Promotion: at least one independently validated mutation must be reusable
// by Arjuna. Unvalidated synthetic candidates are never authority.
const validated = (learned.newlyLearned || []).flatMap(entry => entry.validatedSyntheticMutations || []);
assert.ok(validated.length > 0);
const promotedMutation = validated.find(item => item && item.token && counter.checkLearned(item.token));
assert.ok(promotedMutation, 'no validated mutation became reusable Arjuna memory');

// 4) Replay the original previously-unknown structure with learned memory
// attached. The same event should now enter the known/Arjuna fast path.
const replay = new DetectionEngine(counter).inspect(request(payload, '203.0.113.211'));
assert.equal(replay.tier, 'danger');
assert.equal(replay.isLearnedMatch, true, 'original unknown incident did not become known to Arjuna');

console.log(JSON.stringify({
  status: 'PASS',
  transition: {
    firstSight: 'KRISHNA_UNKNOWN',
    replay: 'ARJUNA_KNOWN'
  },
  learning: {
    learnedRoots: learned.newlyLearned.length,
    generatedBeforeBudget: learned.mutationCandidatesGeneratedBeforeBudget || learned.mutationCandidates,
    evaluatedCandidates: learned.mutationCandidates,
    validatedForPromotion: learned.mutationsValidated,
    validationCoverage: learned.mutationValidationCoverage,
    maxPerTokenObserved: learned.mutationBudget.maxPerTokenObserved,
    perTokenCap: learned.mutationBudget.perToken,
    perIncidentCap: learned.mutationBudget.perIncident,
    budgetWithheld: learned.mutationCandidatesBudgetWithheld || 0
  },
  promotedMutationReuse: true,
  scope: 'deterministic local defensive contract; no external target traffic; not a production zero-day claim'
}, null, 2));
