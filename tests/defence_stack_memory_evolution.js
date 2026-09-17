'use strict';

const assert = require('node:assert/strict');
const patch = require('../defence-stack-v3-patch');
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

function learn(counter, payload, type, ip) {
  return counter.learnFromIncident({
    rawInput: JSON.stringify({ payload }),
    attackTypes: [type],
    sourceIp: ip,
    confidenceScore: 96
  });
}

assert.equal(patch.canonicalMemoryDedupe, true);
assert.deepEqual(patch.mutationBudget, { perToken: 96, perIncident: 256 });
assert.equal(patch.maxLearnedTokensPerIncident, 8);

const counter = isolatedCounter();
const firstPayload = 'UNION SELECT username,password FROM users WHERE id=1';
const first = learn(counter, firstPayload, 'sql-injection', '192.0.2.201');
const rootsAfterFirst = counter.learnedPatterns.length;
assert.ok(rootsAfterFirst > 0, 'first verified incident did not add any roots');
assert.ok((first.newlyLearned || []).length > 0, 'first incident should create reviewed roots');
assert.ok((first.mutationCandidates || 0) <= patch.mutationBudget.perIncident, 'first incident exceeded runtime mutation budget');

const exactReplay = learn(counter, firstPayload, 'sql-injection', '192.0.2.202');
assert.equal(counter.learnedPatterns.length, rootsAfterFirst, 'exact replay inflated reviewed root memory');
assert.equal((exactReplay.newlyLearned || []).length, 0, 'exact replay was incorrectly promoted as new knowledge');
assert.ok((exactReplay.canonicalDuplicatesSuppressed || 0) > 0, 'exact replay did not report duplicate suppression');

const caseVariant = 'union select USERNAME,PASSWORD from USERS where ID=1';
const caseReplay = learn(counter, caseVariant, 'sql-injection', '192.0.2.203');
assert.equal(counter.learnedPatterns.length, rootsAfterFirst, 'case-only replay inflated reviewed root memory');
assert.equal((caseReplay.newlyLearned || []).length, 0, 'case-only replay was incorrectly promoted as new knowledge');
assert.ok((caseReplay.canonicalDuplicatesSuppressed || 0) > 0, 'case-only replay did not report canonical duplicate suppression');

const distinctPayload = '<script>alert(document.cookie)</script>';
const distinct = learn(counter, distinctPayload, 'xss', '192.0.2.204');
assert.ok(counter.learnedPatterns.length > rootsAfterFirst, 'genuinely distinct verified attack failed to evolve memory');
assert.ok((distinct.newlyLearned || []).length > 0, 'distinct attack did not create new reviewed roots');
assert.ok((distinct.mutationCandidates || 0) <= patch.mutationBudget.perIncident, 'distinct incident exceeded runtime mutation budget');

console.log(JSON.stringify({
  status: 'PASS',
  mutationBudget: patch.mutationBudget,
  firstIncident: {
    rootsAdded: first.memoryEvolution && first.memoryEvolution.rootsAdded,
    mutationCandidates: first.mutationCandidates || 0,
    validatedMutations: first.mutationsValidated || 0
  },
  exactReplay: {
    rootsAdded: exactReplay.memoryEvolution && exactReplay.memoryEvolution.rootsAdded,
    canonicalDuplicatesSuppressed: exactReplay.canonicalDuplicatesSuppressed || 0
  },
  caseVariantReplay: {
    rootsAdded: caseReplay.memoryEvolution && caseReplay.memoryEvolution.rootsAdded,
    canonicalDuplicatesSuppressed: caseReplay.canonicalDuplicatesSuppressed || 0
  },
  distinctAttack: {
    rootsAdded: distinct.memoryEvolution && distinct.memoryEvolution.rootsAdded,
    mutationCandidates: distinct.mutationCandidates || 0,
    validatedMutations: distinct.mutationsValidated || 0
  },
  totalReviewedRoots: counter.learnedPatterns.length,
  scope: 'deterministic local defensive memory-evolution regression; no external target traffic'
}, null, 2));
