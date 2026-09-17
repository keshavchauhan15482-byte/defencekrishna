'use strict';

const assert = require('node:assert/strict');
const v5 = require('../defence-stack-v5-patch');
const { CounterEngine } = require('../counter-engine');
const { BloomFilter } = require('../bloom-filter');

function isolatedCounter() {
  const counter = new CounterEngine();
  counter.learnedPatterns = [];
  counter.attackTypeWeights = {};
  counter.sourceIncidentHistory = new Map();
  counter.bloom = new BloomFilter(8192, 4);
  counter._persist = () => {};
  v5.rebuildSeparatedMemory(counter);
  return counter;
}

assert.deepEqual(v5.mutationBudget, { perToken: 48, perIncident: 128 });
assert.equal(v5.bloom.sizeBits, 8192);
assert.equal(v5.bloom.sizeBytes, 1024);

const counter = isolatedCounter();
const learned = counter.learnFromIncident({
  rawInput: JSON.stringify({ payload: 'UNION SELECT username,password FROM users WHERE id=1' }),
  attackTypes: ['sql-injection'],
  sourceIp: '192.0.2.221',
  confidenceScore: 96
});

assert.ok((learned.newlyLearned || []).length > 0, 'no reviewed known-attack roots were learned');
assert.ok((learned.mutationsValidated || 0) > 0, 'no validated mutations were produced');
assert.ok(counter.knownAttackStore.length > 0, 'known attack store is empty');
assert.ok(counter.validatedMutationStore.length > 0, 'validated mutation store is empty');
assert.notEqual(counter.knownAttackStore, counter.validatedMutationStore, 'known and mutation stores must be separate objects');
assert.equal(counter.knownAttackBloom.sizeBytes(), 1024, 'known-attack Bloom must stay exactly 1024 bytes');
assert.equal(counter.validatedMutationBloom.sizeBytes(), 1024, 'mutation Bloom must stay exactly 1024 bytes');

for (const item of counter.knownAttackStore) {
  assert.equal(counter.knownAttackBloom.mightContain(item.token), true, `known Bloom lost reviewed root: ${item.token}`);
}
for (const item of counter.validatedMutationStore) {
  assert.equal(counter.validatedMutationBloom.mightContain(item.token), true, `mutation Bloom lost validated mutation: ${item.token}`);
}

const rootToken = counter.knownAttackStore[0].token;
const rootMatch = counter.checkLearned(rootToken);
assert.ok(rootMatch, 'Arjuna failed to reuse reviewed known root');
assert.equal(rootMatch.arjunaStore, 'known_attack_store');
assert.equal(rootMatch.bloomPrefilter, 'knownAttackBloom');

const mutationToken = counter.validatedMutationStore[0].token;
const mutationMatch = counter.checkLearned(mutationToken);
assert.ok(mutationMatch, 'Arjuna failed to reuse validated mutation');
assert.equal(mutationMatch.arjunaStore, 'validated_mutation_store');
assert.equal(mutationMatch.bloomPrefilter, 'validatedMutationBloom');

// Fixed-memory property: exact audit stores may grow, but each Bloom prefilter
// remains 1024 bytes regardless of pattern count.
const stress = isolatedCounter();
stress.learnedPatterns = Array.from({ length: 2000 }, (_, i) => ({
  token: `reviewed-root-${i}-xxxxxxxx`,
  attackType: 'stress-fixture',
  confidenceScore: 99,
  validatedSyntheticMutations: [{
    token: `validated-mutation-${i}-yyyyyyyy`,
    attackType: 'stress-fixture',
    validatedAt: i + 1,
    score: 100
  }]
}));
const stressed = v5.rebuildSeparatedMemory(stress);
assert.equal(stress.knownAttackStore.length, 2000);
assert.equal(stress.validatedMutationStore.length, 2000);
assert.equal(stress.knownAttackBloom.sizeBytes(), 1024);
assert.equal(stress.validatedMutationBloom.sizeBytes(), 1024);
assert.equal(stressed.knownAttacks.bloomSizeBytes, 1024);
assert.equal(stressed.validatedMutations.bloomSizeBytes, 1024);
assert.equal(stressed.exactConfirmationRequired, true);

console.log(JSON.stringify({
  status: 'PASS',
  mutationBudget: v5.mutationBudget,
  stores: {
    knownAttackStore: counter.knownAttackStore.length,
    validatedMutationStore: counter.validatedMutationStore.length
  },
  bloom: {
    knownAttackBytes: counter.knownAttackBloom.sizeBytes(),
    validatedMutationBytes: counter.validatedMutationBloom.sizeBytes(),
    stressPatternsPerStore: 2000,
    stressKnownAttackBytes: stress.knownAttackBloom.sizeBytes(),
    stressValidatedMutationBytes: stress.validatedMutationBloom.sizeBytes()
  },
  arjunaAccess: {
    knownAttackStore: rootMatch.arjunaStore,
    validatedMutationStore: mutationMatch.arjunaStore
  },
  scope: 'deterministic local defensive memory regression; exact metadata stores remain authoritative; no external target traffic'
}, null, 2));
