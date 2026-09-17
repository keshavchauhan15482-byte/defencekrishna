'use strict';

/**
 * Defence-stack V5 overlay.
 *
 * Keeps Arjuna's two knowledge classes physically/logically distinct at runtime:
 *   - Known Attack Store: reviewed root signatures.
 *   - Validated Mutation Store: independently validated related variants.
 *
 * Each store has its own fixed 8192-bit (1024-byte) Bloom prefilter. Bloom is
 * never block authority by itself; Arjuna requires the corresponding exact
 * store entry after the Bloom "maybe" check. This preserves audit lineage and
 * prevents Bloom false positives from becoming automatic blocks.
 */
require('./defence-stack-v4-patch');

const { CounterEngine } = require('./counter-engine');
const { BloomFilter } = require('./bloom-filter');
const v2 = require('./defence-stack-v2-patch');

const V5_FLAG = Symbol.for('krishna.defenceStackV5Patch.v1');
const BLOOM_SIZE_BITS = 8192;
const BLOOM_HASH_COUNT = 4;

function mutationToken(item) {
  if (typeof item === 'string') return item;
  return item && typeof item.token === 'string' ? item.token : '';
}

function buildSeparatedStores(patterns) {
  const knownByToken = new Map();
  const mutationByToken = new Map();

  for (const entry of patterns || []) {
    if (!entry || typeof entry !== 'object') continue;
    if (typeof entry.token === 'string' && entry.token && !knownByToken.has(entry.token)) {
      knownByToken.set(entry.token, {
        token: entry.token,
        attackType: entry.attackType || 'unknown',
        learnedAt: entry.learnedAt || null,
        confidenceScore: Number(entry.confidenceScore || 0),
        timesReused: Number(entry.timesReused || 0),
        source: 'reviewed_root'
      });
    }

    for (const item of entry.validatedSyntheticMutations || []) {
      const token = mutationToken(item);
      if (!token || mutationByToken.has(token)) continue;
      mutationByToken.set(token, {
        token,
        parentToken: entry.token || null,
        attackType: (item && item.attackType) || entry.attackType || 'unknown',
        validatedAt: (item && item.validatedAt) || null,
        score: Number((item && item.score) || 0),
        source: 'validated_mutation'
      });
    }
  }

  return {
    knownAttackStore: [...knownByToken.values()],
    validatedMutationStore: [...mutationByToken.values()]
  };
}

function bitCount(byte) {
  let value = byte;
  let count = 0;
  while (value) {
    value &= value - 1;
    count++;
  }
  return count;
}

function bloomTelemetry(filter, entries, label) {
  let setBits = 0;
  for (const byte of filter.bits) setBits += bitCount(byte);
  const bitLoad = filter.sizeBits ? setBits / filter.sizeBits : 0;
  return {
    store: label,
    exactEntries: entries,
    bloomSizeBits: filter.sizeBits,
    bloomSizeBytes: filter.sizeBytes(),
    bloomSetBits: setBits,
    bloomBitLoad: bitLoad,
    estimatedMaybeRate: Math.pow(bitLoad, filter.hashCount),
    hashCount: filter.hashCount
  };
}

function rebuildSeparatedMemory(engine) {
  const stores = buildSeparatedStores(engine.learnedPatterns || []);
  const knownBloom = new BloomFilter(BLOOM_SIZE_BITS, BLOOM_HASH_COUNT);
  const mutationBloom = new BloomFilter(BLOOM_SIZE_BITS, BLOOM_HASH_COUNT);

  for (const item of stores.knownAttackStore) knownBloom.add(item.token);
  for (const item of stores.validatedMutationStore) mutationBloom.add(item.token);

  engine.knownAttackStore = stores.knownAttackStore;
  engine.validatedMutationStore = stores.validatedMutationStore;
  engine.knownAttackBloom = knownBloom;
  engine.validatedMutationBloom = mutationBloom;

  const telemetry = {
    knownAttacks: bloomTelemetry(knownBloom, stores.knownAttackStore.length, 'known_attack_store'),
    validatedMutations: bloomTelemetry(mutationBloom, stores.validatedMutationStore.length, 'validated_mutation_store'),
    bloomBytesPerStore: 1024,
    exactConfirmationRequired: true,
    mutationBudget: { ...v2.mutationBudget }
  };
  engine._v5SeparatedMemoryTelemetry = telemetry;
  return telemetry;
}

function exactKnown(engine, token) {
  return Boolean(token && (engine.knownAttackStore || []).some(item => item.token === token));
}

function exactMutation(engine, token) {
  return Boolean(token && (engine.validatedMutationStore || []).some(item => item.token === token));
}

if (!globalThis[V5_FLAG]) {
  globalThis[V5_FLAG] = true;

  const priorLoad = CounterEngine.prototype._load;
  const priorLearn = CounterEngine.prototype.learnFromIncident;
  const priorCheckLearned = CounterEngine.prototype.checkLearned;
  const priorStats = CounterEngine.prototype.stats;

  CounterEngine.prototype._load = function v5SeparatedLoad() {
    const result = priorLoad.call(this);
    rebuildSeparatedMemory(this);
    return result;
  };

  CounterEngine.prototype.learnFromIncident = function v5SeparatedLearn(args = {}) {
    const result = priorLearn.call(this, args);
    const separatedMemory = rebuildSeparatedMemory(this);
    if (!result || typeof result !== 'object') return result;
    return { ...result, separatedMemory };
  };

  CounterEngine.prototype.checkLearned = function v5ArjunaTwoStoreLookup(rawInput) {
    if (!this.knownAttackBloom || !this.validatedMutationBloom) rebuildSeparatedMemory(this);
    const match = priorCheckLearned.call(this, rawInput);
    if (!match) return null;

    if (match.matchSource === 'validated_mutation') {
      const token = match.matchedMutation || '';
      if (!token || !this.validatedMutationBloom.mightContain(token) || !exactMutation(this, token)) return null;
      return { ...match, arjunaStore: 'validated_mutation_store', bloomPrefilter: 'validatedMutationBloom' };
    }

    const token = match.token || '';
    if (!token || !this.knownAttackBloom.mightContain(token) || !exactKnown(this, token)) return null;
    return { ...match, arjunaStore: 'known_attack_store', bloomPrefilter: 'knownAttackBloom' };
  };

  CounterEngine.prototype.stats = function v5SeparatedStats() {
    const stats = priorStats.call(this);
    const separatedMemory = this._v5SeparatedMemoryTelemetry || rebuildSeparatedMemory(this);
    return {
      ...stats,
      separatedArjunaMemory: separatedMemory,
      note: `Arjuna uses separate exact known-attack and validated-mutation stores, each fronted by its own fixed ${separatedMemory.bloomBytesPerStore}-byte Bloom prefilter; exact-store confirmation remains mandatory.`
    };
  };
}

module.exports = {
  patched: true,
  bloom: { sizeBits: BLOOM_SIZE_BITS, sizeBytes: 1024, hashCount: BLOOM_HASH_COUNT },
  mutationBudget: { ...v2.mutationBudget },
  buildSeparatedStores,
  rebuildSeparatedMemory
};
