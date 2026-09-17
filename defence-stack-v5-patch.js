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

function canonicalToken(value) {
  let text = String(value || '').normalize('NFKD');
  let previous = '';
  for (let i = 0; i < 4 && text !== previous; i++) {
    previous = text;
    try { text = decodeURIComponent(text.replace(/\+/g, ' ')); } catch (_) {}
    text = text
      .replace(/\/\*[\s\S]*?\*\//g, ' ')
      .replace(/%00/gi, '')
      .replace(/\\u([0-9a-fA-F]{4})/g, (_, h) => String.fromCharCode(parseInt(h, 16)));
  }
  return text.replace(/\s+/g, ' ').trim().toLowerCase();
}

function buildSeparatedStores(patterns) {
  const knownByToken = new Map();
  const knownCanonical = new Set();
  const mutationByToken = new Map();

  // First establish the complete reviewed-root namespace so a mutation that is
  // merely an exact/canonical representation of any known root cannot appear in
  // both stores.
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
      const canonical = canonicalToken(entry.token);
      if (canonical) knownCanonical.add(canonical);
    }
  }

  for (const entry of patterns || []) {
    if (!entry || typeof entry !== 'object') continue;
    for (const item of entry.validatedSyntheticMutations || []) {
      const token = mutationToken(item);
      if (!token || mutationByToken.has(token)) continue;
      const canonical = canonicalToken(token);
      // Case/encoding/whitespace-equivalent forms of an already-reviewed root
      // remain Known Attack Store knowledge, not duplicate mutation knowledge.
      if (canonical && knownCanonical.has(canonical)) continue;
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

function recordKnownMatch(engine, item, matchMode) {
  const entry = (engine.learnedPatterns || []).find(candidate => candidate && candidate.token === item.token) || item;
  entry.timesReused = Number(entry.timesReused || 0) + 1;
  if (typeof engine._persist === 'function') engine._persist();
  return {
    ...entry,
    matchSource: 'reviewed_root_token',
    arjunaStore: 'known_attack_store',
    bloomPrefilter: 'knownAttackBloom',
    rootMatchMode: matchMode
  };
}

function findKnownMatch(engine, rawInput, canonical = false) {
  const raw = String(rawInput || '');
  const haystack = canonical ? canonicalToken(raw) : raw;
  if (!haystack) return null;

  for (const item of engine.knownAttackStore || []) {
    const token = item && item.token;
    if (!token || !engine.knownAttackBloom.mightContain(token)) continue;
    const needle = canonical ? canonicalToken(token) : token;
    if (!needle) continue;
    if (haystack.includes(needle)) return recordKnownMatch(engine, item, canonical ? 'canonical_equivalent' : 'exact');
  }
  return null;
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

    // Preserve root provenance when the reviewed root itself is present exactly.
    // This prevents generator-produced case copies of the root from stealing the
    // attribution and makes Known vs Mutation datasets genuinely disjoint.
    const exactRoot = findKnownMatch(this, rawInput, false);
    if (exactRoot) return exactRoot;

    const match = priorCheckLearned.call(this, rawInput);
    if (match && match.matchSource === 'validated_mutation') {
      const token = match.matchedMutation || '';
      if (token && this.validatedMutationBloom.mightContain(token) && exactMutation(this, token)) {
        return { ...match, arjunaStore: 'validated_mutation_store', bloomPrefilter: 'validatedMutationBloom' };
      }
      // Parent-equivalent generated variants are intentionally excluded from the
      // mutation store; allow them to resolve back to the reviewed root class.
      return findKnownMatch(this, rawInput, true);
    }

    if (match) {
      const token = match.token || '';
      if (token && this.knownAttackBloom.mightContain(token) && exactKnown(this, token)) {
        return { ...match, arjunaStore: 'known_attack_store', bloomPrefilter: 'knownAttackBloom' };
      }
    }

    return findKnownMatch(this, rawInput, true);
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
