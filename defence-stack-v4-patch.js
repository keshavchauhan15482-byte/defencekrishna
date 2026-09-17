'use strict';

/**
 * Defence-stack V4 overlay.
 *
 * V1-V3 already enforce routing, independent mutation validation, bounded
 * mutation generation, unknown->known promotion, and canonical root dedupe.
 * V4 makes the Bloom fast-path mirror the same trust boundary: only reviewed
 * root tokens and independently validated Arjuna-eligible mutations are kept in
 * Bloom memory. Raw generated candidates must never consume trusted fast-path
 * capacity merely because they were synthesized.
 */
require('./defence-stack-v3-patch');

const { CounterEngine } = require('./counter-engine');
const { BloomFilter } = require('./bloom-filter');

const V4_FLAG = Symbol.for('krishna.defenceStackV4Patch.v1');
const BLOOM_SIZE_BITS = 8192;
const BLOOM_HASH_COUNT = 4;

function mutationToken(item) {
  if (typeof item === 'string') return item;
  return item && typeof item.token === 'string' ? item.token : '';
}

function trustedTokens(patterns) {
  const roots = new Set();
  const mutations = new Set();

  for (const entry of patterns || []) {
    if (entry && typeof entry.token === 'string' && entry.token) roots.add(entry.token);
    for (const item of (entry && entry.validatedSyntheticMutations) || []) {
      const token = mutationToken(item);
      if (token) mutations.add(token);
    }
  }

  return { roots, mutations };
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

function rebuildTrustedBloom(engine) {
  const { roots, mutations } = trustedTokens(engine.learnedPatterns || []);
  const filter = new BloomFilter(BLOOM_SIZE_BITS, BLOOM_HASH_COUNT);

  for (const token of roots) filter.add(token);
  for (const token of mutations) filter.add(token);

  engine.bloom = filter;

  let setBits = 0;
  for (const byte of filter.bits) setBits += bitCount(byte);
  const bitLoad = filter.sizeBits ? setBits / filter.sizeBits : 0;
  const estimatedMaybeRate = Math.pow(bitLoad, filter.hashCount);

  const telemetry = {
    reviewedRoots: roots.size,
    validatedMutations: mutations.size,
    trustedEntries: roots.size + mutations.size,
    bloomSizeBytes: filter.sizeBytes(),
    bloomSetBits: setBits,
    bloomBitLoad: bitLoad,
    estimatedBloomMaybeRate: estimatedMaybeRate,
    source: 'reviewed roots + independently validated Arjuna-eligible mutations only'
  };
  engine._v4TrustedMemoryTelemetry = telemetry;
  return telemetry;
}

function validationTelemetry(patterns) {
  let candidates = 0;
  let validated = 0;
  for (const entry of patterns || []) {
    const info = entry && entry.mutationValidation;
    if (info && Number.isFinite(Number(info.candidateCount))) {
      candidates += Number(info.candidateCount);
    } else if (entry && Array.isArray(entry.syntheticMutations)) {
      candidates += entry.syntheticMutations.length;
    }
    validated += ((entry && entry.validatedSyntheticMutations) || []).length;
  }
  return {
    candidates,
    validated,
    coverage: candidates ? validated / candidates : 0
  };
}

if (!globalThis[V4_FLAG]) {
  globalThis[V4_FLAG] = true;

  const priorLoad = CounterEngine.prototype._load;
  const priorLearn = CounterEngine.prototype.learnFromIncident;
  const priorStats = CounterEngine.prototype.stats;
  const priorForecast = CounterEngine.prototype.getPredictiveForecast;

  CounterEngine.prototype._load = function v4TrustedLoad() {
    const result = priorLoad.call(this);
    // Existing persisted snapshots may contain Bloom bits from old raw mutation
    // candidates. Reconstruct the in-memory filter from reviewed evidence only.
    rebuildTrustedBloom(this);
    return result;
  };

  CounterEngine.prototype.learnFromIncident = function v4TrustedLearn(args = {}) {
    const result = priorLearn.call(this, args);
    const trustedMemory = rebuildTrustedBloom(this);

    // priorLearn may already have scheduled persistence. Its deferred write will
    // now serialize this rebuilt trusted-only Bloom. Calling _persist is safe and
    // coalesced by the existing persistence timer.
    if (typeof this._persist === 'function') this._persist();

    if (!result || typeof result !== 'object') return result;
    return { ...result, trustedMemory };
  };

  CounterEngine.prototype.stats = function v4TrustedStats() {
    const stats = priorStats.call(this);
    const trustedMemory = this._v4TrustedMemoryTelemetry || rebuildTrustedBloom(this);
    const validation = validationTelemetry(this.learnedPatterns || []);
    return {
      ...stats,
      trustedMemory,
      mutationValidation: validation,
      note: `Arjuna fast lookup uses a fixed ${trustedMemory.bloomSizeBytes}-byte Bloom prefilter rebuilt only from reviewed roots and independently validated mutations; exact metadata confirmation remains authoritative.`
    };
  };

  CounterEngine.prototype.getPredictiveForecast = function v4MeasuredForecast(totalRequestsCount) {
    const forecast = priorForecast.call(this, totalRequestsCount);
    const validation = validationTelemetry(this.learnedPatterns || []);
    const trustedMemory = this._v4TrustedMemoryTelemetry || rebuildTrustedBloom(this);
    const pct = validation.candidates ? (validation.coverage * 100).toFixed(1) : '0.0';

    return {
      ...forecast,
      // Retain the legacy field for UI compatibility, but remove the old
      // hard-coded 98.7% claim. This value is now tied to measured local
      // mutation-validation evidence.
      rAndDReadinessIndex: `${pct}% validated mutation coverage (local defensive evidence)`,
      mutationValidationCoverage: validation.coverage,
      trustedMemory
    };
  };
}

module.exports = {
  patched: true,
  bloom: { sizeBits: BLOOM_SIZE_BITS, hashCount: BLOOM_HASH_COUNT },
  rebuildTrustedBloom,
  trustedTokens
};
