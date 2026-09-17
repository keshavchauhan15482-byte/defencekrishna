'use strict';

/**
 * Defence-stack V3 overlay.
 *
 * Layers on top of V2 and protects Krishna's self-evolving memory from
 * duplicate growth. A previously learned root token must not be re-added just
 * because the same attack is replayed with case/encoding/whitespace changes
 * that normalize to the same canonical signature.
 */
const v2 = require('./defence-stack-v2-patch');
const basePatch = require('./defence-stack-patch');
const { CounterEngine } = require('./counter-engine');

const V3_FLAG = Symbol.for('krishna.defenceStackV3Patch.v1');

function normalizeMemoryToken(value) {
  let s = String(value || '').normalize('NFKD');
  let prev = '';
  for (let i = 0; i < 4 && s !== prev; i++) {
    prev = s;
    try { s = decodeURIComponent(s.replace(/\+/g, ' ')); } catch (_) {}
    s = s.replace(/\/\*[\s\S]*?\*\//g, ' ')
      .replace(/%00/gi, '')
      .replace(/\\u([0-9a-fA-F]{4})/g, (_, h) => String.fromCharCode(parseInt(h, 16)));
  }
  return s.replace(/\s+/g, ' ').trim().toLowerCase();
}

if (!globalThis[V3_FLAG]) {
  globalThis[V3_FLAG] = true;

  const priorExtract = CounterEngine.prototype._extractTokens;
  const priorLearn = CounterEngine.prototype.learnFromIncident;

  CounterEngine.prototype._extractTokens = function v3CanonicalDedupeExtract(rawInput, attackTypes) {
    const tokens = priorExtract.call(this, rawInput, attackTypes);
    if (!Array.isArray(tokens) || !tokens.length) return [];

    const existingCanonical = new Set(
      (this.learnedPatterns || [])
        .map(entry => normalizeMemoryToken(entry && entry.token))
        .filter(Boolean)
    );
    const seenThisIncident = new Set();
    const unique = [];

    for (const token of tokens) {
      const canonical = normalizeMemoryToken(token);
      if (!canonical) continue;
      if (existingCanonical.has(canonical) || seenThisIncident.has(canonical)) {
        this._v3CanonicalDuplicatesSuppressed = (this._v3CanonicalDuplicatesSuppressed || 0) + 1;
        continue;
      }
      seenThisIncident.add(canonical);
      unique.push(token);
    }
    return unique;
  };

  CounterEngine.prototype.learnFromIncident = function v3MemoryAwareLearn(args = {}) {
    const before = Array.isArray(this.learnedPatterns) ? this.learnedPatterns.length : 0;
    this._v3CanonicalDuplicatesSuppressed = 0;
    try {
      const result = priorLearn.call(this, args);
      if (!result || typeof result !== 'object') return result;
      const after = Array.isArray(this.learnedPatterns) ? this.learnedPatterns.length : before;
      return {
        ...result,
        canonicalDuplicatesSuppressed: this._v3CanonicalDuplicatesSuppressed || 0,
        memoryEvolution: {
          rootsBefore: before,
          rootsAfter: after,
          rootsAdded: Math.max(0, after - before),
          canonicalDuplicatesSuppressed: this._v3CanonicalDuplicatesSuppressed || 0
        }
      };
    } finally {
      delete this._v3CanonicalDuplicatesSuppressed;
    }
  };
}

module.exports = {
  patched: true,
  mutationBudget: v2.mutationBudget,
  maxLearnedTokensPerIncident: basePatch.mutationLimits.maxLearnedTokensPerIncident,
  canonicalMemoryDedupe: true
};
