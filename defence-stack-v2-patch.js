'use strict';

/**
 * Defence-stack V2 overlay.
 *
 * This deliberately layers on top of defence-stack-patch.js so the current
 * main-branch Arjuna/Krishna routing and Sudarshana confirmed-escape gate stay
 * authoritative. V2 adds only:
 *   1) direct nested-value evidence enrichment for structural unknown routing;
 *   2) bounded adaptive mutation generation (96/root token, 256/incident);
 *   3) explicit mutation-budget telemetry.
 */
require('./defence-stack-patch');

const { CounterEngine } = require('./counter-engine');
const { DetectionEngine } = require('./detection-engine');

const V2_FLAG = Symbol.for('krishna.defenceStackV2Patch.v1');
const MAX_MUTATIONS_PER_TOKEN = 96;
const MAX_MUTATIONS_PER_INCIDENT = 256;

if (!globalThis[V2_FLAG]) {
  globalThis[V2_FLAG] = true;

  const priorInspect = DetectionEngine.prototype.inspect;
  const priorGenerate = CounterEngine.prototype._generateSyntheticMutations;
  const priorLearn = CounterEngine.prototype.learnFromIncident;

  function collectEvidence(value, parts, depth = 0) {
    if (depth > 4 || value === null || value === undefined) return;
    if (typeof value === 'string') {
      parts.push(value);
      return;
    }
    if (typeof value === 'number' || typeof value === 'boolean') {
      parts.push(String(value));
      return;
    }
    if (Array.isArray(value)) {
      for (const item of value) collectEvidence(item, parts, depth + 1);
      return;
    }
    if (typeof value === 'object') {
      for (const [key, item] of Object.entries(value)) {
        parts.push(String(key));
        collectEvidence(item, parts, depth + 1);
      }
    }
  }

  DetectionEngine.prototype.inspect = function v2EvidenceInspect(req) {
    if (!req) return priorInspect.call(this, req);

    const directEvidence = [];
    collectEvidence(req.query || {}, directEvidence);
    collectEvidence(req.body || {}, directEvidence);
    if (!directEvidence.length) return priorInspect.call(this, req);

    // Feed direct values into the existing hardening layer before it records
    // recent per-IP routing state. This avoids JSON escaping hiding structural
    // syntax such as ["constructor"]["prototype"] while preserving all current
    // main-branch routing/Sudarshana semantics.
    const originalRaw = String(req.rawBodyStr || '');
    const enrichedRaw = [originalRaw, ...directEvidence].filter(Boolean).join('\n');
    const enriched = {
      ...req,
      rawBodyStr: enrichedRaw,
      rawBodyBytes: Buffer.byteLength(enrichedRaw)
    };
    return priorInspect.call(this, enriched);
  };

  CounterEngine.prototype._generateSyntheticMutations = function v2BoundedGenerator(token, attackTypes = []) {
    const generated = priorGenerate.call(this, token, attackTypes);
    const source = Array.isArray(generated) ? generated : [];

    // Outside a learnFromIncident transaction the per-token bound still holds.
    if (!Number.isFinite(this._v2MutationBudgetRemaining)) {
      return source.slice(0, MAX_MUTATIONS_PER_TOKEN);
    }

    const allowed = Math.max(0, Math.min(MAX_MUTATIONS_PER_TOKEN, this._v2MutationBudgetRemaining));
    const bounded = source.slice(0, allowed);
    this._v2MutationGeneratedBeforeBudget += source.length;
    this._v2MutationBudgetWithheld += Math.max(0, source.length - bounded.length);
    this._v2MutationBudgetRemaining -= bounded.length;
    this._v2MaxPerTokenCandidates = Math.max(this._v2MaxPerTokenCandidates, bounded.length);
    return bounded;
  };

  CounterEngine.prototype.learnFromIncident = function v2BoundedLearn(args = {}) {
    this._v2MutationBudgetRemaining = MAX_MUTATIONS_PER_INCIDENT;
    this._v2MutationGeneratedBeforeBudget = 0;
    this._v2MutationBudgetWithheld = 0;
    this._v2MaxPerTokenCandidates = 0;

    try {
      const result = priorLearn.call(this, args);
      if (!result || typeof result !== 'object') return result;

      const evaluated = Number(result.mutationCandidates || 0);
      return {
        ...result,
        mutationCandidatesGeneratedBeforeBudget: this._v2MutationGeneratedBeforeBudget,
        mutationCandidatesBudgetWithheld: this._v2MutationBudgetWithheld,
        mutationBudget: {
          perToken: MAX_MUTATIONS_PER_TOKEN,
          perIncident: MAX_MUTATIONS_PER_INCIDENT,
          maxPerTokenObserved: this._v2MaxPerTokenCandidates,
          evaluated,
          remaining: Math.max(0, this._v2MutationBudgetRemaining),
          withheld: this._v2MutationBudgetWithheld
        }
      };
    } finally {
      delete this._v2MutationBudgetRemaining;
      delete this._v2MutationGeneratedBeforeBudget;
      delete this._v2MutationBudgetWithheld;
      delete this._v2MaxPerTokenCandidates;
    }
  };
}

module.exports = {
  patched: true,
  mutationBudget: {
    perToken: MAX_MUTATIONS_PER_TOKEN,
    perIncident: MAX_MUTATIONS_PER_INCIDENT
  }
};
