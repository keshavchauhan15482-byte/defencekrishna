'use strict';

/**
 * Round-2 defence hardening.
 *
 * Keeps the validated Arjuna/Krishna/Sudarshana routing from
 * defence-stack-patch.js and adds two bounded safety contracts:
 * 1) novel-structure evidence is inspected in decoded scalar request values,
 *    not only JSON-escaped serialization;
 * 2) Krishna mutation research is explicitly resource-bounded while retaining
 *    the existing independent-validation/promotion gate.
 */
require('./defence-stack-patch');

const { CounterEngine } = require('./counter-engine');
const { DetectionEngine } = require('./detection-engine');

const ROUND2_FLAG = Symbol.for('krishna.defenceStackRound2.v1');
const MAX_MUTATIONS_PER_TOKEN = 64;
const MAX_MUTATIONS_PER_INCIDENT = 256;
const KRISHNA_NOVEL_PROTOTYPE_CHAIN = /\[\s*['"]constructor['"]\s*\]\s*\[\s*['"]prototype['"]\s*\]/i;

if (!globalThis[ROUND2_FLAG]) {
  globalThis[ROUND2_FLAG] = true;

  const originalInspect = DetectionEngine.prototype.inspect;
  const originalGenerate = CounterEngine.prototype._generateSyntheticMutations;
  const originalLearn = CounterEngine.prototype.learnFromIncident;

  function collectScalarStrings(value, out, depth = 0) {
    if (out.length >= 64 || depth > 4 || value === null || value === undefined) return;
    if (typeof value === 'string') {
      out.push(value.slice(0, 4096));
      return;
    }
    if (Array.isArray(value)) {
      for (const item of value.slice(0, 32)) collectScalarStrings(item, out, depth + 1);
      return;
    }
    if (typeof value === 'object') {
      for (const item of Object.values(value).slice(0, 32)) collectScalarStrings(item, out, depth + 1);
    }
  }

  function requestEvidenceText(req) {
    if (!req) return '';
    const parts = [String(req.url || req.path || ''), String(req.rawBodyStr || '')];
    collectScalarStrings(req.query, parts);
    collectScalarStrings(req.body, parts);

    // If rawBodyStr is JSON, inspect decoded scalar values as well. This closes
    // the escaped-quote blind spot for payloads such as ["constructor"]["prototype"].
    if (typeof req.rawBodyStr === 'string' && req.rawBodyStr.length <= 65536) {
      try { collectScalarStrings(JSON.parse(req.rawBodyStr), parts); } catch (_) {}
    }
    return parts.join('\n');
  }

  DetectionEngine.prototype.inspect = function round2Inspect(req) {
    let result = originalInspect.call(this, req);
    if (result.tier === 'danger') return result;

    if (KRISHNA_NOVEL_PROTOTYPE_CHAIN.test(requestEvidenceText(req))) {
      const reasons = Array.isArray(result.reasons) ? [...result.reasons] : [];
      const zeroDayReasons = Array.isArray(result.zeroDayReasons) ? [...result.zeroDayReasons] : [];
      reasons.push('Krishna novel-structure heuristic: decoded bracket-notation constructor/prototype chain');
      zeroDayReasons.push('Unseen structural prototype-chain access form');
      result = {
        ...result,
        score: Math.max(Number(result.score || 0), 65),
        tier: 'danger',
        attackType: result.attackType || 'prototype-pollution',
        reasons,
        isZeroDayAnomaly: true,
        zeroDayReasons
      };
    }
    return result;
  };

  CounterEngine.prototype._generateSyntheticMutations = function boundedMutationGenerator(token, attackTypes = []) {
    const generated = originalGenerate.call(this, token, attackTypes);
    const hasIncidentBudget = Number.isFinite(this.__krishnaMutationBudgetRemaining);
    const remaining = hasIncidentBudget
      ? Math.max(0, this.__krishnaMutationBudgetRemaining)
      : MAX_MUTATIONS_PER_INCIDENT;
    const localCap = Math.min(MAX_MUTATIONS_PER_TOKEN, remaining);
    const bounded = generated.slice(0, localCap);

    if (hasIncidentBudget) {
      this.__krishnaMutationBudgetRawGenerated += generated.length;
      this.__krishnaMutationBudgetRetained += bounded.length;
      this.__krishnaMutationBudgetDropped += Math.max(0, generated.length - bounded.length);
      this.__krishnaMutationBudgetRemaining -= bounded.length;
    }
    return bounded;
  };

  CounterEngine.prototype.learnFromIncident = function boundedValidatedLearn(args = {}) {
    this.__krishnaMutationBudgetRemaining = MAX_MUTATIONS_PER_INCIDENT;
    this.__krishnaMutationBudgetRawGenerated = 0;
    this.__krishnaMutationBudgetRetained = 0;
    this.__krishnaMutationBudgetDropped = 0;

    try {
      const learned = originalLearn.call(this, args);
      const mutationBudget = {
        maxPerToken: MAX_MUTATIONS_PER_TOKEN,
        maxPerIncident: MAX_MUTATIONS_PER_INCIDENT,
        rawGeneratedBeforeBudget: this.__krishnaMutationBudgetRawGenerated,
        retainedForValidation: this.__krishnaMutationBudgetRetained,
        droppedByBudget: this.__krishnaMutationBudgetDropped,
        remaining: Math.max(0, this.__krishnaMutationBudgetRemaining),
        exhausted: this.__krishnaMutationBudgetRemaining <= 0
      };
      return {
        ...learned,
        mutationBudget,
        mutationCandidatesBeforeBudget: mutationBudget.rawGeneratedBeforeBudget,
        mutationCandidatesDroppedByBudget: mutationBudget.droppedByBudget
      };
    } finally {
      delete this.__krishnaMutationBudgetRemaining;
      delete this.__krishnaMutationBudgetRawGenerated;
      delete this.__krishnaMutationBudgetRetained;
      delete this.__krishnaMutationBudgetDropped;
    }
  };
}

module.exports = {
  patched: true,
  mutationPolicy: {
    maxPerToken: MAX_MUTATIONS_PER_TOKEN,
    maxPerIncident: MAX_MUTATIONS_PER_INCIDENT
  }
};
