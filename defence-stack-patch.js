'use strict';

/**
 * Defence-stack hardening shim.
 *
 * Runtime semantics:
 *   Garuda/Detection -> Arjuna known fast path -> Krishna unknown study ->
 *   Sudarshana scoped containment only for unresolved/high-risk unknowns.
 *
 * Generated mutations never become trusted Arjuna memory merely because they
 * were synthesized. They must be independently re-detected by a fresh detector
 * and fit a bounded, reusable signature budget first.
 */
const { CounterEngine } = require('./counter-engine');
const { DetectionEngine } = require('./detection-engine');
const { SudarshanaCore } = require('./sudarshana-core');

const PATCH_FLAG = Symbol.for('krishna.defenceStackPatch.v1');
const KRISHNA_NOVEL_PROTOTYPE_CHAIN = /\[\s*['"]constructor['"]\s*\]\s*\[\s*['"]prototype['"]\s*\]/i;
const MAX_MUTATIONS_PER_TOKEN = 96;
const MAX_MUTATIONS_PER_INCIDENT = 256;

if (!globalThis[PATCH_FLAG]) {
  globalThis[PATCH_FLAG] = true;

  const originalInspect = DetectionEngine.prototype.inspect;
  const originalLearn = CounterEngine.prototype.learnFromIncident;
  const originalCheckLearned = CounterEngine.prototype.checkLearned;
  const originalEngage = SudarshanaCore.prototype.engageScopedLockdown;
  const originalRecovery = SudarshanaCore.prototype.evaluateAutonomousRecovery;
  const recentInspectionByIp = new Map();

  function normalizeToken(value) {
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

  function requestEvidenceText(req) {
    if (!req) return '';
    const parts = [req.url || req.path || '', req.rawBodyStr || ''];
    collectEvidence(req.query || {}, parts);
    collectEvidence(req.body || {}, parts);
    return parts.join('\n');
  }

  function validationRequest(token) {
    const body = JSON.stringify({ payload: token });
    return {
      ip: '192.0.2.250',
      method: 'POST',
      path: '/mutation-validation',
      url: '/mutation-validation',
      query: {},
      body: { payload: token },
      rawBodyStr: body,
      rawBodyBytes: Buffer.byteLength(body),
      headers: {
        'content-type': 'application/json',
        'user-agent': 'Krishna-Defence-Mutation-Validator/1.0'
      },
      isLoginAttemptFailed: false
    };
  }

  function independentlyDetect(token) {
    const validator = new DetectionEngine(null);
    return validator.inspect(validationRequest(token));
  }

  DetectionEngine.prototype.inspect = function patchedInspect(req) {
    let result = originalInspect.call(this, req);
    const evidence = requestEvidenceText(req);

    // Unknown-structure heuristic only. This does not claim a real zero-day.
    // Reading direct nested values prevents JSON escaping from hiding the
    // bracket-notation constructor/prototype chain from this structural check.
    if (result.tier !== 'danger' && KRISHNA_NOVEL_PROTOTYPE_CHAIN.test(evidence)) {
      const reasons = Array.isArray(result.reasons) ? [...result.reasons] : [];
      reasons.push('Krishna novel-structure heuristic: bracket-notation constructor/prototype chain');
      const zeroDayReasons = Array.isArray(result.zeroDayReasons) ? [...result.zeroDayReasons] : [];
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

    if (req && req.ip) {
      recentInspectionByIp.set(String(req.ip), { at: Date.now(), result });
      if (recentInspectionByIp.size > 256) {
        const cutoff = Date.now() - 5 * 60 * 1000;
        for (const [ip, item] of recentInspectionByIp) if (item.at < cutoff) recentInspectionByIp.delete(ip);
      }
    }
    return result;
  };

  CounterEngine.prototype.learnFromIncident = function validatedLearn(args = {}) {
    const rawInput = String(args.rawInput || '');
    if (!rawInput) {
      return { newlyLearned: [], totalLearned: this.learnedPatterns.length, validationRejected: true, reason: 'Empty incident payload' };
    }

    const requestedConfidence = Number(args.confidenceScore || 0);
    if (!Number.isFinite(requestedConfidence) || requestedConfidence < 75) {
      return {
        newlyLearned: [],
        totalLearned: this.learnedPatterns.length,
        confidenceRejected: true,
        reason: `Incident confidence ${Number.isFinite(requestedConfidence) ? requestedConfidence : 0}% is below the 75% promotion gate`
      };
    }

    const rootValidation = independentlyDetect(rawInput);
    if (rootValidation.tier !== 'danger') {
      return {
        newlyLearned: [],
        totalLearned: this.learnedPatterns.length,
        validationRejected: true,
        validationTier: rootValidation.tier,
        validationScore: rootValidation.score,
        reason: 'Incident was not independently re-detected as danger; Arjuna memory was not modified'
      };
    }

    const boundedConfidence = Math.min(requestedConfidence, 99);
    const learned = originalLearn.call(this, { ...args, confidenceScore: boundedConfidence });

    let generatedBeforeBudget = 0;
    let candidates = 0;
    let validated = 0;
    let incidentBudgetUsed = 0;

    for (const entry of learned.newlyLearned || []) {
      const generated = Array.isArray(entry.syntheticMutations) ? entry.syntheticMutations : [];
      generatedBeforeBudget += generated.length;
      const remainingIncidentBudget = Math.max(0, MAX_MUTATIONS_PER_INCIDENT - incidentBudgetUsed);
      const candidateBudget = Math.min(MAX_MUTATIONS_PER_TOKEN, remainingIncidentBudget);
      const boundedCandidates = generated.slice(0, candidateBudget);
      incidentBudgetUsed += boundedCandidates.length;

      // Persist only the bounded candidate set. Extra generated variants remain
      // diagnostics only and never become trusted Arjuna decisions.
      entry.syntheticMutations = boundedCandidates;
      entry.syntheticMutationsCount = boundedCandidates.length;

      const accepted = [];
      const rejected = [];
      for (const mutation of boundedCandidates) {
        candidates++;
        const verdict = independentlyDetect(mutation);
        const canonicalMutation = normalizeToken(mutation);
        const arjunaEligible = String(mutation || '').length >= 8 && canonicalMutation.length >= 8;
        const record = {
          token: mutation,
          validatedAt: Date.now(),
          score: verdict.score,
          tier: verdict.tier,
          attackType: verdict.attackType || entry.attackType,
          reasons: (verdict.reasons || []).slice(0, 3),
          arjunaEligible
        };
        if (verdict.tier === 'danger' && arjunaEligible) {
          accepted.push(record);
          validated++;
          this.bloom.add(mutation);
        } else {
          if (verdict.tier === 'danger' && !arjunaEligible) record.rejectionReason = 'dangerous_but_not_arjuna_reusable_signature';
          rejected.push(record);
        }
      }

      entry.validatedSyntheticMutations = accepted;
      entry.rejectedSyntheticMutations = rejected.slice(0, 20);
      entry.mutationValidation = {
        generatedCount: generated.length,
        candidateCount: boundedCandidates.length,
        budgetWithheldCount: Math.max(0, generated.length - boundedCandidates.length),
        validatedCount: accepted.length,
        coverage: boundedCandidates.length ? accepted.length / boundedCandidates.length : 0,
        perTokenBudget: MAX_MUTATIONS_PER_TOKEN,
        perIncidentBudget: MAX_MUTATIONS_PER_INCIDENT,
        validator: 'fresh DetectionEngine without learned memory + Arjuna reuse eligibility'
      };
    }

    if (learned.newlyLearned && learned.newlyLearned.length) this._persist();

    const budgetWithheld = Math.max(0, generatedBeforeBudget - candidates);
    return {
      ...learned,
      confidenceScore: boundedConfidence,
      rootValidation: { tier: rootValidation.tier, score: rootValidation.score, attackType: rootValidation.attackType },
      mutationCandidatesGeneratedBeforeBudget: generatedBeforeBudget,
      mutationCandidates: candidates,
      mutationCandidatesBudgetWithheld: budgetWithheld,
      mutationsValidated: validated,
      mutationValidationCoverage: candidates ? validated / candidates : 0,
      mutationBudget: {
        perToken: MAX_MUTATIONS_PER_TOKEN,
        perIncident: MAX_MUTATIONS_PER_INCIDENT,
        used: candidates,
        withheld: budgetWithheld
      },
      mutationsSynthesized: validated
    };
  };

  CounterEngine.prototype.checkLearned = function validatedKnownFastPath(rawInput) {
    const raw = String(rawInput || '');
    const haystack = normalizeToken(raw);
    if (!haystack) return null;

    const recordMutationMatch = (entry, token, matchMode) => {
      entry.timesReused = (entry.timesReused || 0) + 1;
      entry.mutationTimesReused = (entry.mutationTimesReused || 0) + 1;
      this._persist();
      return { ...entry, matchSource: 'validated_mutation', matchedMutation: token, mutationMatchMode: matchMode };
    };

    for (const entry of this.learnedPatterns || []) {
      for (const item of entry.validatedSyntheticMutations || []) {
        const token = typeof item === 'string' ? item : item.token;
        if (!token || token.length < 8) continue;
        if (!this.bloom.mightContain(token)) continue;
        if (raw.includes(token)) return recordMutationMatch(entry, token, 'exact');
      }
    }

    for (const entry of this.learnedPatterns || []) {
      for (const item of entry.validatedSyntheticMutations || []) {
        const token = typeof item === 'string' ? item : item.token;
        if (!token || token.length < 8) continue;
        if (!this.bloom.mightContain(token)) continue;
        const needle = normalizeToken(token);
        if (needle.length >= 8 && haystack.includes(needle)) {
          return recordMutationMatch(entry, token, 'canonical_equivalent');
        }
      }
    }

    const direct = originalCheckLearned.call(this, rawInput);
    if (direct) return { ...direct, matchSource: 'reviewed_root_token' };
    return null;
  };

  SudarshanaCore.prototype.engageScopedLockdown = function routedLockdown(opts = {}) {
    const ip = opts.forensicSnapshot && opts.forensicSnapshot.ip ? String(opts.forensicSnapshot.ip) : null;
    const recent = ip ? recentInspectionByIp.get(ip) : null;
    const fresh = recent && Date.now() - recent.at < 5000 ? recent.result : null;

    if (fresh && fresh.tier === 'danger' && !fresh.isZeroDayAnomaly && !fresh.multiVectorSuspected) {
      return {
        id: null,
        scopeKey: `ip:${ip}`,
        scopeType: 'ip',
        scopeValue: ip,
        status: 'STANDBY_ARJUNA_BLOCKED',
        reason: 'Known/static threat already neutralized at front line; Sudarshana not required',
        lockedAt: null,
        expiresAt: null
      };
    }

    const lock = originalEngage.call(this, opts);
    lock.minimumHoldMs = Math.min(1500, Math.max(250, Math.floor(this.timeBudgetMs / 4)));
    lock.studyState = 'KRISHNA_VALIDATION_IN_PROGRESS';
    return lock;
  };

  SudarshanaCore.prototype.evaluateAutonomousRecovery = function evidenceBasedRecovery({ scopeType, scopeValue, krishnaAnalysis = {} }) {
    const scopeKey = `${scopeType}:${scopeValue}`;
    const lock = this.scopedLockdowns.get(scopeKey);
    if (!lock) {
      return {
        recovered: false,
        notRequired: true,
        status: 'STANDBY',
        reason: 'No active Sudarshana lockdown; front-line defence already contained this event'
      };
    }

    const learnedTokens = Array.isArray(krishnaAnalysis.learnedTokens) ? krishnaAnalysis.learnedTokens.filter(Boolean) : [];
    const validatedMutations = Number(krishnaAnalysis.mutationsCount || 0);
    const confidence = Number(krishnaAnalysis.confidenceScore || 0);
    const studyComplete = learnedTokens.length > 0 && validatedMutations > 0 && confidence >= this.confidenceThreshold;

    if (!studyComplete) {
      lock.studyState = 'UNRESOLVED_FAIL_CLOSED';
      return originalRecovery.call(this, {
        scopeType,
        scopeValue,
        krishnaAnalysis: { ...krishnaAnalysis, confidenceScore: 0 }
      });
    }

    lock.studyState = 'VALIDATED_MUTATIONS_READY';
    const minHold = Number(lock.minimumHoldMs || 0);
    const elapsed = Date.now() - lock.lockedAt;
    if (elapsed < minHold) {
      const remaining = minHold - elapsed;
      if (!lock._recoveryScheduled) {
        lock._recoveryScheduled = true;
        const timer = setTimeout(() => {
          const current = this.scopedLockdowns.get(scopeKey);
          if (!current || current.status !== 'LOCKED') return;
          current.studyState = 'KRISHNA_STUDY_COMPLETE';
          originalRecovery.call(this, { scopeType, scopeValue, krishnaAnalysis });
        }, remaining);
        if (typeof timer.unref === 'function') timer.unref();
      }
      return {
        recovered: false,
        pending: true,
        lockdown: lock,
        reason: `Scoped containment held for ${remaining}ms while validated Krishna study completes`
      };
    }

    lock.studyState = 'KRISHNA_STUDY_COMPLETE';
    return originalRecovery.call(this, { scopeType, scopeValue, krishnaAnalysis });
  };
}

module.exports = {
  patched: true,
  mutationBudget: {
    perToken: MAX_MUTATIONS_PER_TOKEN,
    perIncident: MAX_MUTATIONS_PER_INCIDENT
  }
};
