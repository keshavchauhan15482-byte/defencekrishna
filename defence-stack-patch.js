'use strict';

/**
 * Defence-stack hardening shim.
 *
 * This module preserves the existing WAF/model implementation while tightening
 * the runtime semantics around the project design:
 *   Garuda/Detection -> Arjuna known fast path -> Krishna unknown study ->
 *   Sudarshana scoped containment only for unresolved/high-risk unknowns.
 *
 * It also prevents generated mutations from becoming trusted Arjuna memory
 * merely because they were synthesized. Mutations must first be independently
 * re-detected by a fresh DetectionEngine with learned memory disabled.
 */
const { CounterEngine } = require('./counter-engine');
const { DetectionEngine } = require('./detection-engine');
const { SudarshanaCore } = require('./sudarshana-core');

const PATCH_FLAG = Symbol.for('krishna.defenceStackPatch.v1');
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
    // No CounterEngine is supplied: validation cannot succeed because a token
    // was already learned. It must still look dangerous to the base detector.
    const validator = new DetectionEngine(null);
    return validator.inspect(validationRequest(token));
  }

  DetectionEngine.prototype.inspect = function patchedInspect(req) {
    const result = originalInspect.call(this, req);
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

    let candidates = 0;
    let validated = 0;
    for (const entry of learned.newlyLearned || []) {
      const accepted = [];
      const rejected = [];
      for (const mutation of entry.syntheticMutations || []) {
        candidates++;
        const verdict = independentlyDetect(mutation);
        const record = {
          token: mutation,
          validatedAt: Date.now(),
          score: verdict.score,
          tier: verdict.tier,
          attackType: verdict.attackType || entry.attackType,
          reasons: (verdict.reasons || []).slice(0, 3)
        };
        if (verdict.tier === 'danger') {
          accepted.push(record);
          validated++;
          // The old implementation already inserted every candidate in the
          // Bloom filter. Exact confirmation below only trusts this accepted
          // list, so rejected candidates cannot become block decisions.
          this.bloom.add(mutation);
        } else {
          rejected.push(record);
        }
      }
      entry.validatedSyntheticMutations = accepted;
      entry.rejectedSyntheticMutations = rejected.slice(0, 20);
      entry.mutationValidation = {
        candidateCount: (entry.syntheticMutations || []).length,
        validatedCount: accepted.length,
        coverage: (entry.syntheticMutations || []).length ? accepted.length / entry.syntheticMutations.length : 0,
        validator: 'fresh DetectionEngine without learned memory'
      };
    }
    if (learned.newlyLearned && learned.newlyLearned.length) this._persist();

    return {
      ...learned,
      confidenceScore: boundedConfidence,
      rootValidation: { tier: rootValidation.tier, score: rootValidation.score, attackType: rootValidation.attackType },
      mutationCandidates: candidates,
      mutationsValidated: validated,
      mutationValidationCoverage: candidates ? validated / candidates : 0,
      // Existing proxy uses this field for the Krishna study summary. Report
      // independently validated mutations, not raw generated candidates.
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

    // First prefer the exact validated representation that actually appeared in
    // the request. This preserves precise audit provenance when multiple safe
    // canonical variants (for example upper/lower case) normalize identically.
    for (const entry of this.learnedPatterns || []) {
      for (const item of entry.validatedSyntheticMutations || []) {
        const token = typeof item === 'string' ? item : item.token;
        if (!token || token.length < 8) continue;
        if (!this.bloom.mightContain(token)) continue;
        if (raw.includes(token)) return recordMutationMatch(entry, token, 'exact');
      }
    }

    // Then allow a canonical-equivalent validated mutation. Generated but
    // unvalidated variants are never consulted here, even if Bloom says maybe.
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

    // Arjuna/static known detections were already blocked at the boundary.
    // Do not disrupt the rest of a shared IP with a second containment layer.
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

module.exports = { patched: true };
