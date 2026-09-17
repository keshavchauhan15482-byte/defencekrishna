'use strict';

/**
 * Evidence-normalization hardening layered on top of the validated defence loop.
 *
 * HTTP JSON bodies escape embedded quotes (for example \"constructor\"). The
 * base structural heuristic intentionally reasons over syntax, so this wrapper
 * decodes only quote escaping for structural inspection without rewriting the
 * request delivered to the protected application.
 */
require('./defence-stack-patch');

const { DetectionEngine } = require('./detection-engine');
const { SudarshanaCore } = require('./sudarshana-core');

const HARDENING_FLAG = Symbol.for('krishna.defenceEvidenceHardening.v1');
const BRACKET_PROTOTYPE_CHAIN = /\[\s*['"]constructor['"]\s*\]\s*\[\s*['"]prototype['"]\s*\]/i;

if (!globalThis[HARDENING_FLAG]) {
  globalThis[HARDENING_FLAG] = true;

  const innerInspect = DetectionEngine.prototype.inspect;
  const innerEngage = SudarshanaCore.prototype.engageScopedLockdown;
  const recentFinalInspectionByIp = new Map();

  function evidenceText(req) {
    if (!req) return '';
    const parts = [req.url || req.path || '', req.rawBodyStr || ''];
    try { parts.push(JSON.stringify(req.query || {})); } catch (_) {}
    try { parts.push(JSON.stringify(req.body || {})); } catch (_) {}
    // JSON stringification escapes quotes. Decode only those quote escapes for
    // structural matching; leave all other request bytes untouched.
    return parts.join('\n').replace(/\\"/g, '"').replace(/\\'/g, "'");
  }

  function remember(req, result) {
    if (!req || !req.ip) return;
    recentFinalInspectionByIp.set(String(req.ip), { at: Date.now(), result });
    if (recentFinalInspectionByIp.size > 256) {
      const cutoff = Date.now() - 5 * 60 * 1000;
      for (const [ip, item] of recentFinalInspectionByIp) {
        if (item.at < cutoff) recentFinalInspectionByIp.delete(ip);
      }
    }
  }

  DetectionEngine.prototype.inspect = function evidenceHardenedInspect(req) {
    let result = innerInspect.call(this, req);
    if (result.tier !== 'danger' && BRACKET_PROTOTYPE_CHAIN.test(evidenceText(req))) {
      const reasons = Array.isArray(result.reasons) ? [...result.reasons] : [];
      const zeroDayReasons = Array.isArray(result.zeroDayReasons) ? [...result.zeroDayReasons] : [];
      reasons.push('Krishna novel-structure heuristic: escaped bracket-notation constructor/prototype chain');
      zeroDayReasons.push('Unseen structural prototype-chain access form after JSON evidence normalization');
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
    remember(req, result);
    return result;
  };

  SudarshanaCore.prototype.engageScopedLockdown = function evidenceHardenedEngage(opts = {}) {
    const ip = opts.forensicSnapshot && opts.forensicSnapshot.ip ? String(opts.forensicSnapshot.ip) : null;
    const recent = ip ? recentFinalInspectionByIp.get(ip) : null;
    const finalInspection = recent && Date.now() - recent.at < 5000 ? recent.result : null;
    const evidence = opts.escalationEvidence && typeof opts.escalationEvidence === 'object' ? opts.escalationEvidence : null;
    const confirmedEscape = Boolean(evidence && evidence.confirmed === true && typeof evidence.source === 'string' && evidence.source.length >= 4);

    // The inner defence patch already handles ordinary known/unknown routing.
    // This guard is specifically needed when evidence normalization upgraded a
    // previously-safe parse result into a Krishna unknown-structure result.
    if (finalInspection && finalInspection.tier === 'danger' && finalInspection.isZeroDayAnomaly && !confirmedEscape) {
      return {
        id: null,
        scopeKey: `ip:${ip}`,
        scopeType: 'ip',
        scopeValue: ip,
        status: 'STANDBY_KRISHNA_CONTAINED',
        reason: 'Unknown structural threat contained by Krishna; Sudarshana requires confirmed escape/breach evidence',
        lockedAt: null,
        expiresAt: null,
        escalationRequired: 'confirmed_escape_or_breach_evidence'
      };
    }

    return innerEngage.call(this, opts);
  };
}

module.exports = { hardened: true };
