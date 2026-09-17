'use strict';

/**
 * Defence-stack V6 routing normalization.
 *
 * Earlier detector layers can legitimately fire both a deterministic known
 * signature and the structural anomaly sentry for the same payload. The project
 * architecture, however, requires mutually exclusive routing semantics:
 *   - deterministic known signature / learned memory -> Arjuna
 *   - otherwise-unclassified structural anomaly -> Krishna
 *
 * V6 does not weaken blocking. It removes the contradictory "unknown" label
 * when a concrete known attack family already matched and keeps Sudarshana on
 * the same normalized route authority.
 */
require('./defence-stack-v5-patch');

const { DetectionEngine } = require('./detection-engine');
const { SudarshanaCore } = require('./sudarshana-core');

const V6_FLAG = Symbol.for('krishna.defenceStackV6Patch.v1');

const KNOWN_REASON_PATTERNS = [
  /sql injection|sql ast/i,
  /cross-site scripting|\bxss\b/i,
  /outside the intended directory|path traversal/i,
  /command injection|shellshock/i,
  /log4j|jndi rce/i,
  /server-side request forgery|\bssrf\b/i,
  /file inclusion/i,
  /template injection/i,
  /\bxxe\b|xml external entity/i,
  /ldap injection/i,
  /nosql injection/i,
  /prototype pollution/i,
  /kubernetes|cloud cluster/i,
  /business logic|price tampering/i,
  /prompt injection|jailbreak/i,
  /webshell|polyglot code/i,
  /graphql/i,
  /python sandbox-escape|object-introspection/i,
  /jwt none|algorithm confusion/i,
  /csv .*formula injection|dde command/i,
  /sensitive files|exposed secrets/i,
  /open redirect/i,
  /crlf/i,
  /deserialization/i,
  /redos|buffer overflow/i,
  /authentication bypass|auth bypass/i,
  /reconnaissance path/i,
  /risky http method|method is not allowed/i
];

const ZERO_DAY_REASON_PATTERNS = [
  /novel zero-day structural anomaly/i,
  /mathematical entropy engine flagged structural anomaly/i,
  /krishna novel-structure heuristic/i,
  /unseen structural prototype-chain access form/i
];

function isKnownAttackReason(reason) {
  const text = String(reason || '');
  if (!text) return false;
  if (ZERO_DAY_REASON_PATTERNS.some(pattern => pattern.test(text))) return false;
  return KNOWN_REASON_PATTERNS.some(pattern => pattern.test(text));
}

function isZeroDayReason(reason) {
  const text = String(reason || '');
  return ZERO_DAY_REASON_PATTERNS.some(pattern => pattern.test(text));
}

if (!globalThis[V6_FLAG]) {
  globalThis[V6_FLAG] = true;
  const priorInspect = DetectionEngine.prototype.inspect;
  const priorEngage = SudarshanaCore.prototype.engageScopedLockdown;
  const normalizedRecentByIp = new Map();

  DetectionEngine.prototype.inspect = function v6ExclusiveKnownUnknownRouting(req) {
    const baseResult = priorInspect.call(this, req);
    if (!baseResult || typeof baseResult !== 'object') return baseResult;

    const reasons = Array.isArray(baseResult.reasons) ? baseResult.reasons : [];
    const knownMatched = Boolean(baseResult.isLearnedMatch) || reasons.some(isKnownAttackReason);
    let result = baseResult;

    if (baseResult.isZeroDayAnomaly && knownMatched) {
      const normalizedReasons = reasons.filter(reason => !isZeroDayReason(reason));
      normalizedReasons.push('Routing normalized: deterministic known signature takes Arjuna precedence over structural-anomaly labeling');
      result = {
        ...baseResult,
        reasons: normalizedReasons,
        isZeroDayAnomaly: false,
        zeroDayReasons: [],
        routingAuthority: 'arjuna_known',
        routingNormalization: 'known_signature_precedence'
      };
    } else if (baseResult.isZeroDayAnomaly) {
      result = { ...baseResult, routingAuthority: 'krishna_unknown' };
    } else if (knownMatched) {
      result = { ...baseResult, routingAuthority: 'arjuna_known' };
    }

    if (req && req.ip) {
      normalizedRecentByIp.set(String(req.ip), { at: Date.now(), result });
      if (normalizedRecentByIp.size > 256) {
        const cutoff = Date.now() - 5 * 60 * 1000;
        for (const [ip, item] of normalizedRecentByIp) {
          if (item.at < cutoff) normalizedRecentByIp.delete(ip);
        }
      }
    }
    return result;
  };

  SudarshanaCore.prototype.engageScopedLockdown = function v6NormalizedContainment(opts = {}) {
    const ip = opts.forensicSnapshot && opts.forensicSnapshot.ip ? String(opts.forensicSnapshot.ip) : null;
    const recent = ip ? normalizedRecentByIp.get(ip) : null;
    const fresh = recent && Date.now() - recent.at < 5000 ? recent.result : null;

    if (fresh && fresh.tier === 'danger' && fresh.routingAuthority === 'arjuna_known') {
      return {
        id: null,
        scopeKey: `ip:${ip}`,
        scopeType: 'ip',
        scopeValue: ip,
        status: 'STANDBY_ARJUNA_BLOCKED',
        reason: 'Normalized known threat already neutralized by Arjuna; Sudarshana not required',
        lockedAt: null,
        expiresAt: null
      };
    }
    return priorEngage.call(this, opts);
  };
}

module.exports = {
  patched: true,
  knownReasonPatterns: KNOWN_REASON_PATTERNS.length,
  exclusiveKnownUnknownRouting: true,
  sudarshanaUsesNormalizedRoute: true
};
