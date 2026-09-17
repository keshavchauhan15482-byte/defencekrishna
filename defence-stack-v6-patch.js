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
 * V6 does not weaken blocking. It only removes the contradictory "unknown"
 * label when a concrete known attack family already matched.
 */
require('./defence-stack-v5-patch');

const { DetectionEngine } = require('./detection-engine');

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

  DetectionEngine.prototype.inspect = function v6ExclusiveKnownUnknownRouting(req) {
    const result = priorInspect.call(this, req);
    if (!result || typeof result !== 'object') return result;

    const reasons = Array.isArray(result.reasons) ? result.reasons : [];
    const knownMatched = Boolean(result.isLearnedMatch) || reasons.some(isKnownAttackReason);

    if (result.isZeroDayAnomaly && knownMatched) {
      const normalizedReasons = reasons.filter(reason => !isZeroDayReason(reason));
      normalizedReasons.push('Routing normalized: deterministic known signature takes Arjuna precedence over structural-anomaly labeling');
      return {
        ...result,
        reasons: normalizedReasons,
        isZeroDayAnomaly: false,
        zeroDayReasons: [],
        routingAuthority: 'arjuna_known',
        routingNormalization: 'known_signature_precedence'
      };
    }

    if (result.isZeroDayAnomaly) {
      return { ...result, routingAuthority: 'krishna_unknown' };
    }
    if (knownMatched) {
      return { ...result, routingAuthority: 'arjuna_known' };
    }
    return result;
  };
}

module.exports = {
  patched: true,
  knownReasonPatterns: KNOWN_REASON_PATTERNS.length,
  exclusiveKnownUnknownRouting: true
};
