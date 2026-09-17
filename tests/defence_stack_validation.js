'use strict';

const assert = require('node:assert/strict');
require('../defence-stack-patch');
const { CounterEngine } = require('../counter-engine');
const { DetectionEngine } = require('../detection-engine');
const { SudarshanaCore } = require('../sudarshana-core');
const { BloomFilter } = require('../bloom-filter');

const checks = [];
function check(name, fn) {
  fn();
  checks.push(name);
}
function req(ip, payload) {
  const rawBodyStr = JSON.stringify({ payload });
  return {
    ip,
    method: 'POST',
    path: '/api/input',
    url: '/api/input',
    query: {},
    body: { payload },
    rawBodyStr,
    rawBodyBytes: Buffer.byteLength(rawBodyStr),
    headers: { 'content-type': 'application/json', 'user-agent': 'Krishna-Defence-Contract/1.0' },
    isLoginAttemptFailed: false
  };
}
function isolatedCounter() {
  const counter = new CounterEngine();
  // Isolate this contract from committed demo memory and filesystem writes.
  counter.learnedPatterns = [];
  counter.attackTypeWeights = {};
  counter.sourceIncidentHistory = new Map();
  counter.bloom = new BloomFilter(8192, 4);
  counter._persist = () => {};
  return counter;
}

async function main() {
  const lowConfidenceCounter = isolatedCounter();
  const lowConfidence = lowConfidenceCounter.learnFromIncident({
    rawInput: JSON.stringify({ payload: '<script>alert(1)</script>' }),
    attackTypes: ['xss'],
    sourceIp: '192.0.2.9',
    confidenceScore: 60
  });
  check('Low-confidence incident cannot poison Arjuna memory', () => {
    assert.equal(lowConfidence.confidenceRejected, true);
    assert.equal(lowConfidenceCounter.learnedPatterns.length, 0);
  });

  const counter = isolatedCounter();
  const rootPayload = 'UNION SELECT username,password FROM users WHERE id=1';
  const learned = counter.learnFromIncident({
    rawInput: JSON.stringify({ payload: rootPayload }),
    attackTypes: ['sql-injection'],
    sourceIp: '192.0.2.10',
    confidenceScore: 96
  });

  check('Krishna independently validates a root incident before learning', () => {
    assert.equal(learned.validationRejected, undefined);
    assert.equal(learned.rootValidation.tier, 'danger');
    assert.ok(learned.newlyLearned.length >= 1);
  });

  const entry = learned.newlyLearned[0];
  check('Mutation generation produces candidates and independently validated variants', () => {
    assert.ok(learned.mutationCandidates > 0);
    assert.ok(learned.mutationsValidated > 0);
    assert.ok(Array.isArray(entry.validatedSyntheticMutations));
    assert.ok(entry.validatedSyntheticMutations.length > 0);
    assert.ok(entry.mutationValidation.coverage > 0);
  });

  const allRoots = (learned.newlyLearned || []).map(e => e.token).filter(Boolean);
  const allValidated = (learned.newlyLearned || []).flatMap(e => e.validatedSyntheticMutations || []);
  const mutation = allValidated.find(m => allRoots.every(root => !m.token.includes(root)));
  check('Krishna produces at least one distinct validated mutation', () => {
    assert.ok(mutation, 'expected a validated mutation that is not an exact learned root token');
  });

  check('Arjuna fast-path recognizes a validated related mutation', () => {
    const match = counter.checkLearned(mutation.token);
    assert.ok(match);
    assert.equal(match.matchSource, 'validated_mutation');
    assert.equal(match.matchedMutation, mutation.token);
  });

  check('Generated but unvalidated candidates cannot become Arjuna block decisions', () => {
    const unvalidated = 'benign-generated-candidate-should-not-block-12345';
    entry.syntheticMutations.push(unvalidated);
    counter.bloom.add(unvalidated); // Bloom membership alone must never be authority.
    assert.equal(counter.checkLearned(unvalidated), null);
  });

  check('Detection layer routes validated known mutation to Arjuna danger fast-path', () => {
    const engine = new DetectionEngine(counter);
    const result = engine.inspect(req('192.0.2.11', mutation.token));
    assert.equal(result.isLearnedMatch, true);
    assert.equal(result.tier, 'danger');
  });

  check('Known/static front-line block does not unnecessarily invoke Sudarshana', () => {
    const engine = new DetectionEngine(null);
    const known = engine.inspect(req('192.0.2.20', '<script>alert(1)</script>'));
    assert.equal(known.tier, 'danger');
    assert.equal(known.isZeroDayAnomaly, false);
    const core = new SudarshanaCore({ timeBudgetMs: 1000 });
    const result = core.engageScopedLockdown({
      scopeType: 'ip', scopeValue: '192.0.2.20', incidentId: 'known',
      reason: known.reasons[0], forensicSnapshot: { ip: '192.0.2.20' }
    });
    assert.equal(result.status, 'STANDBY_ARJUNA_BLOCKED');
    assert.equal(core.isUnderLockdown({ ip: '192.0.2.20' }).locked, false);
  });

  check('Unresolved unknown stays fail-closed under scoped Sudarshana containment', () => {
    const engine = new DetectionEngine(null);
    const unknown = engine.inspect(req('192.0.2.21', 'probe ${process.mainModule.require("child_process")}'));
    assert.equal(unknown.tier, 'danger');
    assert.equal(unknown.isZeroDayAnomaly, true);
    const core = new SudarshanaCore({ timeBudgetMs: 1000 });
    core.engageScopedLockdown({
      scopeType: 'ip', scopeValue: '192.0.2.21', incidentId: 'unknown',
      reason: unknown.reasons[0], forensicSnapshot: { ip: '192.0.2.21' }
    });
    const recovery = core.evaluateAutonomousRecovery({
      scopeType: 'ip', scopeValue: '192.0.2.21',
      krishnaAnalysis: { confidenceScore: 98, mutationsCount: 0, learnedTokens: [] }
    });
    assert.equal(recovery.recovered, false);
    assert.equal(core.isUnderLockdown({ ip: '192.0.2.21' }).locked, true);
  });

  const successEngine = new DetectionEngine(null);
  const successUnknown = successEngine.inspect(req('192.0.2.22', 'probe ${process.mainModule.require("child_process")}'));
  const successCore = new SudarshanaCore({ timeBudgetMs: 1000 });
  const lock = successCore.engageScopedLockdown({
    scopeType: 'ip', scopeValue: '192.0.2.22', incidentId: 'study',
    reason: successUnknown.reasons[0], forensicSnapshot: { ip: '192.0.2.22' }
  });
  const pending = successCore.evaluateAutonomousRecovery({
    scopeType: 'ip', scopeValue: '192.0.2.22',
    krishnaAnalysis: { confidenceScore: 98, mutationsCount: 2, learnedTokens: ['validated-token'] }
  });
  check('Sudarshana holds the offender scope while Krishna validation completes', () => {
    assert.equal(lock.status, 'LOCKED');
    assert.equal(pending.pending, true);
    assert.equal(successCore.isUnderLockdown({ ip: '192.0.2.22' }).locked, true);
    assert.equal(successCore.isUnderLockdown({ ip: '192.0.2.23' }).locked, false);
  });

  await new Promise(resolve => setTimeout(resolve, 350));
  check('Validated Krishna study permits time-bound autonomous recovery', () => {
    assert.equal(successCore.isUnderLockdown({ ip: '192.0.2.22' }).locked, false);
    assert.equal(successCore.verifyLedgerIntegrity().isValid, true);
  });

  console.log(JSON.stringify({
    passed: checks.length,
    checks,
    mutationValidation: {
      candidates: learned.mutationCandidates,
      validated: learned.mutationsValidated,
      coverage: learned.mutationValidationCoverage
    },
    scope: 'owned/local defensive module contract; no external target traffic'
  }, null, 2));
}

main().catch(err => {
  console.error(err);
  process.exitCode = 1;
});
