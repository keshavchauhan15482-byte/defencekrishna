'use strict';

const assert = require('node:assert/strict');
require('../defence-stack-v6-patch');
const v5 = require('../defence-stack-v5-patch');
const { DetectionEngine } = require('../detection-engine');
const { CounterEngine } = require('../counter-engine');
const { SudarshanaCore } = require('../sudarshana-core');

function request(ip, payload) {
  const body = { payload };
  const rawBodyStr = JSON.stringify(body);
  return {
    ip,
    method: 'POST',
    path: '/api/input',
    url: '/api/input',
    query: {},
    body,
    rawBodyStr,
    rawBodyBytes: Buffer.byteLength(rawBodyStr),
    headers: {
      'content-type': 'application/json',
      'user-agent': 'Krishna-Local-War-Exercise/1.0'
    },
    isLoginAttemptFailed: false
  };
}

function isolatedCounter() {
  const counter = new CounterEngine();
  counter.learnedPatterns = [];
  counter.attackTypeWeights = {};
  counter.sourceIncidentHistory = new Map();
  counter._persist = () => {};
  v5.rebuildSeparatedMemory(counter);
  return counter;
}

function ratio(hit, total) {
  return total ? hit / total : 0;
}

async function main() {
  const receipts = [];

  // WAVE 0 — civilian/benign sanity. The exercise must not win by blocking
  // everything. These are local module events only.
  const benign = [
    'normal customer message',
    'order status request 12345',
    'network monitoring dashboard is healthy',
    'please select your city from the list',
    'account profile update request',
    'search for blue shoes',
    'invoice status for order 8831',
    'hello support team',
    'product availability query',
    'download monthly report'
  ];
  const benignResults = benign.map((payload, i) =>
    new DetectionEngine(null).inspect(request(`192.0.2.${10 + i}`, payload))
  );
  const benignDanger = benignResults.filter(r => r.tier === 'danger').length;
  assert.equal(benignDanger, 0, 'war exercise produced a benign danger decision');
  receipts.push({
    wave: 'W0_CIVILIAN_TRAFFIC',
    total: benign.length,
    danger: benignDanger,
    observedDangerRate: ratio(benignDanger, benign.length),
    status: 'PASS'
  });

  // WAVE 1 — deterministic known/static pressure. Arjuna owns this route even
  // if a lower-level structural heuristic also recognizes suspicious syntax.
  const known = [
    "' OR 1=1--",
    '<script>alert(1)</script>',
    '../../../../etc/passwd',
    '; whoami',
    'http://169.254.169.254/latest/meta-data/',
    '${jndi:ldap://example.test/a}',
    '<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>',
    '{"$ne":null}',
    '{"__proto__":{"admin":true}}',
    '{{7*7}}'
  ];
  let knownBlocked = 0;
  let knownUnexpectedUnknown = 0;
  let knownAuthority = 0;
  for (let i = 0; i < known.length; i++) {
    const result = new DetectionEngine(null).inspect(request(`198.51.100.${10 + i}`, known[i]));
    if (result.tier === 'danger') knownBlocked++;
    if (result.isZeroDayAnomaly) knownUnexpectedUnknown++;
    if (result.routingAuthority === 'arjuna_known') knownAuthority++;
  }
  assert.equal(knownBlocked, known.length, 'known attack wave was not fully blocked');
  assert.equal(knownUnexpectedUnknown, 0, 'known attack wave leaked into Krishna unknown routing');
  assert.equal(knownAuthority, known.length, 'known attack wave did not receive Arjuna route authority');
  receipts.push({
    wave: 'W1_ARJUNA_KNOWN_PRESSURE',
    total: known.length,
    blocked: knownBlocked,
    blockRate: ratio(knownBlocked, known.length),
    routedUnknown: knownUnexpectedUnknown,
    arjunaAuthority: knownAuthority,
    status: 'PASS'
  });

  // WAVE 2 — genuinely otherwise-unclassified structures. These strings are
  // caught by the anomaly sentry without first matching a deterministic known
  // attack family. They are unseen-to-system fixtures, not real zero-day proof.
  const unknowns = [
    '["constructor"]["prototype"]["isAdmin"]',
    'grep /tmp/runtime-state',
    'ps -aux',
    'bash ./local-stage',
    'ls /var/tmp/krishna'
  ];
  const unknownResults = unknowns.map((payload, i) =>
    new DetectionEngine(null).inspect(request(`203.0.113.${20 + i}`, payload))
  );
  const routedKrishna = unknownResults.filter(
    r => r.tier === 'danger' && r.isZeroDayAnomaly && r.routingAuthority === 'krishna_unknown'
  ).length;
  assert.equal(routedKrishna, unknowns.length, 'one or more curated unknown structures bypassed Krishna routing');
  receipts.push({
    wave: 'W2_KRISHNA_UNKNOWN_PRESSURE',
    total: unknowns.length,
    routedToKrishna: routedKrishna,
    routeRate: ratio(routedKrishna, unknowns.length),
    status: 'PASS'
  });

  // WAVE 3 — study/evolve/promote. Start with an unseen structure, let Krishna
  // independently validate it, generate bounded mutations, then prove that the
  // original root and a distinct validated mutation occupy different Arjuna
  // knowledge stores.
  const counter = isolatedCounter();
  const learningPayload = '["constructor"]["prototype"]["isAdmin"]';
  const firstSight = new DetectionEngine(counter).inspect(request('203.0.113.50', learningPayload));
  assert.equal(firstSight.tier, 'danger');
  assert.equal(firstSight.isZeroDayAnomaly, true);
  assert.equal(firstSight.routingAuthority, 'krishna_unknown');

  const learned = counter.learnFromIncident({
    rawInput: JSON.stringify({ payload: learningPayload }),
    attackTypes: ['prototype-pollution'],
    sourceIp: '203.0.113.50',
    confidenceScore: 96
  });
  assert.ok((learned.newlyLearned || []).length > 0, 'Krishna created no reviewed root knowledge');
  assert.ok((learned.mutationCandidates || 0) > 0, 'Krishna generated no mutation candidates');
  assert.ok((learned.mutationCandidates || 0) <= 128, 'incident mutation cap exceeded');
  assert.ok(Number(learned.mutationBudget && learned.mutationBudget.maxPerTokenObserved || 0) <= 48, 'root mutation cap exceeded');
  assert.ok((learned.mutationsValidated || 0) > 0, 'no mutation candidate passed independent validation');

  const roots = (learned.newlyLearned || []).map(entry => entry.token).filter(Boolean);
  const validated = (learned.newlyLearned || []).flatMap(entry => entry.validatedSyntheticMutations || []);
  const distinctMutation = validated.find(item => item && item.token && roots.every(root => item.token !== root));
  assert.ok(distinctMutation, 'no distinct validated mutation available for promotion replay');

  v5.rebuildSeparatedMemory(counter);
  const originalMatch = counter.checkLearned(roots[0]);
  const mutationMatch = counter.checkLearned(distinctMutation.token);
  assert.ok(originalMatch, 'reviewed root was not reusable by Arjuna');
  assert.ok(mutationMatch, 'validated mutation was not reusable by Arjuna');
  assert.equal(originalMatch.arjunaStore, 'known_attack_store');
  assert.equal(mutationMatch.arjunaStore, 'validated_mutation_store');
  assert.equal(counter.knownAttackBloom.sizeBytes(), 1024);
  assert.equal(counter.validatedMutationBloom.sizeBytes(), 1024);

  const replayOriginal = new DetectionEngine(counter).inspect(request('203.0.113.51', roots[0]));
  const replayMutation = new DetectionEngine(counter).inspect(request('203.0.113.52', distinctMutation.token));
  assert.equal(replayOriginal.isLearnedMatch, true, 'original unknown did not become Arjuna-known after study');
  assert.equal(replayMutation.isLearnedMatch, true, 'validated related mutation did not become Arjuna-known');
  assert.equal(replayOriginal.routingAuthority, 'arjuna_known');
  assert.equal(replayMutation.routingAuthority, 'arjuna_known');

  receipts.push({
    wave: 'W3_KRISHNA_EVOLVE_TO_ARJUNA',
    firstSight: 'KRISHNA_UNKNOWN',
    reviewedRoots: learned.newlyLearned.length,
    mutationCandidates: learned.mutationCandidates,
    validatedMutations: learned.mutationsValidated,
    validationCoverage: learned.mutationValidationCoverage,
    perRootCap: 48,
    perIncidentCap: 128,
    originalReplayStore: originalMatch.arjunaStore,
    mutationReplayStore: mutationMatch.arjunaStore,
    knownBloomBytes: counter.knownAttackBloom.sizeBytes(),
    mutationBloomBytes: counter.validatedMutationBloom.sizeBytes(),
    status: 'PASS'
  });

  // WAVE 4 — confirmed escape. Sudarshana may engage only with explicit owned-
  // lab escape evidence, and only for the offender scope. Krishna then supplies
  // enough validated study evidence for time-bound recovery.
  const offenderIp = '192.0.2.220';
  const neighborIp = '192.0.2.221';
  const escapeResult = new DetectionEngine(null).inspect(
    request(offenderIp, 'grep /tmp/runtime-state')
  );
  assert.equal(escapeResult.tier, 'danger');
  assert.equal(escapeResult.isZeroDayAnomaly, true);
  assert.equal(escapeResult.routingAuthority, 'krishna_unknown');

  const sudarshana = new SudarshanaCore({ timeBudgetMs: 1000 });
  const lock = sudarshana.engageScopedLockdown({
    scopeType: 'ip',
    scopeValue: offenderIp,
    incidentId: 'local-war-confirmed-escape',
    reason: escapeResult.reasons[0],
    forensicSnapshot: { ip: offenderIp },
    escalationEvidence: {
      confirmed: true,
      source: 'owned_lab_backend_receipt',
      reference: 'deterministic local war exercise escape receipt'
    }
  });
  assert.equal(lock.status, 'LOCKED');
  assert.equal(sudarshana.isUnderLockdown({ ip: offenderIp }).locked, true);
  assert.equal(sudarshana.isUnderLockdown({ ip: neighborIp }).locked, false, 'Sudarshana containment leaked to an unrelated client');

  const pendingRecovery = sudarshana.evaluateAutonomousRecovery({
    scopeType: 'ip',
    scopeValue: offenderIp,
    krishnaAnalysis: {
      confidenceScore: 98,
      mutationsCount: learned.mutationsValidated,
      learnedTokens: roots
    }
  });
  assert.equal(pendingRecovery.pending, true);
  await new Promise(resolve => setTimeout(resolve, 350));
  assert.equal(sudarshana.isUnderLockdown({ ip: offenderIp }).locked, false, 'validated local recovery did not release offender scope');
  assert.equal(sudarshana.verifyLedgerIntegrity().isValid, true, 'Sudarshana audit ledger failed integrity verification');

  receipts.push({
    wave: 'W4_SUDARSHANA_CONFIRMED_ESCAPE',
    offender: 'documentation-range IP',
    lockStatus: lock.status,
    unrelatedClientLocked: false,
    recoveryPendingObserved: pendingRecovery.pending,
    releasedAfterValidatedStudy: true,
    ledgerIntegrity: true,
    status: 'PASS'
  });

  const summary = {
    status: 'PASS',
    exercise: 'KRISHNA_DEFENCE_LOCAL_WAR_EXERCISE',
    wavesPassed: receipts.filter(r => r.status === 'PASS').length,
    wavesTotal: receipts.length,
    receipts,
    finalMemory: {
      knownExactEntries: counter.knownAttackStore.length,
      validatedMutationExactEntries: counter.validatedMutationStore.length,
      knownBloomBytes: counter.knownAttackBloom.sizeBytes(),
      mutationBloomBytes: counter.validatedMutationBloom.sizeBytes()
    },
    claimBoundary: 'owned/local deterministic defensive exercise only; no external target traffic; unseen-to-system fixtures are not production zero-day proof'
  };

  console.log(JSON.stringify(summary, null, 2));
}

main().catch(err => {
  console.error(err);
  process.exitCode = 1;
});
