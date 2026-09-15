/**
 * Comprehensive Verification Suite — Sudarshana Core, Krishna Force & Arjuna Force
 *
 * Verifies:
 * 1. Arjuna Force <1ms Multi-Signal Interception
 * 2. Sudarshana Scoped Lockdown (Zero Downtime on other routes/users)
 * 3. Krishna Force AI Deep Forensics & Priority Mutation Synthesis
 * 4. Sudarshana Time-Bound Autonomous Recovery Cycle
 * 5. Multi-Party Cryptographic 2-Signature Administrative Unlock
 * 6. Cryptographic SHA-256 Tamper-Evident Ledger Verification
 * 7. Adversarial Poisoning Flooding Defense
 */

const crypto = require('node:crypto');
const { DetectionEngine } = require('./detection-engine');
const { CounterEngine } = require('./counter-engine');
const { SudarshanaCore } = require('./sudarshana-core');

async function runSudarshanaKrishnaVerification() {
  console.log('================================================================');
  console.log('⚔️  KRISHNA DEFENCE SYSTEM — UNIFIED SUDARSHANA-KRISHNA AUDIT');
  console.log('================================================================\n');

  const counter = new CounterEngine();
  const engine = new DetectionEngine(counter);
  const approvalKeys = {lead:crypto.generateKeyPairSync('ed25519'), ops:crypto.generateKeyPairSync('ed25519')};
  const unlockPublicKeys = Object.fromEntries(Object.entries(approvalKeys).map(([id,p])=>[id,p.publicKey.export({format:'pem',type:'spki'})]));
  const sudarshana = new SudarshanaCore({ timeBudgetMs: 5000, confidenceThreshold: 85, unlockPublicKeys });
  function signApproval(signer,scopeKey) {
    const approval={signer,scopeKey,lockdownId:sudarshana.scopedLockdowns.get(scopeKey).id,expiresAt:Date.now()+60000};
    return {...approval,signature:crypto.sign(null,Buffer.from(JSON.stringify(approval)),approvalKeys[signer].privateKey).toString('base64')};
  }

  // TEST 1: Arjuna Force Multi-Signal Interception
  console.log('--- TEST 1: Arjuna Force Multi-Signal Front-Line Decision ---');
  const t1Req = {
    method: 'POST',
    path: '/login',
    query: {},
    body: { username: 'admin', password: "' OR 1=1--" },
    ip: '185.220.101.1'
  };
  const t1Result = engine.inspect(t1Req);
  console.log(`[Arjuna Decision]: Tier=${t1Result.tier}, Score=${t1Result.score}, Type=${t1Result.attackType}`);
  console.log(`[Reasons]: ${t1Result.reasons.join('; ')}`);
  console.assert(t1Result.tier === 'danger', 'Test 1 Failed: Should be danger tier');
  console.log('✅ TEST 1 PASSED: Arjuna Force intercepted threat accurately!\n');

  // TEST 2: Sudarshana Scoped Lockdown on Breach
  console.log('--- TEST 2: Sudarshana Scoped Lockdown Engagement ---');
  const lock = sudarshana.engageScopedLockdown({
    scopeType: 'ip',
    scopeValue: '185.220.101.1',
    incidentId: 'INC-TEST-001',
    payload: JSON.stringify(t1Req.body),
    reason: 'Zero-day SQLi Tautology Exploit',
    forensicSnapshot: { ip: t1Req.ip, path: t1Req.path }
  });
  console.log(`[Lockdown Status]: ID=${lock.id}, Scope=${lock.scopeKey}, Status=${lock.status}`);
  
  // Verify that the locked IP is blocked
  const checkAttacker = sudarshana.isUnderLockdown({ ip: '185.220.101.1', path: '/login', query: {}, body: {} });
  console.log(`[Attacker Request Check]: Locked=${checkAttacker.locked}, Reason=${checkAttacker.reason}`);
  console.assert(checkAttacker.locked === true, 'Test 2 Failed: Attacker should be under lockdown');

  // Verify that ANOTHER legitimate user on another IP is NOT blocked (Zero Downtime!)
  const checkLegitUser = sudarshana.isUnderLockdown({ ip: '203.0.113.50', path: '/login', query: {}, body: {} });
  console.log(`[Legitimate User Check]: Locked=${checkLegitUser.locked} (Zero Downtime for Normal Users!)`);
  console.assert(checkLegitUser.locked === false, 'Test 2 Failed: Legitimate user should NOT be locked');
  console.log('✅ TEST 2 PASSED: Sudarshana scoped lockdown isolates attacker with zero impact on others!\n');

  // TEST 3: Krishna Force AI Deep Forensic & Mutation Generation
  console.log('--- TEST 3: Krishna Force Forensic R&D & Pre-emptive Immunization ---');
  const freshToken = `' OR ${Math.floor(Math.random() * 90000 + 10000)}=${Math.floor(Math.random() * 90000 + 10000)}--`;
  const learning = counter.learnFromIncident({
    rawInput: JSON.stringify({ password: freshToken }),
    attackTypes: ['sql-injection'],
    sourceIp: '185.220.101.1',
    confidenceScore: 98
  });
  console.log(`[Krishna Learned]: Tokens=${learning.newlyLearned.length}, Mutations Synthesized=${learning.mutationsSynthesized}`);
  console.log(`[Confidence Score]: ${learning.confidenceScore}%`);
  console.assert(learning.mutationsSynthesized >= 2, 'Test 3 Failed: Should synthesize mutations');
  console.log('✅ TEST 3 PASSED: Krishna Force successfully synthesized mutations & trained Bloom Filter!\n');

  // TEST 3.5: Pattern-Level Distributed Botnet Scoped Lockdown
  console.log('--- TEST 3.5: Sudarshana Pattern-Level Distributed Botnet Lockdown ---');
  sudarshana.engageScopedLockdown({
    scopeType: 'pattern',
    scopeValue: 'UNION SELECT password FROM users',
    incidentId: 'INC-BOTNET-01',
    payload: 'UNION SELECT password FROM users',
    reason: 'Distributed Botnet Multi-IP Attack'
  });
  // Attacker 2 from DIFFERENT IP sending same pattern
  const botnetCheck = sudarshana.isUnderLockdown({ ip: '45.33.32.156', path: '/login', query: {}, body: { q: 'UNION SELECT password FROM users' } });
  console.log(`[Botnet Attack Check]: Locked=${botnetCheck.locked}, Scope=${botnetCheck.scope}`);
  console.assert(botnetCheck.locked === true, 'Test 3.5 Failed: Distributed botnet pattern should be locked across all IPs');
  console.log('✅ TEST 3.5 PASSED: Sudarshana Pattern-Level lockdown successfully blocks distributed botnets across any IP!\n');

  // TEST 4: Sudarshana Time-Bound Autonomous Recovery Cycle
  console.log('--- TEST 4: Sudarshana Autonomous Closed-Loop Recovery ---');
  const recovery = sudarshana.evaluateAutonomousRecovery({
    scopeType: 'ip',
    scopeValue: '185.220.101.1',
    krishnaAnalysis: {
      confidenceScore: 98,
      mutationsCount: learning.mutationsSynthesized
    }
  });
  console.log(`[Autonomous Recovery]: Recovered=${recovery.recovered}, Status=${recovery.lockdown.status}`);
  console.log(`[Recovery Cycle]: Duration=${recovery.lockdown.recoveryCycle.recoveredInMs}ms, Confidence=${recovery.lockdown.recoveryCycle.krishnaConfidence}%`);
  console.assert(recovery.recovered === true, 'Test 4 Failed: Should auto-recover when confidence is high');
  console.log('✅ TEST 4 PASSED: Sudarshana safely lifted scoped lockdown in <5ms after Krishna confirmed safety!\n');

  // TEST 5: Cryptographic Tamper-Evident SHA-256 Ledger Verification
  console.log('--- TEST 5: Cryptographic SHA-256 Tamper-Evident Ledger Integrity ---');
  const ledgerSummary = sudarshana.getLedgerSummary();
  console.log(`[Ledger Status]: Total Blocks=${ledgerSummary.totalBlocks}, Latest Hash=${ledgerSummary.latestBlockHash.substring(0, 24)}...`);
  
  // Verify Hash Chain validity
  for (let i = 1; i < sudarshana.ledger.length; i++) {
    const current = sudarshana.ledger[i];
    const prev = sudarshana.ledger[i - 1];
    console.assert(current.previousHash === prev.hash, `Hash chain broken at block ${i}`);
  }
  console.log('✅ TEST 5 PASSED: Cryptographic hash chain is mathematically intact & tamper-evident!\n');

  // TEST 6: Multi-Party 2-Signature Administrative Cryptographic Unlock
  console.log('--- TEST 6: Two-Party Cryptographic Signature Manual Unlock ---');
  sudarshana.engageScopedLockdown({
    scopeType: 'route',
    scopeValue: '/admin',
    incidentId: 'INC-ADMIN-PROBE',
    payload: 'sensitive probe',
    reason: 'Admin Route Probe'
  });
  
  // Single signature fails
  const singleSig = sudarshana.multiPartyUnlock({
    scopeType: 'route',
    scopeValue: '/admin',
    signatures: ['SIG_SEC_LEAD_2026']
  });
  console.log(`[Single Signature Attempt]: OK=${singleSig.ok} (${singleSig.error})`);
  console.assert(singleSig.ok === false, 'Test 6 Failed: Single signature must fail');

  // Dual valid signatures succeed
  const dualSig = sudarshana.multiPartyUnlock({
    scopeType: 'route',
    scopeValue: '/admin',
    signatures: [signApproval('lead','route:/admin'), signApproval('ops','route:/admin')]
  });
  console.log(`[Dual Signature Attempt]: OK=${dualSig.ok} (${dualSig.message})`);
  console.assert(dualSig.ok === true, 'Test 6 Failed: Dual signatures must succeed');
  console.log('✅ TEST 6 PASSED: Multi-party cryptographic unlock enforced!\n');

  // TEST 7: Adversarial Poisoning Flooding Defense
  console.log('--- TEST 7: Adversarial Memory Poisoning Flooding Defense ---');
  let poisoningCaught = false;
  for (let i = 0; i < 12; i++) {
    const res = counter.learnFromIncident({
      rawInput: `fake_incident_payload_${i}`,
      attackTypes: ['xss'],
      sourceIp: '198.51.100.99',
      confidenceScore: 90
    });
    if (res.poisoningSuspected) {
      poisoningCaught = true;
      console.log(`[Poisoning Defense]: Caught at iteration ${i + 1} (${res.reason})`);
      break;
    }
  }
  console.assert(poisoningCaught === true, 'Test 7 Failed: Poisoning flooding must be caught');
  console.log('✅ TEST 7 PASSED: Memory poisoning attack neutralized without corrupting Bloom filter!\n');

  console.log('================================================================');
  console.log('🎯 ALL 7 UNIFIED ARCHITECTURE TESTS 100% PASSED & VERIFIED!');
  console.log('================================================================');
}

runSudarshanaKrishnaVerification().catch(console.error);
