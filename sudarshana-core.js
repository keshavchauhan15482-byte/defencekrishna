/**
 * Sentinel Layer 3 — Sudarshana Core: Scoped Lockdown, Cryptographic Ledger & Auto-Recovery
 *
 * Implements the Mahabharata Defensive Trinity:
 * 1. Arjuna Force (Perimeter Front Line) <1ms Multi-Signal Filter
 * 2. Krishna Force (Supreme AI Core) Deep Forensic & Mutation R&D
 * 3. Sudarshana Core (Immortal Containment Sentry) Scoped Lockdown, Cryptographic Ledger & Time-Bound Auto-Recovery
 */

const crypto = require('crypto');

class SudarshanaCore {
  constructor(options = {}) {
    this.timeBudgetMs = options.timeBudgetMs || 8000; // 8 seconds default time budget
    this.confidenceThreshold = options.confidenceThreshold || 85; // 85% confidence required to auto-lift
    this.scopedLockdowns = new Map(); // scopeKey -> lockdownRecord
    this.ledger = []; // SHA-256 hash-chained tamper-evident audit ledger
    this.unlockedKeys = new Set();
    this.unlockPublicKeys = options.unlockPublicKeys || {};
    this.retainedAnchor = "0".repeat(64);
    this._initGenesisBlock();
  }

  _initGenesisBlock() {
    const genesis = {
      index: 0,
      timestamp: Date.now(),
      previousHash: '0000000000000000000000000000000000000000000000000000000000000000',
      data: { event: 'SUDARSHANA_GENESIS', message: 'Cryptographic Tamper-Evident Security Ledger Initialized' },
      hash: ''
    };
    genesis.hash = this._calculateHash(genesis);
    this.ledger.push(genesis);
  }

  _calculateHash(block) {
    const str = `${block.index}|${block.timestamp}|${block.previousHash}|${JSON.stringify(block.data)}`;
    return crypto.createHash('sha256').update(str).digest('hex');
  }

  _appendBlock(data) {
    const prevBlock = this.ledger[this.ledger.length - 1];
    const newBlock = {
      index: prevBlock.index + 1,
      timestamp: Date.now(),
      previousHash: prevBlock.hash,
      data,
      hash: ''
    };
    newBlock.hash = this._calculateHash(newBlock);
    this.ledger.push(newBlock);
    if (this.ledger.length > 200) this.retainedAnchor = this.ledger.shift().hash;
    return newBlock;
  }

  /**
   * Checks if an incoming request falls under an ACTIVE scoped lockdown.
   * Only the affected route/IP/session is blocked — Other scopes are unaffected by this specific lockdown check.
   */
  isUnderLockdown(req) {
    const ip = req.ip || '';
    const path = (req.path || '/').split('?')[0];
    const session = (req.body && req.body.user_id) || (req.query || {}).user_id || '';

    // Check IP scope
    const ipLock = this.scopedLockdowns.get(`ip:${ip}`);
    if (ipLock && ['LOCKED','HUMAN_ESCALATED'].includes(ipLock.status)) return { locked: true, reason: ipLock.reason, scope: `IP: ${ip}`, lock: ipLock };

    // Check Route scope (only if route is explicitly locked)
    const routeLock = this.scopedLockdowns.get(`route:${path}`);
    if (routeLock && ['LOCKED','HUMAN_ESCALATED'].includes(routeLock.status)) return { locked: true, reason: routeLock.reason, scope: `Route: ${path}`, lock: routeLock };

    // Check Session scope
    if (session) {
      const sessionLock = this.scopedLockdowns.get(`session:${session}`);
      if (sessionLock && ['LOCKED','HUMAN_ESCALATED'].includes(sessionLock.status)) return { locked: true, reason: sessionLock.reason, scope: `Session: ${session}`, lock: sessionLock };
    }

    // Check Pattern / Distributed Botnet Token scope
    const combined = (req.url || '') + ' ' + JSON.stringify(req.query || {}) + ' ' + (req.rawBodyStr || JSON.stringify(req.body || {}));
    for (const [key, lock] of this.scopedLockdowns.entries()) {
      if (key.startsWith('pattern:') && ['LOCKED','HUMAN_ESCALATED'].includes(lock.status)) {
        const pattern = key.substring(8);
        if (pattern.length >= 4 && combined.includes(pattern)) {
          return { locked: true, reason: lock.reason, scope: `Distributed Botnet Signature: ${pattern.substring(0, 30)}`, lock };
        }
      }
    }

    return { locked: false };
  }

  /**
   * Engages a SCOPED lockdown when a breach is suspected.
   * Isolates the specific IP / Route without taking down the entire website.
   */
  engageScopedLockdown({ scopeType, scopeValue, incidentId, payload, reason, forensicSnapshot }) {
    const scopeKey = `${scopeType}:${scopeValue}`;
    const lockdown = {
      id: 'LOCK-' + crypto.randomUUID(),
      scopeKey,
      scopeType,
      scopeValue,
      incidentId,
      payload,
      reason,
      lockedAt: Date.now(),
      timeBudgetMs: this.timeBudgetMs,
      expiresAt: Date.now() + this.timeBudgetMs,
      status: 'LOCKED',
      forensicSnapshot: forensicSnapshot || {},
      recoveryCycle: null
    };

    this.scopedLockdowns.set(scopeKey, lockdown);

    // Record immutable block in Cryptographic Ledger
    this._appendBlock({
      action: 'SCOPED_LOCKDOWN_ENGAGED',
      lockdownId: lockdown.id,
      scopeKey,
      incidentId,
      reason
    });

    console.log(`[SUDARSHANA CORE] 🔒 SCOPED LOCKDOWN ENGAGED on ${scopeKey} (Time Budget: ${this.timeBudgetMs / 1000}s)`);
    return lockdown;
  }

  /**
   * Autonomous Closed-Loop Recovery Execution:
   * Called by Krishna Force once R&D, mutation extraction, and Bloom filter training are completed.
   */
  evaluateAutonomousRecovery({ scopeType, scopeValue, krishnaAnalysis }) {
    const scopeKey = `${scopeType}:${scopeValue}`;
    const lockdown = this.scopedLockdowns.get(scopeKey);
    if (!lockdown || lockdown.status !== 'LOCKED') return { recovered: false, error: 'No active lockdown found for scope' };

    const now = Date.now();
    const elapsedMs = now - lockdown.lockedAt;
    const isWithinTimeBudget = elapsedMs <= this.timeBudgetMs;
    const confidence = krishnaAnalysis.confidenceScore || 0;
    const isConfident = confidence >= this.confidenceThreshold;

    if (isWithinTimeBudget && isConfident) {
      lockdown.status = 'AUTO_RECOVERED';
      lockdown.recoveredAt = now;
      lockdown.recoveryCycle = {
        recoveredInMs: elapsedMs,
        krishnaConfidence: confidence,
        mutationsSynthesized: krishnaAnalysis.mutationsCount || 0,
        bloomFilterSynchronized: true,
        verdict: 'AUTONOMOUS_RESTORED'
      };

      // Record recovery in Cryptographic Ledger
      this._appendBlock({
        action: 'AUTONOMOUS_LOCKDOWN_LIFTED',
        lockdownId: lockdown.id,
        scopeKey,
        recoveryCycle: lockdown.recoveryCycle
      });

      console.log(`[SUDARSHANA CORE] 🛡️ AUTONOMOUS RECOVERY COMPLETE for ${scopeKey} in ${elapsedMs}ms (Confidence: ${confidence}%) — Scoped Lockdown Safely Lifted!`);
      return { recovered: true, lockdown };
    } else {
      // Time expired or confidence insufficient — Fail-Closed Safety Mode
      lockdown.status = 'HUMAN_ESCALATED';
      this._appendBlock({
        action: 'LOCKDOWN_ESCALATED_FAIL_CLOSED',
        lockdownId: lockdown.id,
        scopeKey,
        reason: isWithinTimeBudget ? `Low AI Confidence (${confidence}%)` : `Time budget exceeded (${elapsedMs}ms)`
      });

      console.log(`[SUDARSHANA CORE] ⚠️ LOCKDOWN ESCALATED (Fail-Closed Safety) for ${scopeKey}`);
      return { recovered: false, lockdown, reason: 'Escalated to multi-party human approval' };
    }
  }

  /**
   * Two-Party Cryptographic Signature Unlock (for manual overrides)
   */
  multiPartyUnlock({ scopeType, scopeValue, signatures }) {
    const scopeKey = `${scopeType}:${scopeValue}`;
    const lockdown = this.scopedLockdowns.get(scopeKey);
    if (!lockdown || !['LOCKED','HUMAN_ESCALATED'].includes(lockdown.status)) return {ok:false,error:'No active lockdown'};
    if (!Array.isArray(signatures) || signatures.length !== 2) return {ok:false,error:'Two distinct Ed25519 approvals required'};
    const seen = new Set();
    const seenKeys = new Set();
    for (const approval of signatures) {
      if (!approval || typeof approval !== 'object' || typeof approval.signer !== 'string' || seen.has(approval.signer) ||
          !Object.prototype.hasOwnProperty.call(this.unlockPublicKeys,approval.signer) ||
          !Number.isFinite(approval.expiresAt) || approval.expiresAt <= Date.now() ||
          approval.expiresAt > Date.now()+300000 || approval.lockdownId !== lockdown.id || approval.scopeKey !== scopeKey) {
        return {ok:false,error:'Invalid, expired, replayed or duplicate approval'};
      }
      try {
        const key=crypto.createPublicKey(this.unlockPublicKeys[approval.signer]);
        const fingerprint=crypto.createHash('sha256').update(key.export({format:'der',type:'spki'})).digest('hex');
        if (seenKeys.has(fingerprint)) throw new Error('Approvals must use distinct public keys');
        const payload=JSON.stringify({signer:approval.signer,scopeKey,lockdownId:lockdown.id,expiresAt:approval.expiresAt});
        if (key.asymmetricKeyType !== 'ed25519' || !crypto.verify(null,Buffer.from(payload),key,Buffer.from(approval.signature,'base64'))) throw new Error('Invalid signature');
        seenKeys.add(fingerprint);
      } catch (_) {return {ok:false,error:'Invalid Ed25519 signature'};}
      seen.add(approval.signer);
    }
    lockdown.status='MANUAL_UNLOCKED';lockdown.unlockedAt=Date.now();
    this._appendBlock({action:'MANUAL_MULTI_PARTY_UNLOCK',lockdownId:lockdown.id,scopeKey,signers:[...seen]});
    return {ok:true,message:'Scope released after two independent signed approvals'};
  }

  /**
   * Cryptographic Hash-Chain Integrity Verifier:
   * Checks retained hash-chain consistency. Complete-history replacement needs an independent external anchor.
   */
  verifyLedgerIntegrity() {
    for (let i = 0; i < this.ledger.length; i++) {
      const current = this.ledger[i];
      const prev = this.ledger[i - 1];

      // 1. Verify previous hash pointer
      if (current.previousHash !== (prev ? prev.hash : this.retainedAnchor)) {
        return {
          isValid: false,
          tamperedBlockIndex: i,
          error: `Cryptographic Chain Broken: Block #${i} previousHash does not match Block #${i - 1} hash!`,
          protocol: 'FAIL_CLOSED_EMERGENCY_ALARM'
        };
      }

      // 2. Re-calculate mathematical SHA-256 hash of the block contents
      const calculatedHash = this._calculateHash(current);
      if (current.hash !== calculatedHash) {
        return {
          isValid: false,
          tamperedBlockIndex: i,
          error: `Mathematical Hash Mismatch: Block #${i} payload was tampered/modified!`,
          expectedHash: calculatedHash,
          actualHash: current.hash,
          protocol: 'FAIL_CLOSED_EMERGENCY_ALARM'
        };
      }
    }

    return {
      isValid: true,
      totalBlocksVerified: this.ledger.length,
      status: 'HASH_CHAIN_CONSISTENT', limitation: 'In-memory chain; independent external anchoring is required to detect complete history replacement'
    };
  }

  getLedgerSummary() {
    const integrity = this.verifyLedgerIntegrity();
    return {
      totalBlocks: this.ledger.length,
      latestBlockHash: this.ledger[this.ledger.length - 1]?.hash,
      activeLockdowns: [...this.scopedLockdowns.values()].filter(l => ['LOCKED','HUMAN_ESCALATED'].includes(l.status)).length,
      integrity,
      recentBlocks: this.ledger.slice(-10).reverse()
    };
  }
}

module.exports = { SudarshanaCore };
