/**
 * Bharat Cyber Shield — Layer 3: Markov Chain Behavioral Sequence Model
 * Temporal State Transition & Rapid IDOR / Scanner Probe Anomaly Analyzer
 * 
 * Latency Target: < 0.05ms
 */

class BehavioralSequenceModel {
  constructor() {
    this.transitions = new Map(); // currPath -> Map(nextPath -> count)
    this.pathTotals = new Map();   // currPath -> totalOutTransitions
    this.vocabulary = new Set();
    this.sessionHistories = new Map(); // ip_or_session -> [ { path, ts, idorVal } ]
    this.maxHistoryPerSession = 15;
    this.sessionTtlMs = 10 * 60 * 1000; // 10 mins

    this.seedBaselineTransitions();
  }

  seedBaselineTransitions() {
    const normalSessions = [
      ['/', '/products', '/products', '/checkout'],
      ['/', '/products', '/login', '/checkout'],
      ['/login', '/products', '/checkout'],
      ['/login', '/login'],
      ['/products', '/login'],
      ['/checkout', '/checkout'],
      ['/cart', '/checkout'],
      ['/', '/search', '/products', '/checkout'],
      ['/products', '/products', '/products'],
      ['/', '/help', '/contact', '/products']
    ];

    for (const session of normalSessions) {
      this.recordSession(session);
    }
  }

  recordSession(pathArray) {
    for (let i = 0; i < pathArray.length - 1; i++) {
      const curr = this.normalizePath(pathArray[i]);
      const next = this.normalizePath(pathArray[i + 1]);
      this.recordTransition(curr, next);
    }
  }

  recordTransition(curr, next) {
    this.vocabulary.add(curr);
    this.vocabulary.add(next);

    if (!this.transitions.has(curr)) {
      this.transitions.set(curr, new Map());
    }
    const nextMap = this.transitions.get(curr);
    nextMap.set(next, (nextMap.get(next) || 0) + 1);

    this.pathTotals.set(curr, (this.pathTotals.get(curr) || 0) + 1);
  }

  normalizePath(rawPath) {
    const p = String(rawPath || '/').split('?')[0];
    // Generalize numeric IDs to :id for generic transition modeling
    return p.replace(/\/\d+/g, '/:id');
  }

  extractIdorId(rawPath) {
    const match = String(rawPath || '').match(/\/(\d+)(\/|$)/);
    return match ? parseInt(match[1], 10) : null;
  }

  /**
   * Tracks an incoming request from an IP / session and returns sequence anomaly metrics
   */
  evaluateRequest(sessionKey, rawPath) {
    const now = Date.now();
    const cleanPath = this.normalizePath(rawPath);
    const idorNum = this.extractIdorId(rawPath);

    if (!this.sessionHistories.has(sessionKey)) {
      this.sessionHistories.set(sessionKey, []);
    }

    const history = this.sessionHistories.get(sessionKey);
    // Prune stale entries
    while (history.length > 0 && now - history[0].ts > this.sessionTtlMs) {
      history.shift();
    }

    let transitionProb = 1.0;
    let isIdorRapidScan = false;
    let scanVelocity = 0;

    if (history.length > 0) {
      const lastEntry = history[history.length - 1];
      const prevPath = lastEntry.path;

      // 1. Compute Markov transition probability with Laplace smoothing
      const nextMap = this.transitions.get(prevPath);
      const count = nextMap ? (nextMap.get(cleanPath) || 0) : 0;
      const total = this.pathTotals.get(prevPath) || 0;
      const vocabSize = Math.max(this.vocabulary.size, 10);

      transitionProb = (count + 1) / (total + vocabSize);

      // 2. IDOR Sequence Detection (e.g., sequential access to /user/101, /user/102 in <1s)
      if (idorNum !== null && lastEntry.idorVal !== null) {
        const idDiff = Math.abs(idorNum - lastEntry.idorVal);
        const timeDiff = now - lastEntry.ts;

        if (idDiff >= 1 && idDiff <= 5 && timeDiff < 1500) {
          isIdorRapidScan = true;
          scanVelocity = Number((1000 / Math.max(timeDiff, 10)).toFixed(2)); // requests per second
        }
      }
    }

    // Record new state in session
    history.push({ path: cleanPath, ts: now, idorVal: idorNum });
    if (history.length > this.maxHistoryPerSession) history.shift();

    // Dynamically learn benign transitions if probability is not extreme zero
    if (history.length >= 2 && !isIdorRapidScan) {
      const prev = history[history.length - 2].path;
      this.recordTransition(prev, cleanPath);
    }

    // Sequence anomaly score: 1.0 (normal) down to 0.0 (highly anomalous)
    let anomalyScore = 0.0;
    if (isIdorRapidScan) {
      anomalyScore = 0.88;
    } else if (transitionProb < 0.05 && history.length >= 3) {
      anomalyScore = Math.max(0, Math.min(0.50, -Math.log10(Math.max(transitionProb, 0.001)) / 3.0));
    }

    return {
      sequenceScore: Number(anomalyScore.toFixed(4)),
      transitionProbability: Number(transitionProb.toFixed(4)),
      isIdorRapidScan,
      scanVelocity,
      sessionDepth: history.length
    };
  }
}

const behavioralSequenceModel = new BehavioralSequenceModel();

module.exports = {
  BehavioralSequenceModel,
  behavioralSequenceModel
};
