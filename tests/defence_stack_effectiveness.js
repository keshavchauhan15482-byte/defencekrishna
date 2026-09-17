'use strict';

const assert = require('node:assert/strict');
require('../defence-stack-patch');
const { DetectionEngine } = require('../detection-engine');
const { CounterEngine } = require('../counter-engine');
const { BloomFilter } = require('../bloom-filter');

function request({ ip = '192.0.2.10', method = 'POST', path = '/api/input', payload = '', query = {}, body = null, rawBodyStr = null, headers = {} } = {}) {
  const actualBody = body === null ? (payload ? { payload } : {}) : body;
  const raw = rawBodyStr === null ? JSON.stringify(actualBody) : rawBodyStr;
  return {
    ip,
    method,
    path,
    url: path,
    query,
    body: actualBody,
    rawBodyStr: raw,
    rawBodyBytes: Buffer.byteLength(raw),
    headers: {
      'content-type': 'application/json',
      'user-agent': 'Mozilla/5.0 Krishna-Defence-Effectiveness/1.0',
      ...headers
    },
    isLoginAttemptFailed: false
  };
}

function inspectFresh(spec) {
  return new DetectionEngine(null).inspect(request(spec));
}

function isolatedCounter() {
  const counter = new CounterEngine();
  counter.learnedPatterns = [];
  counter.attackTypeWeights = {};
  counter.sourceIncidentHistory = new Map();
  counter.bloom = new BloomFilter(8192, 4);
  counter._persist = () => {};
  return counter;
}

const benign = [
  { method: 'GET', path: '/', body: {}, rawBodyStr: '' },
  { method: 'GET', path: '/home', body: {}, rawBodyStr: '' },
  { method: 'GET', path: '/products', query: {}, body: {}, rawBodyStr: '' },
  { method: 'GET', path: '/search', query: {}, body: {}, rawBodyStr: '' },
  { method: 'GET', path: '/about', body: {}, rawBodyStr: '' },
  { method: 'GET', path: '/status', body: {}, rawBodyStr: '' },
  { method: 'POST', path: '/api/input', payload: 'normal customer message' },
  { method: 'POST', path: '/api/input', payload: 'order status request 12345' },
  { method: 'POST', path: '/api/input', payload: 'please select your city from the list' },
  { method: 'POST', path: '/api/input', payload: 'network monitoring dashboard is healthy' }
];

const known = [
  { name: 'SQL injection', payload: "' OR 1=1--" },
  { name: 'XSS', payload: '<script>alert(1)</script>' },
  { name: 'Path traversal', payload: '../../../../etc/passwd' },
  { name: 'Command injection', payload: '; whoami' },
  { name: 'SSRF metadata', payload: 'http://169.254.169.254/latest/meta-data/' },
  { name: 'Log4j/JNDI', payload: '${jndi:ldap://example.test/a}' },
  { name: 'XXE', payload: '<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>' },
  { name: 'NoSQL operator', payload: '{"$ne":null}' },
  { name: 'Prototype pollution', rawBodyStr: '{"__proto__":{"admin":true}}', body: {} },
  { name: 'Template expression', payload: '{{7*7}}' }
];

const novelStructural = [
  'probe ${process.mainModule.require("child_process")}',
  'x; eval(user_supplied_expression)',
  "' and 7=7 union 'x'",
  '<custom-tag onpointerdown=doSomething()>',
  '["constructor"]["prototype"]["isAdmin"]'
];

const benignResults = benign.map((spec, i) => ({ name: `benign-${i + 1}`, result: inspectFresh({ ...spec, ip: `192.0.2.${30 + i}` }) }));
const knownResults = known.map((spec, i) => ({ name: spec.name, result: inspectFresh({ ...spec, ip: `198.51.100.${30 + i}` }) }));
const novelResults = novelStructural.map((payload, i) => ({ payload, result: inspectFresh({ payload, ip: `203.0.113.${30 + i}` }) }));

const benignDanger = benignResults.filter(x => x.result.tier === 'danger').length;
const knownBlocked = knownResults.filter(x => x.result.tier === 'danger').length;
const novelDanger = novelResults.filter(x => x.result.tier === 'danger').length;
const novelKrishna = novelResults.filter(x => x.result.tier === 'danger' && x.result.isZeroDayAnomaly).length;

const mutationSeeds = [
  { type: 'sql-injection', payload: 'UNION SELECT username,password FROM users WHERE id=1' },
  { type: 'xss', payload: '<script>alert(document.cookie)</script>' },
  { type: 'ssrf', payload: 'http://127.0.0.1/internal/admin' }
];

let mutationCandidates = 0;
let mutationsValidated = 0;
let validatedReuseChecks = 0;
let validatedReuseHits = 0;
const mutationRuns = [];

for (let i = 0; i < mutationSeeds.length; i++) {
  const seed = mutationSeeds[i];
  const counter = isolatedCounter();
  const learned = counter.learnFromIncident({
    rawInput: JSON.stringify({ payload: seed.payload }),
    attackTypes: [seed.type],
    sourceIp: `192.0.2.${100 + i}`,
    confidenceScore: 96
  });
  mutationCandidates += learned.mutationCandidates || 0;
  mutationsValidated += learned.mutationsValidated || 0;
  for (const entry of learned.newlyLearned || []) {
    for (const mutation of entry.validatedSyntheticMutations || []) {
      validatedReuseChecks++;
      if (counter.checkLearned(mutation.token)) validatedReuseHits++;
    }
  }
  mutationRuns.push({
    attackType: seed.type,
    candidates: learned.mutationCandidates || 0,
    validated: learned.mutationsValidated || 0,
    coverage: learned.mutationValidationCoverage || 0,
    learnedRoots: (learned.newlyLearned || []).length
  });
}

const metrics = {
  benign: {
    total: benignResults.length,
    danger: benignDanger,
    observedDangerRate: benignResults.length ? benignDanger / benignResults.length : 0
  },
  knownAttacks: {
    total: knownResults.length,
    blockedDanger: knownBlocked,
    blockRate: knownResults.length ? knownBlocked / knownResults.length : 0
  },
  novelStructural: {
    total: novelResults.length,
    danger: novelDanger,
    dangerRate: novelResults.length ? novelDanger / novelResults.length : 0,
    routedToKrishna: novelKrishna,
    krishnaRouteRate: novelResults.length ? novelKrishna / novelResults.length : 0
  },
  mutations: {
    candidates: mutationCandidates,
    independentlyValidated: mutationsValidated,
    validationCoverage: mutationCandidates ? mutationsValidated / mutationCandidates : 0,
    validatedReuseChecks,
    arjunaReuseHits: validatedReuseHits,
    arjunaValidatedMutationReuseRate: validatedReuseChecks ? validatedReuseHits / validatedReuseChecks : 0,
    runs: mutationRuns
  }
};

// Release-safety gates for this deterministic local contract. These are not
// production accuracy claims; they simply prevent obvious defensive regressions.
assert.ok(metrics.benign.observedDangerRate <= 0.10, `local benign danger rate too high: ${metrics.benign.observedDangerRate}`);
assert.ok(metrics.knownAttacks.blockRate >= 0.80, `known attack block rate too low: ${metrics.knownAttacks.blockRate}`);
assert.ok(metrics.novelStructural.krishnaRouteRate >= 0.60, `novel structural Krishna routing too low: ${metrics.novelStructural.krishnaRouteRate}`);
assert.ok(metrics.mutations.candidates > 0, 'mutation generator produced no candidates');
assert.ok(metrics.mutations.independentlyValidated > 0, 'no mutation candidate passed independent validation');
assert.equal(metrics.mutations.arjunaValidatedMutationReuseRate, 1, 'not all validated mutations were reusable by Arjuna');

console.log(JSON.stringify({
  status: 'PASS',
  metrics,
  knownCases: knownResults.map(x => ({ name: x.name, tier: x.result.tier, score: x.result.score, attackType: x.result.attackType })),
  novelCases: novelResults.map(x => ({ tier: x.result.tier, score: x.result.score, isZeroDayAnomaly: x.result.isZeroDayAnomaly, attackType: x.result.attackType })),
  scope: 'deterministic local/module effectiveness benchmark; documentation-range IPs only; not production zero-day evidence'
}, null, 2));
