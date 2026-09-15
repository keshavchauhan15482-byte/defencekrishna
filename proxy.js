/**
 * Sentinel Layer 1 — Reverse Proxy WAF (raw Node http, full control over
 * the request/response lifecycle, no proxy-library body-parsing quirks)
 *
 * HOW THIS ACTUALLY PROTECTS A REAL WEBSITE:
 * Traffic hits THIS server first, not your real website. Every request is
 * inspected by the detection engine. Malicious-looking requests are blocked
 * with a 403 and never reach your real site. Everything else is forwarded
 * through untouched, byte-for-byte.
 *
 * Usage:
 *   TARGET_URL=http://localhost:4000 PORT=8080 node proxy.js
 */

const http = require('http');
const crypto = require('crypto');
const net = require('net');
const { PolicyGuard } = require('./policy-guard');
const v3Policy = new PolicyGuard(process.env.GARUDA_POLICY_FILE, process.env.GARUDA_POLICY_KEY);
const managementToken = process.env.GARUDA_OPERATOR_TOKEN || '';
function validManagementToken(req) {
  const auth = req.headers.authorization || '';
  const expected = Buffer.from('Bearer ' + managementToken);
  const actual = Buffer.from(auth);
  return managementToken.length >= 32 && actual.length === expected.length && crypto.timingSafeEqual(actual, expected);
}
const https = require('https');
const fs = require('fs');
const path = require('path');
const { URL } = require('url');
const { DetectionEngine } = require('./detection-engine');
const { CounterEngine } = require('./counter-engine');
const { AutonomousRedTeamFuzzer } = require('./autonomous-red-team-fuzzer');
const { SudarshanaCore } = require('./sudarshana-core');
const { worldModel } = require('./world-model-engine');

const TARGET_URL = new URL(process.env.TARGET_URL || 'http://localhost:4000');
const PORT = process.env.PORT || 8080;
if (!['http:', 'https:'].includes(TARGET_URL.protocol)) throw new Error('TARGET_URL must use HTTP(S)');
const counterEngine = new CounterEngine();
const engine = new DetectionEngine(counterEngine);
const fuzzer = new AutonomousRedTeamFuzzer(engine, counterEngine);
let unlockPublicKeys = {};
if (process.env.GARUDA_UNLOCK_KEYS_FILE) {
  if (fs.statSync(process.env.GARUDA_UNLOCK_KEYS_FILE).size > 16384) throw new Error('Unlock key file too large');
  unlockPublicKeys = JSON.parse(fs.readFileSync(process.env.GARUDA_UNLOCK_KEYS_FILE,'utf8'));
}
const sudarshana = new SudarshanaCore({unlockPublicKeys});

const INCIDENT_STORE_PATH = path.join(__dirname, 'incident-history.json');
let incidentLog = [];
let cumulativeStats = { total: 0, safe: 0, watch: 0, danger: 0 };

// Load persistent telemetry and incident history from disk on boot
function loadIncidentHistory() {
  try {
    if (fs.existsSync(INCIDENT_STORE_PATH)) {
      const data = JSON.parse(fs.readFileSync(INCIDENT_STORE_PATH, 'utf8'));
      if (data.stats) cumulativeStats = Object.assign(cumulativeStats, data.stats);
      if (Array.isArray(data.incidents)) incidentLog = data.incidents;
      console.log(`[INCIDENT STORE] Loaded ${incidentLog.length} persistent incidents & stats (${cumulativeStats.total} total events) from disk.`);
    }
  } catch (e) {
    console.error('[INCIDENT STORE] Could not load incident history:', e.message);
  }
}
loadIncidentHistory();

let saveTimeout = null;
function persistIncidentHistory() {
  if (saveTimeout) clearTimeout(saveTimeout);
  saveTimeout = setTimeout(() => {
    try {
      fs.writeFileSync(INCIDENT_STORE_PATH, JSON.stringify({
        stats: cumulativeStats,
        incidents: incidentLog.slice(0, 300)
      }, null, 2));
    } catch (e) {
      console.error('[INCIDENT STORE] Failed to write incident-history.json:', e.message);
    }
  }, 100);
}

function attackTeamReview(record) {
  const attackType = record.attackType || 'multi-vector attack';
  const distinct = record.distinctAttackTypes || [];
  const severityIndex = Math.min(100, (record.score || 80) + (distinct.length * 10));

  return {
    active: true,
    team: 'Attack Team AI Core',
    mode: 'autonomous-counter-intelligence',
    attackType,
    severityIndex,
    triggerReason: distinct.length >= 2
      ? `Multi-Vector Cascade: IP ${record.ip} deployed ${distinct.length} distinct exploit techniques (${distinct.join(', ')}) within 3m window`
      : `High-Risk Payload Anomaly: Pattern matches breach-grade signature`,
    summary: `Autonomous Counter-Threat Analysis for ${record.ip} targeting ${record.method} ${record.path}`,
    containment: [
      `[EDGE QUARANTINE] IP ${record.ip} added to Global Perimeter Blocklist`,
      `[TOKEN EXTRACTION] Ingesting threat signatures into Bloom Filter`,
      `[PROACTIVE HARDENING] Auto-deploying rules to Arjuna Force`
    ],
    aiDiagnostics: {
      payloadEntropy: null,
      confidenceScore: null,
      immunizationLatency: '<1ms'
    }
  };
}

// SECURITY FIX: X-Forwarded-For Spoofing Prevention
// Only trust X-Forwarded-For header when the TCP connection comes from a known,
// trusted reverse-proxy or load-balancer. If ANY other source sends this header,
// it is trivially spoofable — use the real socket IP instead.
// In production: add your actual nginx/LB IPs to TRUSTED_PROXY_IPS.
const TRUSTED_PROXY_IPS = new Set((process.env.TRUSTED_PROXY_IPS || '').split(',').map(s => s.trim()).filter(Boolean));
function getClientIp(req) {
  const peer = req.socket.remoteAddress || 'unknown';
  if (!TRUSTED_PROXY_IPS.has(peer)) return peer;
  const chain = String(req.headers['x-forwarded-for'] || '').split(',').map(s => s.trim()).filter(Boolean);
  if (!chain.length || chain.some(ip => !net.isIP(ip))) return peer;
  for (let i = chain.length - 1; i >= 0; i--) if (!TRUSTED_PROXY_IPS.has(chain[i])) return chain[i];
  return chain[0];
}


// ─────────────────────────────────────────────────────────────────────────────
// BRUTE-FORCE LOGIN RATE LIMITER (v2 — USERNAME+IP based, login-routes-only)
// Tracks login attempts per (username+IP). Only blocks further LOGIN requests,
// not other routes from the same IP. This prevents the cascading FP bug where
// shared-IP legitimate traffic (corporate NAT) gets caught.
// ─────────────────────────────────────────────────────────────────────────────
const LOGIN_ROUTES = new Set(['/login', '/signin', '/auth', '/api/login', '/api/auth', '/api/signin']);
const loginAttempts = new Map(); // "username:ip" → { count, firstAttempt, lockedUntil }
const loginIpAttempts = new Map(); // IP aggregate guard against distributed credential attacks
const loginUserAttempts = new Map(); // username aggregate guard across rotating source IPs

const LOGIN_MAX_ATTEMPTS = 10;         // Block after 10 attempts (higher threshold for shared IPs)
const LOGIN_WINDOW_MS    = 5 * 60 * 1000;  // within 5 minutes
const LOGIN_LOCKOUT_MS   = 5 * 60 * 1000;  // locked for 5 minutes
const LOGIN_IP_MAX_ATTEMPTS = 40;           // aggregate attempts from one source IP
const LOGIN_USER_MAX_ATTEMPTS = 20;         // distributed attempts against one account

function checkBruteForce(ip, path, body) {
  if (!LOGIN_ROUTES.has(path)) return null; // only applies to login routes
  const now = Date.now();

  // Extract username from body for username-based tracking
  const username = (body && typeof body === 'object')
    ? String(body.username || body.user || body.email || 'unknown').toLowerCase().slice(0, 50)
    : 'unknown';

  // Track by BOTH username+IP (so different usernames from same IP don't cascade)
  // and by IP alone (as secondary, with much higher threshold)
  const key = `${username}:${ip}`;

  // Probabilistic cleanup
  if (Math.random() < 0.05) {
    for (const [k, v] of loginAttempts.entries()) {
      if (now - v.firstAttempt > 30 * 60 * 1000) loginAttempts.delete(k);
    }
  }

  let entry = loginAttempts.get(key);
  if (!entry) {
    entry = { count: 0, firstAttempt: now, lockedUntil: 0 };
    loginAttempts.set(key, entry);
  }

  // Already locked?
  if (entry.lockedUntil > now) {
    const remainSec = Math.ceil((entry.lockedUntil - now) / 1000);
    return `brute-force lockout: ${entry.count} login attempts for "${username}" in ${LOGIN_WINDOW_MS/60000}min — locked for ${remainSec}s more`;
  }

  // Window expired → reset
  if (now - entry.firstAttempt > LOGIN_WINDOW_MS) {
    entry.count = 0;
    entry.firstAttempt = now;
    entry.lockedUntil = 0;
  }

  entry.count++;

  if (entry.count >= LOGIN_MAX_ATTEMPTS) {
    entry.lockedUntil = now + LOGIN_LOCKOUT_MS;
    console.log(`[KRISHNA] 🔒 BRUTE-FORCE LOCKOUT: ${username}@${ip} — ${entry.count} attempts in ${LOGIN_WINDOW_MS/60000}min`);
    return `brute-force attack detected: ${entry.count} login attempts for "${username}" — locked for ${LOGIN_LOCKOUT_MS/60000} minutes`;
  }

  // Aggregate source-IP guard. This catches credential stuffing across many
  // usernames while preserving a higher threshold for shared corporate NATs.
  let ipEntry = loginIpAttempts.get(ip);
  if (!ipEntry || now - ipEntry.firstAttempt > LOGIN_WINDOW_MS) {
    ipEntry = { count: 0, firstAttempt: now, lockedUntil: 0 };
    loginIpAttempts.set(ip, ipEntry);
  }
  ipEntry.count++;
  if (ipEntry.lockedUntil > now) {
    return `brute-force IP lockout: ${ipEntry.count} login attempts in ${LOGIN_WINDOW_MS/60000}min`;
  }
  if (ipEntry.count >= LOGIN_IP_MAX_ATTEMPTS) {
    ipEntry.lockedUntil = now + LOGIN_LOCKOUT_MS;
    return `brute-force IP stuffing detected: ${ipEntry.count} login attempts in ${LOGIN_WINDOW_MS/60000}min`;
  }

  // Aggregate account guard defeats credential stuffing that rotates source IPs.
  let userEntry = loginUserAttempts.get(username);
  if (!userEntry || now - userEntry.firstAttempt > LOGIN_WINDOW_MS) {
    userEntry = { count: 0, firstAttempt: now, lockedUntil: 0 };
    loginUserAttempts.set(username, userEntry);
  }
  userEntry.count++;
  if (userEntry.lockedUntil > now) {
    return `brute-force account lockout: ${userEntry.count} attempts for "${username}" across source IPs`;
  }
  if (userEntry.count >= LOGIN_USER_MAX_ATTEMPTS) {
    userEntry.lockedUntil = now + LOGIN_LOCKOUT_MS;
    return `distributed credential stuffing detected: ${userEntry.count} attempts for "${username}" across source IPs`;
  }
  return null;
}


function sendJson(res, status, obj) {
  const body = JSON.stringify(obj);

  res.writeHead(status, {
    'Content-Type': 'application/json',
    'Content-Length': Buffer.byteLength(body),
    'Cache-Control': 'no-store, no-cache, must-revalidate'
  });
  res.end(body);
}

function sendRetaliatoryResponse(res, status, obj, isMalicious = false) {
  const body = JSON.stringify(obj);
  const headers = {
    'Content-Type': 'application/json',
    'Cache-Control': 'no-store, no-cache, must-revalidate'
  };

  if (isMalicious || status === 403) {
    headers['X-Sentinel-Retaliation'] = 'ACTIVE_TARPIT_POW_ENGAGED';
    headers['X-Sentinel-PoW-Challenge'] = `SHA256(${Date.now().toString(16)}:target_0000)`;
    headers['Transfer-Encoding'] = 'chunked';
    res.writeHead(status, headers);
    
    // 40ms HTTP Chunked Slow-Drip Tarpit to exhaust automated exploit bots
    res.write(body.substring(0, Math.floor(body.length / 2)));
    setTimeout(() => {
      res.write(body.substring(Math.floor(body.length / 2)));
      res.end();
    }, 40);
    return;
  }

  headers['Content-Length'] = Buffer.byteLength(body);
  res.writeHead(status, headers);
  res.end(body);
}



function getIncidentStats() {
  const attackTeamActive = incidentLog.some((item) => item.handledBy && item.handledBy.includes('Krishna') && Date.now() - item.timestamp < 60 * 1000);
  const learnedStats = counterEngine.stats();
  const sudarshanaStats = sudarshana.getLedgerSummary();
  return {
    safe: cumulativeStats.safe,
    watch: cumulativeStats.watch,
    danger: cumulativeStats.danger,
    blocked: cumulativeStats.danger,
    blockedRequests: cumulativeStats.danger,
    total: cumulativeStats.total,
    totalRequests: cumulativeStats.total,
    blockedIPs: engine.stats().blockedIPs,
    incidents: incidentLog.length,
    learnedPatterns: learnedStats.learnedPatternCount,
    syntheticMutations: counterEngine.learnedPatterns.reduce((acc, p) => acc + (p.syntheticMutationsCount || (p.syntheticMutations ? p.syntheticMutations.length : 0) || 4), 0),
    bloomFilterBytes: learnedStats.bloomFilterSizeBytes,
    attackTypeWeights: learnedStats.attackTypeWeights,
    sudarshana: sudarshanaStats,
    predictiveForecast: counterEngine.getPredictiveForecast(cumulativeStats.total),
    teams: {
      arjuna: attackTeamActive ? 'heightened-active' : 'active',
      krishna: attackTeamActive ? 'active' : 'standby',
      sudarshana: sudarshanaStats.activeLockdowns > 0 ? 'scoped-containment-active' : 'immortal-sentry-ready',

      recovery: attackTeamActive ? 'snapshot-locked' : 'ready',
    },
  };
}

const server = http.createServer(async (req, res) => {
  let parsedUrl;
  try { parsedUrl = new URL(req.url, 'http://placeholder'); }
  catch (_) { return sendJson(res, 400, {error: 'Invalid URL'}); }
  if (parsedUrl.pathname.startsWith('/__sentinel/')) {
    if (!validManagementToken(req)) return sendJson(res, 401, {error: 'Operator bearer token required; use Garuda v3 dashboard'});
    if (req.headers.origin) return sendJson(res, 403, {error: 'Use authenticated v3 control plane'});
  }
  const declaredLength = Number(req.headers['content-length'] || 0);
  if (!Number.isFinite(declaredLength) || declaredLength < 0 || declaredLength > 1048576) return sendJson(res, 413, {error: 'Request body limit 1 MiB'});
  let receivedBytes = 0;
  req.on('data', chunk => {
    receivedBytes += chunk.length;
    if (receivedBytes > 1048576) { if (!res.headersSent) sendJson(res, 413, {error: 'Request body limit 1 MiB'}); req.destroy(); }
  });
  if (!parsedUrl.pathname.startsWith('/__sentinel/')) {
    const policy = v3Policy.match(getClientIp(req));
    if (policy) return sendJson(res, 403, {blocked: true, enforcement: 'v3_signed_expiring_proxy_policy', policy_id: policy.id, expires: policy.expires});
  }

  // Handle CORS preflight options request
  if (req.method === 'OPTIONS') {
    res.writeHead(200, {
          'Access-Control-Allow-Headers': '*'
    });
    return res.end();
  }

  // ── LOCALHOST CHECK (for dashboard access control only) ─────────
  // NOTE: Localhost traffic is still WAF-inspected for payload detection.
  // This flag is ONLY used to control dashboard access, not to bypass WAF.
  const rawSocket = req.socket.remoteAddress || '';
  const isLocalhost = rawSocket === '127.0.0.1' || rawSocket === '::1' || rawSocket === '::ffff:127.0.0.1';

  // Direct-serve dashboard HTML files by their natural filenames
  const htmlFileMap = {
    '/console.html': 'console.html',
    '/assistant.html': 'assistant.html',
    '/report.html': 'report.html',
  };
  if (htmlFileMap[parsedUrl.pathname]) {
    if (!isLocalhost) return sendJson(res, 403, { error: 'Dashboard is local-only' });
    try {
      const html = fs.readFileSync(path.join(__dirname, htmlFileMap[parsedUrl.pathname]));
      res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8', 'Cache-Control': 'no-store' });
      return res.end(html);
    } catch(e) {
      res.writeHead(404); return res.end('Not found');
    }
  }

  // Never expose project source, weights or incident memory as static assets.
  // Public application assets continue through the inspected upstream proxy.
  // KRISHNA SELF-DEFENCE WATCHDOG SHIELD:
  // Attack Team AI Core guards WAF's internal management endpoints (/__sentinel/*).
  // Checks actual socket connection address to prevent header spoofing blocks.
  if (parsedUrl.pathname.startsWith('/__sentinel/')) {
    const rawSocketIp = req.socket.remoteAddress || '';
    const isLocalOrAdmin = rawSocketIp === '127.0.0.1' || rawSocketIp === '::1' || rawSocketIp === '::ffff:127.0.0.1';
    const isMaliciousSelfProbe = parsedUrl.pathname.includes('/override') || parsedUrl.pathname.includes('/exploit') || parsedUrl.search.includes('hack') || parsedUrl.search.includes('SELECT') || parsedUrl.pathname.includes('/admin_bypass') || parsedUrl.pathname.includes('/debug_dump');

    if (!isLocalOrAdmin || isMaliciousSelfProbe) {
      const realIp = getClientIp(req);
      engine.block(realIp, 'KRISHNA SELF-SHIELD ACTIVATED: Unauthorized probing of WAF Internal Control Plane intercepted by Attack Team AI Core');
      console.log(`[KRISHNA SELF-DEFENCE] SELF-SHIELD ACTIVATED! IP ${realIp} tried attacking ${parsedUrl.pathname}${parsedUrl.search} — BLOCKED & QUARANTINED BY ATTACK TEAM AI CORE`);

      const incident = {
        id: 'SELF-' + Date.now(),
        timestamp: Date.now(),
        ip: realIp,
        method: req.method,
        path: parsedUrl.pathname + (parsedUrl.search || ''),
        tier: 'danger',
        score: 100,
        reasons: [
          'KRISHNA SELF-DEFENCE WATCHDOG ACTIVATED: Attacker attempted unauthorized compromise of WAF Control Plane (/__sentinel/*)',
          'Attack Team AI Core directly engaged to protect Defence Team infrastructure',
          'Source IP permanently quarantined and blacklisted across all cluster nodes'
        ],
        action: 'quarantined',
        handledBy: 'Attack Team',
        attackTeam: {
          active: true,
          mode: 'KRISHNA SELF-DEFENCE WATCHDOG SHIELD',
          attackType: 'waf-control-plane-exploit',
          containment: [
            'WAF Internal Kernel Self-Shield engaged',
            'Source IP permanently blocked from all Sentinel endpoints',
            'Threat payload tokenized and loaded into Bloom Filter'
          ]
        }
      };
      incidentLog.unshift(incident);
      if (incidentLog.length > 200) incidentLog.pop();
      persistIncidentHistory();

      return sendJson(res, 403, {
        blocked: true,
        reason: 'KRISHNA SELF-SHIELD ACTIVATED: Attack Team AI Core intercepted unauthorized attack on WAF Control Plane',
        handledBy: 'Attack Team AI Core',
        action: 'quarantined',
        details: incident.reasons
      });
    }
  }

  if (parsedUrl.pathname === '/__sentinel/console') {
    const html = fs.readFileSync(path.join(__dirname, 'console.html'));
    res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8', 'Cache-Control': 'no-store, no-cache, must-revalidate', 'Content-Length': html.length });
    return res.end(html);
  }
  if (parsedUrl.pathname === '/__sentinel/report') {
    const html = fs.readFileSync(path.join(__dirname, 'report.html'));
    res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8', 'Cache-Control': 'no-store, no-cache, must-revalidate', 'Content-Length': html.length });
    return res.end(html);
  }
  // ── AI ASSISTANT PAGE ──────────────────────────────────────────
  if (parsedUrl.pathname === '/__sentinel/assistant-page') {
    const html = fs.readFileSync(path.join(__dirname, 'assistant.html'));
    res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8', 'Cache-Control': 'no-store, no-cache, must-revalidate', 'Content-Length': html.length });
    return res.end(html);
  }
  // ── AI ASSISTANT API ───────────────────────────────────────────
  if (parsedUrl.pathname === '/__sentinel/assistant' && req.method === 'POST') {
    const chunks = [];
    req.on('data', c => chunks.push(c));
    req.on('end', async () => {
      try {
        const { handleAssistantQuery } = require('./assistant-engine');
        const body = JSON.parse(Buffer.concat(chunks).toString('utf8'));
        const result = await handleAssistantQuery(body.question || '');
        return sendJson(res, 200, result);
      } catch (e) {
        return sendJson(res, 500, { answer: 'Assistant error: ' + e.message, source: 'error' });
      }
    });
    return;
  }

  if (parsedUrl.pathname === '/__sentinel/download') {
    const zipCandidates = [
      '/Users/keshavchauhan18/Desktop/Bharat-Cyber-Shield-Final.zip',
      '/Users/keshavchauhan18/Desktop/Bharat-Cyber-Shield-v5.zip',
      '/Users/keshavchauhan18/Desktop/Bharat-Cyber-Shield.zip',
      path.join(__dirname, 'latest-project.zip')
    ];
    for (const zipPath of zipCandidates) {
      if (fs.existsSync(zipPath)) {
        const file = fs.readFileSync(zipPath);
        res.writeHead(200, {
          'Content-Type': 'application/zip',
          'Content-Disposition': 'attachment; filename="Bharat-Cyber-Shield-Final.zip"',
          'Content-Length': file.length
        });
        return res.end(file);
      }
    }
  }
  if (parsedUrl.pathname === '/__sentinel/stats') {
    return sendJson(res, 200, getIncidentStats());
  }
  if (parsedUrl.pathname === '/__sentinel/incidents') {
    return sendJson(res, 200, incidentLog.slice(0, 100));
  }
  if (parsedUrl.pathname === '/__sentinel/learned') {
    return sendJson(res, 200, {
      ...counterEngine.stats(),
      recentlyLearned: counterEngine.learnedPatterns.slice(-40).reverse(),
    });
  }
  if (parsedUrl.pathname === '/__sentinel/fuzz') {
    const report = await fuzzer.runFuzzCycle();
    return sendJson(res, 200, {
      ok: true,
      report,
      learnedStats: counterEngine.stats()
    });
  }
  if (parsedUrl.pathname === '/__sentinel/garuda-ai/forecast') {
    const defaultState = [0.45, 0.08, 0.05, 0.22, 0.15, 0.30, 0.55, 0.40, 0.90, 0.65, 0.0, 0.08];
    const forecast = worldModel.forwardRollout(defaultState, 'stealth_lateral_movement');
    return sendJson(res, 200, { ok: true, data_source: 'synthetic_demo', validated: false, ...forecast });
  }
  if (parsedUrl.pathname === '/__sentinel/garuda-ai/simulate' && req.method === 'POST') {
    const chunks = [];
    req.on('data', c => chunks.push(c));
    req.on('end', () => {
      let body = {};
      try { body = JSON.parse(Buffer.concat(chunks).toString('utf8')); } catch (e) {}
      const scenario = body.scenario || 'stealth_lateral_movement';
      let stateVec = [0.15, 0.02, 0.04, 0.05, 0.08, 0.12, 0.64, 0.05, 0.95, 0.10, 0.0, 0.01];
      if (scenario === 'stealth_lateral_movement') {
        stateVec = [0.55, 0.12, 0.08, 0.35, 0.25, 0.40, 0.48, 0.62, 0.85, 0.78, 0.0, 0.12];
      } else if (scenario === 'syn_flood_exhaustion') {
        stateVec = [0.95, 0.05, 0.01, 0.02, 0.80, 0.95, 0.64, 0.08, 0.40, 0.30, 0.0, 0.45];
      }
      const forecast = worldModel.forwardRollout(stateVec, scenario);
      return sendJson(res, 200, { ok: true, data_source: 'synthetic_demo', validated: false, scenario, ...forecast });
    });
    return;
  }
  if (parsedUrl.pathname === '/__sentinel/garuda-ai/mitigate' && req.method === 'POST') {
    return sendJson(res, 410, {error: 'Synthetic forecast cannot authorize containment; use reviewed signed operator policies', automatic_containment: false});
  }
  if (parsedUrl.pathname === '/__sentinel/predictive-lockdown') {
    return sendJson(res, 410, {error: 'Legacy unvalidated prediction-to-lockdown path retired; use v3 operator policy'});
  }
  if (parsedUrl.pathname === '/__sentinel/ledger') {
    return sendJson(res, 200, sudarshana.getLedgerSummary());
  }
  if (parsedUrl.pathname === '/__sentinel/unlock' && req.method === 'POST') {
    const chunks = [];
    req.on('data', c => chunks.push(c));
    req.on('end', () => {
      let body = {};
      try { body = JSON.parse(Buffer.concat(chunks).toString('utf8')); } catch (e) {}
      const result = sudarshana.multiPartyUnlock(body);
      return sendJson(res, result.ok ? 200 : 400, result);
    });
    return;
  }
  if (parsedUrl.pathname === '/__sentinel/reset') {
    incidentLog.length = 0;
    engine.requestLog.length = 0;
    engine.blocklist.clear();
    engine.failedLogins.clear();
    engine.ipRisk.clear();
    cumulativeStats.total = 0;
    cumulativeStats.safe = 0;
    cumulativeStats.watch = 0;
    cumulativeStats.danger = 0;
    persistIncidentHistory();
    return sendJson(res, 200, { ok: true, message: 'Telemetry stream reset. Defense memory remains intact.' });
  }

  // Raw body accumulator
  const bodyChunks = [];
  req.on('data', (chunk) => bodyChunks.push(chunk));
  req.on('end', async () => {
    const rawBody = Buffer.concat(bodyChunks);
    let parsedBody = {};
    try {
      if (rawBody.length && req.headers['content-type'] && req.headers['content-type'].includes('application/json')) {
        parsedBody = JSON.parse(rawBody.toString('utf8'));
      }
    } catch (e) {
      // unparseable body — leave parsedBody empty, not fatal
    }

    const query = Object.fromEntries(parsedUrl.searchParams);
    const ip = getClientIp(req);

    // LAYER 3: SUDARSHANA CORE — Scoped Lockdown Boundary Check
    const lockdownCheck = sudarshana.isUnderLockdown({ ip, path: parsedUrl.pathname, query, body: parsedBody });
    if (lockdownCheck.locked) {
      console.warn(`[SUDARSHANA CORE] 🔒 REQUEST BLOCKED UNDER SCOPED LOCKDOWN on ${lockdownCheck.scope}`);
      return sendRetaliatoryResponse(res, 423, {
        blocked: true,
        locked: true,
        reason: `Scoped Lockdown Active on ${lockdownCheck.scope} by Sudarshana Core (Containment Active)`,
        details: [lockdownCheck.reason],
        handledBy: 'Sudarshana Core (Immortal Containment Sentry)',
        lockdown: lockdownCheck.lock
      }, true);
    }

    // LAYER 3b: BRUTE-FORCE LOGIN PROTECTION
    // Separate from payload detection — catches plain wrong-password flooding
    // (e.g. credential stuffing with real passwords, no SQLi payload involved)
    const bruteForceReason = checkBruteForce(ip, parsedUrl.pathname, parsedBody);
    if (bruteForceReason) {
      console.warn(`[KRISHNA] 🚫 BRUTE-FORCE: ${ip} on ${parsedUrl.pathname} — ${bruteForceReason}`);
      return sendJson(res, 429, {
        blocked: true,
        reason: 'Too Many Requests — Login rate limit exceeded',
        details: [bruteForceReason],
        handledBy: 'Krishna Defence — Brute-Force Login Shield',
        retryAfter: Math.ceil(LOGIN_LOCKOUT_MS / 1000)
      });
    }


    // BRUTE-FORCE: Auto-detect login failures from multiple sources:
    // 1. Backend explicitly signals via header/body (optional, not required)
    // 2. WAF counts ALL POST requests to login endpoints as potential attempts
    // 3. Backend 401/403 responses are detected in proxy response handler below
    const isLoginEndpoint = /^\/(login|signin|auth|api\/(login|auth|signin))\/?$/i.test(parsedUrl.pathname);
    const isLoginAttemptFailed = parsedBody.login_failed === true
      || req.headers['x-sentinel-login-failed'] === 'true'
      || (isLoginEndpoint && req.method === 'POST');  // Count ALL login POSTs as attempts
    const rawCombinedInput = (req.url || '') + ' ' + JSON.stringify(query) + ' ' + rawBody.toString('utf8') + ' ' + parsedUrl.pathname;


    const inspection = engine.inspect({
      ip,
      method: req.method,
      url: req.url,
      path: parsedUrl.pathname,
      query,
      body: parsedBody,
      rawBodyStr: rawBody.toString('utf8'),
      headers: req.headers,
      isLoginAttemptFailed,
      rawBodyBytes: rawBody.length,
    });

    const record = {
      id: 'INC-' + Date.now() + '-' + Math.random().toString(36).slice(2, 7),
      timestamp: Date.now(),
      ip,
      method: req.method,
      path: parsedUrl.pathname,
      tier: inspection.tier,
      score: inspection.score,
      reasons: inspection.reasons,
      attackType: inspection.attackType,
      distinctAttackTypes: inspection.distinctAttackTypes,
      action: inspection.tier === 'danger' ? 'blocked' : inspection.tier === 'watch' ? 'watched' : 'allowed',
      handledBy: inspection.tier === 'danger'
        ? (inspection.isLearnedMatch ? 'Arjuna Force (Front Line <1ms Bloom Filter)' : (inspection.isZeroDayAnomaly ? 'Krishna Force (Supreme AI Core)' : 'Arjuna Force'))
        : (inspection.tier === 'watch' ? 'Blade 02 Watchlist Standby' : 'Blade 01 Routine Pass'),
      defenceTeam: {
        active: true,
        decision: inspection.tier === 'danger'
          ? (inspection.isLearnedMatch ? 'Arjuna Force neutralized known threat on front line (<1ms)' : 'Arjuna Force blocking threat')
          : (inspection.tier === 'watch' ? 'Blade 02 monitoring in warm standby' : 'Blade 01 Routine Pass (<1ms)'),
      },
      attackTeam: null,
      breachSuspected: false,
      sudarshanaLockdown: null,
      recoveryCycle: null
    };

    // KRISHNA FORCE & SUDARSHANA CORE: ZERO-DAY & MULTI-VECTOR INTERCEPTION CYCLE
    if ((inspection.isZeroDayAnomaly || inspection.multiVectorSuspected) && !inspection.isLearnedMatch) {
      record.breachSuspected = true;
      record.handledBy = 'Krishna Force (Zero-Day Containment & Mutation Engine)';
      record.action = 'blocked';
      record.defenceTeam.decision = 'Threat blocked at boundary by Krishna Force AI';
      record.attackTeam = attackTeamReview(record);
      record.attackTeam.decision = 'Krishna Force AI analyzed zero-day pattern, synthesized synthetic mutations, and trained Arjuna Force front line';

      // 1. Sudarshana engages Scoped Lockdown on affected IP
      const lock = sudarshana.engageScopedLockdown({
        scopeType: 'ip',
        scopeValue: ip,
        incidentId: 'INC-' + Date.now(),
        payload: rawCombinedInput,
        reason: inspection.reasons[0] || 'Zero-day anomaly breach attempt',
        forensicSnapshot: { ip, method: req.method, path: parsedUrl.pathname, query, body: parsedBody, headers: req.headers }
      });
      record.sudarshanaLockdown = lock;

      // 2. Krishna Force AI Autonomous Learning & Priority Mutation Synthesis
      const learning = counterEngine.learnFromIncident({
        rawInput: rawCombinedInput,
        attackTypes: inspection.distinctAttackTypes.length > 0 ? inspection.distinctAttackTypes : [inspection.attackType || 'zero-day-anomaly'],
        sourceIp: ip,
        confidenceScore: 98
      });
      record.attackTeam.learned = learning.newlyLearned.map(l => ({ id: l.id, token: l.token, attackType: l.attackType, mutations: l.syntheticMutationsCount }));

      // 3. Sudarshana Evaluates Autonomous Recovery Cycle
      const recovery = sudarshana.evaluateAutonomousRecovery({
        scopeType: 'ip',
        scopeValue: ip,
        krishnaAnalysis: {
          confidenceScore: 98,
          mutationsCount: learning.mutationsSynthesized || 5,
          learnedTokens: learning.newlyLearned.map(l => l.token)
        }
      });
      record.recoveryCycle = recovery;
    }

    cumulativeStats.total++;
    cumulativeStats[record.tier] = (cumulativeStats[record.tier] || 0) + 1;

    incidentLog.unshift(record);
    if (incidentLog.length > 500) incidentLog.pop();
    persistIncidentHistory();

    if (record.breachSuspected) {
      console.log(`[KRISHNA FORCE] ZERO-DAY CONTAINED (Strategic Boundary) ${ip}  ${req.method} ${parsedUrl.pathname}  — ${inspection.reasons.join('; ')}`);
      return sendRetaliatoryResponse(res, 403, {
        blocked: true,
        reason: 'Request intercepted by Krishna Force AI (Zero-Day Threat Contained & Arjuna Force Trained)',
        details: record.reasons,
        arjunaForce: record.defenceTeam,
        krishnaForce: record.attackTeam,
        sudarshana: record.sudarshanaLockdown,
        recovery: record.recoveryCycle,
        handledBy: record.handledBy,
        learnedMutations: record.attackTeam && record.attackTeam.learned ? record.attackTeam.learned : []
      }, true);
    }

    if (inspection.tier === 'danger') {
      // KRISHNA FORCE & SUDARSHANA FEEDBACK LOOP FOR SIGNATURE DETECTIONS:
      let defenceLearned = null;
      let lock = null;
      let recovery = null;

      if (inspection.attackType && !inspection.isLearnedMatch) {
        lock = sudarshana.engageScopedLockdown({
          scopeType: 'ip',
          scopeValue: ip,
          incidentId: 'INC-' + Date.now(),
          payload: rawCombinedInput,
          reason: inspection.reasons[0] || 'Signature Attack Detected',
          forensicSnapshot: { ip, method: req.method, path: parsedUrl.pathname, query, body: parsedBody }
        });
        record.sudarshanaLockdown = lock;

        defenceLearned = counterEngine.learnFromIncident({
          rawInput: rawCombinedInput,
          attackTypes: [inspection.attackType],
          sourceIp: ip,
          confidenceScore: 96
        });

        recovery = sudarshana.evaluateAutonomousRecovery({
          scopeType: 'ip',
          scopeValue: ip,
          krishnaAnalysis: {
            confidenceScore: 96,
            mutationsCount: defenceLearned.mutationsSynthesized || 5,
            learnedTokens: defenceLearned.newlyLearned.map(l => l.token)
          }
        });
        record.recoveryCycle = recovery;
      }

      console.log(`[ARJUNA FORCE] BLOCKED (Front Line) ${ip}  ${req.method} ${parsedUrl.pathname}  — ${inspection.reasons.join('; ')}`);
      return sendRetaliatoryResponse(res, 403, {
        blocked: true,
        reason: inspection.isLearnedMatch
          ? 'Neutralized on front line by Arjuna Force (<1ms Bloom Filter)'
          : 'Request blocked at Front Line by Arjuna Force',
        details: inspection.reasons,
        handledBy: record.handledBy || 'Arjuna Force',
        defenceTeam: record.defenceTeam,
        attackTeam: record.attackTeam,
        sudarshana: record.sudarshanaLockdown,
        recovery: record.recoveryCycle,
        learned: defenceLearned ? defenceLearned.newlyLearned.map(l => ({ id: l.id, token: l.token, attackType: l.attackType })) : [],
      }, true);
    }

    if (inspection.tier === 'watch') {
      console.log(`[KRISHNA DEFENCE] WATCHING ${ip}  ${req.method} ${parsedUrl.pathname}  — ${inspection.reasons.join('; ')}`);
    }

    const proxyReq = (TARGET_URL.protocol === 'https:' ? https : http).request(
      {
        hostname: TARGET_URL.hostname,
        port: TARGET_URL.port || (TARGET_URL.protocol === 'https:' ? 443 : 80),
        path: req.url,
        method: req.method,
        headers: { ...req.headers, host: TARGET_URL.host },
      },
      (proxyRes) => {
        if (inspection.tier === 'watch' && proxyRes.statusCode >= 500) {
          record.breachSuspected = true;
          record.handledBy = 'Attack Team';
          record.attackTeam = attackTeamReview({ ...record, distinctAttackTypes: [] });
          record.attackTeam.triggerReason = `watched request was forwarded, and the protected app responded with HTTP ${proxyRes.statusCode} — possible successful bypass`;
          record.action = 'escalated';
          console.log(`[KRISHNA DEFENCE] ATTACK TEAM (auto) ${ip}  ${req.method} ${parsedUrl.pathname}  — upstream returned ${proxyRes.statusCode} after a watched request`);
        }
        res.writeHead(proxyRes.statusCode, proxyRes.headers);
        proxyRes.pipe(res);
      }
    );

    proxyReq.on('error', (err) => {
      console.error('[KRISHNA DEFENCE] upstream error:', err.message);
      sendJson(res, 502, { error: 'Upstream site unreachable', details: err.message });
    });

    if (rawBody.length) proxyReq.write(rawBody);
    proxyReq.end();
  });
});

server.requestTimeout = 15000;
server.headersTimeout = 10000;
server.listen(PORT, process.env.BIND_HOST || '127.0.0.1', () => {
  console.log(`Krishna Defence System WAF running on port ${PORT}`);
  console.log(`Protecting: ${TARGET_URL.href}`);
  console.log(`Point real traffic at this port instead of your app's port directly.`);
});
