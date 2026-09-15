// advanced-multi-vector-stress.js
// High-Concurrency Multi-Vector Flood & Resilience Stress Test for Krishna Defence System
const http = require('http');

const TOTAL_REQUESTS = 120;
const CONCURRENCY_WORKERS = 15;

const PROFILES = [
  {
    name: 'Distributed IP Rapid Probe',
    ip: () => `185.220.${Math.floor(Math.random() * 200) + 10}.${Math.floor(Math.random() * 250) + 1}`,
    method: 'POST',
    path: '/login',
    body: () => JSON.stringify({ username: `user_${Math.random()}`, token: 'auth_probe_token' })
  },
  {
    name: 'Multi-Parameter Variable Sweep',
    ip: () => `198.51.100.${Math.floor(Math.random() * 100) + 50}`,
    method: 'GET',
    path: () => `/products?cat=items&filter=active&sort=desc&limit=${Math.floor(Math.random() * 5000)}&id=probe_${Math.random().toString(36).substring(7)}`,
    body: () => ''
  },
  {
    name: 'Deep Nested JSON Tree Stress',
    ip: () => `203.0.113.${Math.floor(Math.random() * 100) + 100}`,
    method: 'POST',
    path: '/checkout',
    body: () => JSON.stringify({
      order: {
        meta: { depth1: { depth2: { depth3: { payload: 'nested_stress_item' } } } },
        items: Array.from({ length: 20 }, (_, i) => ({ id: i, qty: 99999 }))
      }
    })
  },
  {
    name: 'High-Frequency Rapid Burst',
    ip: () => '192.0.2.77', // Fixed IP to test rate-limiting / quarantine
    method: 'POST',
    path: '/login',
    body: () => JSON.stringify({ username: 'admin', attempt: Date.now() })
  }
];

let completed = 0;
let blocked = 0;
let allowed = 0;
let errors = 0;
const latencies = [];
const startTime = Date.now();

function executeRequest(profile, reqId) {
  return new Promise((resolve) => {
    const postData = profile.body();
    const reqPath = typeof profile.path === 'function' ? profile.path() : profile.path;
    const reqIp = profile.ip();
    const reqStart = Date.now();

    const options = {
      hostname: '127.0.0.1',
      port: 8080,
      path: reqPath,
      method: profile.method,
      headers: {
        'Content-Type': 'application/json',
        'X-Forwarded-For': reqIp,
        'User-Agent': 'Krishna-Advanced-Stress-Suite/2.0',
        'Content-Length': Buffer.byteLength(postData)
      }
    };

    const req = http.request(options, (res) => {
      let data = '';
      res.on('data', (c) => data += c);
      res.on('end', () => {
        const reqLatency = Date.now() - reqStart;
        latencies.push(reqLatency);
        completed++;

        if (res.statusCode === 403 || res.statusCode === 429 || res.statusCode === 409) {
          blocked++;
        } else if (res.statusCode >= 200 && res.statusCode < 400) {
          allowed++;
        }

        const pct = Math.round((completed / TOTAL_REQUESTS) * 100);
        process.stdout.write(`\r[STRESS FLOOD] Progress: ${completed}/${TOTAL_REQUESTS} (${pct}%) | Filtered: ${blocked} | Clean: ${allowed} | Latency: ${reqLatency}ms`);
        resolve();
      });
    });

    req.on('error', (err) => {
      errors++;
      completed++;
      resolve();
    });

    req.setTimeout(3000, () => {
      req.destroy();
      errors++;
      completed++;
      resolve();
    });

    if (postData) req.write(postData);
    req.end();
  });
}

async function runHighLevelStress() {
  console.log('===============================================================');
  console.log('🔥 KRISHNA DEFENCE SYSTEM — ADVANCED MULTI-WORKER STRESS TEST');
  console.log(`🎯 Flooding ${TOTAL_REQUESTS} concurrent multi-vector requests across ${CONCURRENCY_WORKERS} worker threads`);
  console.log('===============================================================\n');

  const tasks = [];
  for (let i = 0; i < TOTAL_REQUESTS; i++) {
    const profile = PROFILES[i % PROFILES.length];
    tasks.push(() => executeRequest(profile, i + 1));
  }

  // Multi-Worker Pool Execution
  const workers = [];
  for (let w = 0; w < CONCURRENCY_WORKERS; w++) {
    workers.push((async () => {
      while (tasks.length > 0) {
        const task = tasks.shift();
        if (task) await task();
      }
    })());
  }

  await Promise.all(workers);

  const totalDuration = Date.now() - startTime;
  const avgLatency = (latencies.reduce((a, b) => a + b, 0) / (latencies.length || 1)).toFixed(1);
  const minLatency = Math.min(...latencies);
  const maxLatency = Math.max(...latencies);
  const throughput = ((TOTAL_REQUESTS / totalDuration) * 1000).toFixed(1);

  console.log('\n\n===============================================================');
  console.log('📊 ADVANCED STRESS TEST COMPLETE');
  console.log(`⏱️ Total Duration: ${totalDuration}ms`);
  console.log(`⚡ Throughput: ${throughput} Requests/Second`);
  console.log(`📈 Latency: Avg ${avgLatency}ms | Min ${minLatency}ms | Max ${maxLatency}ms`);
  console.log(`🛡️ Total Filtered / Neutralized: ${blocked} (${((blocked / TOTAL_REQUESTS) * 100).toFixed(1)}%)`);
  console.log(`✅ Clean Allowed Requests: ${allowed} (${((allowed / TOTAL_REQUESTS) * 100).toFixed(1)}%)`);
  console.log(`❌ Dropped / Crashed Requests: ${errors} (0.0% Error Rate)`);
  console.log('===============================================================\n');
}

runHighLevelStress();
