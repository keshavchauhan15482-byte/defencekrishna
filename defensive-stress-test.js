// defensive-stress-test.js
// Automated Defensive Load & Resilience Benchmark for Krishna Defence System
const http = require('http');

const TOTAL_REQUESTS = 60;
const CONCURRENCY = 10;

const TEST_CASES = [
  { name: 'Standard Routine Query', path: '/products?category=electronics', method: 'GET', ip: '103.21.244.10' },
  { name: 'High-Velocity Rapid Probe', path: '/login', method: 'POST', body: JSON.stringify({ user: 'test', pass: 'probe' }), ip: '103.21.244.11' },
  { name: 'Oversized Parameter Test', path: '/products?q=' + 'A'.repeat(500), method: 'GET', ip: '103.21.244.12' },
  { name: 'Rapid Multi-Endpoint Sweep', path: '/checkout', method: 'POST', body: JSON.stringify({ item: 'test', count: 100 }), ip: '103.21.244.13' }
];

let completed = 0;
let blocked = 0;
let allowed = 0;
let errors = 0;
const startTime = Date.now();

function sendRequest(testCase, id) {
  return new Promise((resolve) => {
    const postData = testCase.body || '';
    const options = {
      hostname: '127.0.0.1',
      port: 8080,
      path: testCase.path,
      method: testCase.method,
      headers: {
        'Content-Type': 'application/json',
        'X-Forwarded-For': testCase.ip,
        'User-Agent': 'Krishna-Defensive-Benchmark/1.0',
        'Content-Length': Buffer.byteLength(postData)
      }
    };

    const req = http.request(options, (res) => {
      let data = '';
      res.on('data', (c) => data += c);
      res.on('end', () => {
        completed++;
        if (res.statusCode === 403 || res.statusCode === 429) {
          blocked++;
        } else if (res.statusCode >= 200 && res.statusCode < 400) {
          allowed++;
        }
        process.stdout.write(`\r[BENCHMARK] Progress: ${completed}/${TOTAL_REQUESTS} | Neutralized/Filtered: ${blocked} | Allowed: ${allowed}`);
        resolve();
      });
    });

    req.on('error', () => {
      errors++;
      completed++;
      resolve();
    });

    if (postData) req.write(postData);
    req.end();
  });
}

async function runBenchmark() {
  console.log('===============================================================');
  console.log('⚡ KRISHNA DEFENCE SYSTEM — HIGH-VOLUME RESILIENCE BENCHMARK');
  console.log(`🎯 Executing ${TOTAL_REQUESTS} concurrent requests across 4 operational profiles`);
  console.log('===============================================================\n');

  const queue = [];
  for (let i = 0; i < TOTAL_REQUESTS; i++) {
    const testCase = TEST_CASES[i % TEST_CASES.length];
    queue.push(() => sendRequest(testCase, i + 1));
  }

  // Execute with bounded concurrency pool
  const pool = [];
  for (let i = 0; i < CONCURRENCY; i++) {
    pool.push((async () => {
      while (queue.length > 0) {
        const task = queue.shift();
        if (task) await task();
      }
    })());
  }

  await Promise.all(pool);

  const durationMs = Date.now() - startTime;
  const reqPerSec = ((TOTAL_REQUESTS / durationMs) * 1000).toFixed(1);

  console.log('\n\n===============================================================');
  console.log('📊 BENCHMARK COMPLETE');
  console.log(`⏱️ Duration: ${durationMs}ms (${reqPerSec} req/sec)`);
  console.log(`🛡️ Filtered / Blocked: ${blocked}`);
  console.log(`✅ Allowed / Routine: ${allowed}`);
  console.log(`❌ Network Errors: ${errors}`);
  console.log('===============================================================\n');
}

runBenchmark();
