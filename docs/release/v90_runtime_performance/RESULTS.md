# V90 — Live-Compatible Runtime Performance

**Authoritative GitHub Actions run:** `35564831357`  
**Job:** `106224480471`  
**Artifact:** `v90-live-runtime-performance-evidence` (`10624335094`)  
**Artifact ZIP SHA256:** `ac9b52b5c925c2d14b682b5db8191f8b39b93942893671265077aedc77a00077`  
**Runtime checkpoint SHA256:** `90a9adb03faf93a77697e3eba123bd8dffe5be72f716b4b3419deedb3eaa4`

## Claim boundary

These are measured **in-process lab runtime** numbers on a GitHub-hosted Ubuntu CPU runner for the checkpoint actually compatible with the localhost graph inference service. They are not a customer production SLA, do not include HTTP/network transport overhead, and are not latency measurements for offline V70/V88/V89 experimental models.

The benchmark uses sequential single-thread requests after warm-up. Forecast-only timing excludes explanation. Explanation timing includes the runtime's gradient×input attribution path. An incompatible host-mode replay is reported as skipped rather than silently coerced into the graph schema.

## Measured results

| Replay | Active nodes | Mode | Mean | p50 | p95 | p99 | Throughput from mean |
|---|---:|---|---:|---:|---:|---:|---:|
| `replay.json` | 2 | Forecast only | **2.862 ms** | 2.825 ms | **2.922 ms** | 3.597 ms | **349.39/s** |
| `replay.json` | 2 | Forecast + explanation | **6.249 ms** | 6.162 ms | 6.619 ms | 7.699 ms | **160.01/s** |
| `alert_replay.json` | 3 | Forecast only | **3.012 ms** | 2.858 ms | **3.076 ms** | 5.474 ms | **332.02/s** |
| `alert_replay.json` | 3 | Forecast + explanation | **6.170 ms** | 6.066 ms | 6.366 ms | 7.535 ms | **162.08/s** |

Service initialization: **21.43 ms**.  
Maximum process RSS after benchmark: **44.99 MiB**.

`host_replay.json` was not benchmarked because its payload mode is `host` while the measured runtime bundle declares `graph`; the service correctly rejected the schema/mode mismatch.

## What this supports

- The current compatible graph runtime performs forecast inference in roughly **3 ms mean / 3.1 ms p95** on the measured CPU environment.
- Sequential in-process throughput is roughly **332–349 forecast calls/s** for the measured replay payloads.
- Prediction-specific gradient×input explanation raises mean inference time to roughly **6.2 ms** in this benchmark.
- Memory footprint after the benchmark remained about **45 MiB RSS**.

## What this does not support

- It is not an HTTP end-to-end or packet-ingestion latency SLA.
- It is not a multi-tenant load test.
- It is not a customer/enterprise production benchmark.
- It does not imply the offline experimental forecasting/progression checkpoints share this latency.
