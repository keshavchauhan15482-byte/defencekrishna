"""V90 reproducible latency/resource benchmark for the live compatible Garuda runtime.

This measures the checkpoint actually loaded by the localhost inference service. It does
not pretend that offline V70/V88/V89 experimental models are drop-in compatible with the
10-second graph schema. Numbers are measured in-process on the GitHub Actions CPU and
reported separately for forecast-only and explanation-enabled inference. Replay payloads
that target a different graph mode/schema are reported as skipped rather than weakening
or crashing the compatible-runtime benchmark.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import platform
import resource
import time
from pathlib import Path

import numpy as np

from .inference import ForecastService


def sha256(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for block in iter(lambda: f.read(1024 * 1024), b""):
            h.update(block)
    return h.hexdigest()


def percentiles_ms(values):
    a = np.asarray(values, dtype=float) * 1000.0
    return {
        "n": int(len(a)),
        "mean_ms": float(a.mean()),
        "median_ms": float(np.median(a)),
        "p50_ms": float(np.percentile(a, 50)),
        "p95_ms": float(np.percentile(a, 95)),
        "p99_ms": float(np.percentile(a, 99)),
        "min_ms": float(a.min()),
        "max_ms": float(a.max()),
        "single_thread_throughput_per_second_from_mean": float(1000.0 / a.mean()),
    }


def benchmark(service, payload, repeats, warmup, explain):
    for _ in range(warmup):
        service.predict(payload, explain=explain)
    values = []
    for _ in range(repeats):
        t0 = time.perf_counter()
        service.predict(payload, explain=explain)
        values.append(time.perf_counter() - t0)
    return percentiles_ms(values)


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--artifacts", default="garuda_v3/artifacts/residual_run")
    p.add_argument("--output", required=True)
    p.add_argument("--forecast-repeats", type=int, default=300)
    p.add_argument("--explain-repeats", type=int, default=60)
    args = p.parse_args()

    folder = Path(args.artifacts)
    out = Path(args.output)
    if out.exists():
        p.error("Output exists; V90 performance evidence is immutable")
    out.mkdir(parents=True)

    t0 = time.perf_counter()
    service = ForecastService(folder)
    init_seconds = time.perf_counter() - t0

    scenarios = []
    skipped = []
    for name in ("replay.json", "alert_replay.json", "host_replay.json"):
        path = folder / name
        if not path.exists():
            skipped.append({"scenario": name, "reason": "replay_file_missing"})
            continue
        payload = json.loads(path.read_text())
        try:
            service.validate(payload)
        except ValueError as exc:
            skipped.append({
                "scenario": name,
                "payload_bytes": int(path.stat().st_size),
                "payload_mode": payload.get("mode"),
                "runtime_mode": service.meta.get("mode"),
                "reason": str(exc),
            })
            continue
        active = int(np.asarray(payload["mask"], dtype=float)[-1].sum())
        row = {
            "scenario": name,
            "active_nodes_last_window": active,
            "payload_bytes": int(path.stat().st_size),
            "forecast_only": benchmark(service, payload, args.forecast_repeats, 20, False),
            "with_gradient_x_input_explanation": benchmark(service, payload, args.explain_repeats, 5, True),
        }
        scenarios.append(row)
        print(json.dumps(row, indent=2), flush=True)

    if not scenarios:
        raise RuntimeError("No validated replay payloads available")

    max_rss_mib = float(resource.getrusage(resource.RUSAGE_SELF).ru_maxrss) / 1024.0
    report = {
        "protocol": "V90 live-compatible in-process runtime performance benchmark",
        "claim_boundary": (
            "Measured on a GitHub-hosted Ubuntu CPU runner for the checkpoint actually used by the localhost graph runtime. "
            "These are reproducible lab/runtime numbers, not a customer production SLA and not latency for offline V70/V88/V89 experimental models."
        ),
        "runtime_artifact_folder": str(folder),
        "checkpoint_sha256": service.model_hash,
        "metrics_sha256": sha256(folder / "metrics.json"),
        "model_meta": service.meta,
        "service_initialization_ms": float(init_seconds * 1000.0),
        "max_process_rss_mib_after_benchmark": max_rss_mib,
        "environment": {
            "python": platform.python_version(),
            "platform": platform.platform(),
            "processor": platform.processor(),
        },
        "scenarios": scenarios,
        "skipped_replays": skipped,
        "measurement_contract": {
            "timer": "time.perf_counter",
            "forecast_only_excludes_explanation": True,
            "explanation_path_is_gradient_x_input": True,
            "single_threaded_sequential_requests": True,
            "http_transport_overhead_included": False,
            "warmup_used": True,
            "incompatible_graph_modes_are_skipped_not_coerced": True,
        },
    }
    (out / "summary.json").write_text(json.dumps(report, indent=2, allow_nan=False) + "\n")
    print(json.dumps({
        "checkpoint_sha256": service.model_hash,
        "initialization_ms": report["service_initialization_ms"],
        "max_rss_mib": max_rss_mib,
        "scenarios": scenarios,
        "skipped_replays": skipped,
    }, indent=2), flush=True)


if __name__ == "__main__":
    main()
