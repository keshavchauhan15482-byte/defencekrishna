"""V70 combined flow+packet world-model forecasting benchmark on real CICAPT PCAPNG.

The benchmark trains the residual LSTM world model on Phase-1 10-second network-state
vectors produced directly from packet captures using the full SIH flow+packet feature
schema, selects its persistence/residual blend on a later Phase-1 validation segment,
and evaluates state forecasting on the separate Phase-2 capture.

No attack labels are used.  The metric is future-state MSE versus persistence; this
closes the narrower question of whether the *combined packet+flow representation* is
actually consumed by a learned temporal state-transition model, rather than merely
being extractable.
"""
from __future__ import annotations

import argparse
import json
from collections import defaultdict
from itertools import islice
from pathlib import Path

import numpy as np

from .pcap_reader import packets
from .ps_complete import FEATURES, _connection_flow, summarize
from .v47_unseen_family import HISTORY, HORIZON
from .v60_residual_state_forecasting import train_residual_world_model

WINDOW_SECONDS = 10
EMBARGO_SEQUENCES = HISTORY + HORIZON


def packet_states(path: Path, packet_limit: int):
    """Stream capture into chronological 10-second state vectors without gap filling."""
    times = []
    vectors = []
    current_bucket = None
    connections = defaultdict(list)
    decoded = 0

    def flush():
        nonlocal connections, current_bucket
        if current_bucket is None:
            return
        flows = [_connection_flow(v) for v in connections.values()]
        times.append(int(current_bucket))
        vectors.append(summarize(flows))
        connections = defaultdict(list)

    for p in islice(packets(path, max_packets=max(packet_limit * 2, packet_limit + 1)), packet_limit):
        decoded += 1
        b = int(p["t"] // WINDOW_SECONDS) * WINDOW_SECONDS
        if current_bucket is None:
            current_bucket = b
        elif b != current_bucket:
            if b < current_bucket:
                raise RuntimeError(f"Non-monotone packet timestamp in {path}: {b} < {current_bucket}")
            flush()
            current_bucket = b
        endpoints = sorted([(p["src"], p["sport"]), (p["dst"], p["dport"])])
        key = (endpoints[0], endpoints[1], p["protocol"])
        connections[key].append(p)
    flush()

    if decoded < 1000 or len(vectors) < HISTORY + HORIZON + 20:
        raise RuntimeError(f"Insufficient packet/state support {path}: packets={decoded} windows={len(vectors)}")
    return np.asarray(times, dtype=np.int64), np.asarray(vectors, dtype=np.float32), decoded


def contiguous_sequences(times, states):
    X, future, cutoff = [], [], []
    total = HISTORY + HORIZON
    for i in range(0, len(states) - total + 1):
        t = times[i:i + total]
        if not np.all(np.diff(t) == WINDOW_SECONDS):
            continue
        X.append(states[i:i + HISTORY])
        future.append(states[i + HISTORY:i + total])
        cutoff.append(int(times[i + HISTORY - 1]))
    if not X:
        raise RuntimeError("No contiguous state sequences")
    return np.asarray(X, dtype=np.float32), np.asarray(future, dtype=np.float32), np.asarray(cutoff, dtype=np.int64)


def mse(pred, target, mask):
    ids = np.where(mask)[0]
    if len(ids) == 0:
        raise RuntimeError("Empty evaluation mask")
    return float(np.mean((pred[ids] - target[ids]) ** 2))


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--phase1", required=True)
    p.add_argument("--phase2", required=True)
    p.add_argument("--output", required=True)
    p.add_argument("--packet-limit", type=int, default=2_000_000)
    p.add_argument("--seeds", nargs="+", type=int, default=[42, 43, 44])
    p.add_argument("--epochs", type=int, default=18)
    args = p.parse_args()
    if len(set(args.seeds)) < 3:
        p.error("At least three distinct seeds required")

    t1, s1, n1 = packet_states(Path(args.phase1), args.packet_limit)
    t2, s2, n2 = packet_states(Path(args.phase2), args.packet_limit)
    x1, f1, c1 = contiguous_sequences(t1, s1)
    x2, f2, c2 = contiguous_sequences(t2, s2)

    # Chronological Phase-1 development split with a 12-sequence embargo.  Phase 2 is
    # never used for normalization, checkpoint/blend selection, or early stopping.
    cut = int(len(x1) * 0.70)
    val_start = cut + EMBARGO_SEQUENCES
    if cut < 100 or len(x1) - val_start < 50:
        raise RuntimeError(f"Phase1 support too small after embargo: sequences={len(x1)}")

    X = np.concatenate([x1, x2], axis=0)
    F = np.concatenate([f1, f2], axis=0)
    train = np.zeros(len(X), dtype=bool)
    val = np.zeros(len(X), dtype=bool)
    test = np.zeros(len(X), dtype=bool)
    train[:cut] = True
    val[val_start:len(x1)] = True
    test[len(x1):] = True

    rows = {}
    for seed in args.seeds:
        print(f"V70 seed={seed}", flush=True)
        world = train_residual_world_model(X, F, train, val, int(seed), epochs=args.epochs)
        tm = mse(world["pred"], world["future_scaled"], test)
        pm = mse(world["persistence"], world["future_scaled"], test)
        vm = float(world["validation_mse"])
        vpm = float(world["validation_persistence_mse"])
        rows[str(seed)] = {
            "seed": int(seed),
            "blend_alpha": float(world["blend_alpha"]),
            "trend_beta": float(world["trend_beta"]),
            "validation_mse": vm,
            "validation_persistence_mse": vpm,
            "validation_improvement_vs_persistence": float((vpm - vm) / vpm),
            "validation_gate_passed": bool(vm < vpm),
            "phase2_test_mse": tm,
            "phase2_persistence_mse": pm,
            "phase2_improvement_vs_persistence": float((pm - tm) / pm),
            "phase2_gate_passed": bool(tm < pm),
        }

    test_improvements = np.asarray([r["phase2_improvement_vs_persistence"] for r in rows.values()], dtype=float)
    validation_improvements = np.asarray([r["validation_improvement_vs_persistence"] for r in rows.values()], dtype=float)
    report = {
        "protocol": "V70 real CICAPT combined packet+flow state-transition forecasting",
        "claim_boundary": (
            "The learned residual LSTM consumes the complete extracted SIH packet+flow state vector and is "
            "evaluated on a separate experiment-phase capture. This is state-dynamics evidence; it is not "
            "attack-stage accuracy, warning lead-time, or production zero-day evidence."
        ),
        "features": list(FEATURES),
        "feature_count": len(FEATURES),
        "window_seconds": WINDOW_SECONDS,
        "history_windows": HISTORY,
        "forecast_windows": HORIZON,
        "forecast_seconds": HORIZON * WINDOW_SECONDS,
        "phase1": {
            "capture": str(args.phase1), "decoded_packets": n1, "observed_windows": len(s1),
            "contiguous_sequences": len(x1), "train_sequences": int(train.sum()),
            "validation_sequences": int(val.sum()), "embargo_sequences": EMBARGO_SEQUENCES,
            "first_epoch": int(t1[0]), "last_epoch": int(t1[-1]),
        },
        "phase2": {
            "capture": str(args.phase2), "decoded_packets": n2, "observed_windows": len(s2),
            "test_sequences": int(test.sum()), "first_epoch": int(t2[0]), "last_epoch": int(t2[-1]),
        },
        "leakage_contract": {
            "phase2_used_for_training": False,
            "phase2_used_for_normalization": False,
            "phase2_used_for_blend_selection": False,
            "phase2_used_for_early_stopping": False,
            "phase1_train_validation_chronological": True,
            "phase1_embargo_sequences": EMBARGO_SEQUENCES,
        },
        "seeds": rows,
        "summary": {
            "validation_gate_passed_seeds": int(sum(r["validation_gate_passed"] for r in rows.values())),
            "phase2_gate_passed_seeds": int(sum(r["phase2_gate_passed"] for r in rows.values())),
            "mean_phase2_improvement_vs_persistence": float(test_improvements.mean()),
            "sd_phase2_improvement_vs_persistence": float(test_improvements.std(ddof=1)),
            "min_phase2_improvement_vs_persistence": float(test_improvements.min()),
            "mean_validation_improvement_vs_persistence": float(validation_improvements.mean()),
        },
    }
    out = Path(args.output)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(report, indent=2, allow_nan=False) + "\n")
    print(json.dumps(report["summary"], indent=2), flush=True)
    print(json.dumps(rows, indent=2), flush=True)


if __name__ == "__main__":
    main()
