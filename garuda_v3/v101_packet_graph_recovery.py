"""V101 packet-compatible GraphSAGE+LSTM recovery on development-only CICAPT captures.

This runner exists because V99 exposed a real contract mismatch: the frozen active
checkpoint had been trained on flow-only graph artifacts, while the raw-PCAP adapter
set packet_features_present=1.  V101 does not touch HIKARI for fitting or selection.
It trains a new development candidate directly from hash-pinned CICAPT packet
captures mapped into the same v3.1 service-graph contract used by GraphWorldModel.

Evidence boundary:
- Phase-1 CICAPT is development train/validation only.
- Phase-2 CICAPT is a previously-used development cross-phase sanity check.
- Model/seed selection uses Phase-1 validation only.
- Support center/scale use Phase-1 train only; cutoff uses Phase-1 validation only.
- HIKARI is quarantined and rejected by filename and known MD5.
- No fresh external-generalisation, attack-risk, MITRE-stage, or successful-compromise
  claim is created by this script.
"""
from __future__ import annotations

import argparse
import hashlib
import json
from collections import defaultdict
from itertools import islice
from pathlib import Path
from typing import Dict, Iterable, List

import numpy as np

from .autograd import Adam
from .data import FEATURES, SCHEMA, graph_snapshot
from .model import GraphWorldModel
from .pcap_reader import packets
from .ps_complete import _connection_flow
from .support_gate import fit as fit_support_gate, score as support_score

HISTORY = 8
HORIZON = 4
WINDOW_SECONDS = 10
MAX_NODES = 32
EMBARGO_SEQUENCES = HISTORY + HORIZON

PHASE1_NAME = "1stPhase-timed-Merged.pcap"
PHASE2_NAME = "2ndPhase-timed-MergedV2.pcap"
PHASE1_SHA256 = "aaba416bda0cf922e0a2288b5e9cdb3a4050959e14631bc3f1e4d3f1c29395c6"
PHASE2_SHA256 = "bd24eda4928e3c561756d3cbc5fad4c93554b8c1f2f6e0aba674ff63b4e7bae3"

HIKARI_CAPTURE = "Monday_2022-04-11_0622_BRUTEFORCE_XML_150s.pcap"
HIKARI_MD5 = "900deec66e058801a377fd81c5fc805e"


class RecoveryContractError(RuntimeError):
    pass


def file_hash(path: Path, algorithm: str = "sha256") -> str:
    h = hashlib.new(algorithm)
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            h.update(block)
    return h.hexdigest()


def canonical_sha256(value: dict) -> str:
    payload = json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False).encode("utf-8")
    return hashlib.sha256(payload).hexdigest()


def assert_not_quarantined(path: Path) -> None:
    """Fail closed if the consumed V99 HIKARI holdout is supplied to V101."""
    name = path.name.lower()
    if "hikari" in name or path.name == HIKARI_CAPTURE:
        raise RecoveryContractError("V99 HIKARI holdout is quarantined from V101 fitting/selection")
    # Filename-independent guard for the exact consumed V99 capture.
    if path.exists() and file_hash(path, "md5") == HIKARI_MD5:
        raise RecoveryContractError("Consumed V99 HIKARI capture hash is quarantined")


def verify_development_capture(path: Path, expected_name: str, expected_sha256: str) -> str:
    assert_not_quarantined(path)
    if path.name != expected_name:
        raise RecoveryContractError(f"Unexpected CICAPT development capture: {path.name}")
    observed = file_hash(path, "sha256")
    if observed != expected_sha256:
        raise RecoveryContractError(
            f"CICAPT capture SHA-256 mismatch for {path.name}: {observed}"
        )
    return observed


def _flow_from_packets(observed: List[dict]) -> dict:
    flow = _connection_flow(observed)
    flow["retransmission_fraction"] = float(flow.get("retransmission_count", 0.0)) / max(
        float(flow.get("packets", 0.0)), 1.0
    )
    return flow


def packet_service_graphs(path: Path, packet_limit: int):
    """Map raw packet telemetry to the frozen v3.1 service-graph feature contract."""
    times: List[int] = []
    xs: List[np.ndarray] = []
    adjs: List[np.ndarray] = []
    masks: List[np.ndarray] = []
    current_bucket = None
    connections: Dict[tuple, List[dict]] = defaultdict(list)
    decoded = 0

    def flush() -> None:
        nonlocal connections
        if current_bucket is None:
            return
        flows = [_flow_from_packets(v) for v in connections.values()]
        x, adj, mask, _ = graph_snapshot(flows, mode="service", max_nodes=MAX_NODES)
        times.append(int(current_bucket))
        xs.append(x.astype(np.float32, copy=False))
        adjs.append(adj.astype(np.float32, copy=False))
        masks.append(mask.astype(np.float32, copy=False))
        connections = defaultdict(list)

    iterator: Iterable[dict] = packets(
        path, max_packets=max(packet_limit * 2, packet_limit + 1)
    )
    for packet in islice(iterator, packet_limit):
        decoded += 1
        bucket = int(packet["t"] // WINDOW_SECONDS) * WINDOW_SECONDS
        if current_bucket is None:
            current_bucket = bucket
        elif bucket != current_bucket:
            if bucket < current_bucket:
                raise RecoveryContractError(f"Non-monotone packet timestamp in {path}")
            flush()
            current_bucket = bucket
        endpoints = sorted(
            [(packet["src"], packet["sport"]), (packet["dst"], packet["dport"])]
        )
        key = (endpoints[0], endpoints[1], packet["protocol"])
        connections[key].append(packet)
    flush()

    if decoded < 1000:
        raise RecoveryContractError(f"Too few decoded IPv4 packets: {decoded}")
    if len(times) < HISTORY + HORIZON + 20:
        raise RecoveryContractError(f"Too few observed 10-second graph windows: {len(times)}")
    return (
        np.asarray(times, dtype=np.int64),
        np.asarray(xs, dtype=np.float32),
        np.asarray(adjs, dtype=np.float32),
        np.asarray(masks, dtype=np.float32),
        decoded,
    )


def build_sequences(times, x, adj, mask):
    sx, sa, sm, future, cutoffs = [], [], [], [], []
    total = HISTORY + HORIZON
    for start in range(0, len(times) - total + 1):
        ids = slice(start, start + total)
        if not np.all(np.diff(times[ids]) == WINDOW_SECONDS):
            continue
        hx = x[start : start + HISTORY]
        ha = adj[start : start + HISTORY]
        hm = mask[start : start + HISTORY]
        fx = x[start + HISTORY : start + total]
        fm = mask[start + HISTORY : start + total]
        pooled_future = (fx * fm[:, :, None]).sum(axis=1) / np.maximum(
            fm.sum(axis=1, keepdims=True), 1.0
        )
        sx.append(hx)
        sa.append(ha)
        sm.append(hm)
        future.append(pooled_future)
        cutoffs.append(int(times[start + HISTORY - 1] + WINDOW_SECONDS))
    if not sx:
        raise RecoveryContractError("No contiguous 8-history/4-future graph sequences")
    return tuple(
        np.asarray(v)
        for v in (sx, sa, sm, future, cutoffs)
    )


def chronological_phase1_split(n: int):
    cut = int(n * 0.70)
    val_start = cut + EMBARGO_SEQUENCES
    if cut < 100 or n - val_start < 50:
        raise RecoveryContractError(
            f"Phase-1 support too small after embargo: sequences={n}, train={cut}, val={n-val_start}"
        )
    return np.arange(cut), np.arange(val_start, n)


def pooled_history(x: np.ndarray, mask: np.ndarray) -> np.ndarray:
    return (x * mask[:, :, :, None]).sum(axis=2) / np.maximum(
        mask.sum(axis=2, keepdims=True), 1.0
    )


def persistence_prediction(x: np.ndarray, mask: np.ndarray) -> np.ndarray:
    pooled = pooled_history(x, mask)
    return np.repeat(pooled[:, -1:, :], HORIZON, axis=1)


def mse(pred: np.ndarray, target: np.ndarray) -> float:
    return float(np.mean((pred - target) ** 2))


def infer_state(model: GraphWorldModel, x, adj, mask, batch_size: int = 64) -> np.ndarray:
    rows = []
    for start in range(0, len(x), batch_size):
        mean, _, _ = model.forward(
            x[start : start + batch_size],
            adj[start : start + batch_size],
            mask[start : start + batch_size],
            HORIZON,
        )
        rows.append(mean.data)
    return np.concatenate(rows, axis=0)


def state_objective(model: GraphWorldModel, x, adj, mask, target):
    mean, sigma, _ = model.forward(x, adj, mask, HORIZON)
    error = mean - target
    nll = ((error / sigma).power(2) * 0.5 + sigma.log()).mean()
    return 10.0 * error.power(2).mean() + 0.01 * nll


def train_seed(train_arrays, valid_arrays, seed: int, epochs: int, batch_size: int):
    tx, ta, tm, ty = train_arrays
    vx, va, vm, vy = valid_arrays
    model = GraphWorldModel(
        architecture="gnn_lstm",
        seed=int(seed),
        decoder="residual",
        stage_count=0,
    )
    optimizer = Adam(model.parameters(), lr=0.003)
    rng = np.random.default_rng(seed)
    initial_pred = infer_state(model, vx, va, vm, batch_size=batch_size)
    best = mse(initial_pred, vy)
    best_epoch = 0
    best_weights = {k: v.data.copy() for k, v in model.params.items()}
    curve = [{"epoch": 0, "train_objective": None, "validation_mse": best}]

    for epoch in range(epochs):
        order = rng.permutation(len(tx))
        losses = []
        for offset in range(0, len(order), batch_size):
            ids = order[offset : offset + batch_size]
            objective = state_objective(model, tx[ids], ta[ids], tm[ids], ty[ids])
            objective.backward()
            optimizer.step()
            losses.append(float(objective.data))
        val_pred = infer_state(model, vx, va, vm, batch_size=batch_size)
        val_mse = mse(val_pred, vy)
        curve.append(
            {
                "epoch": epoch + 1,
                "train_objective": float(np.mean(losses)),
                "validation_mse": val_mse,
            }
        )
        if val_mse < best:
            best = val_mse
            best_epoch = epoch + 1
            best_weights = {k: v.data.copy() for k, v in model.params.items()}

    if not np.isfinite(best):
        raise RecoveryContractError("No finite validation checkpoint")
    for key, value in best_weights.items():
        model.params[key].data = value
    return model, best, int(best_epoch), curve


def candidate_row(model, valid_arrays, phase2_arrays, seed, best_epoch):
    vx, va, vm, vy = valid_arrays
    px, pa, pm, py = phase2_arrays
    vpred = infer_state(model, vx, va, vm)
    ppred = infer_state(model, px, pa, pm)
    vpersist = persistence_prediction(vx, vm)
    ppersist = persistence_prediction(px, pm)
    vmse = mse(vpred, vy)
    vpmse = mse(vpersist, vy)
    tmse = mse(ppred, py)
    tpmse = mse(ppersist, py)
    return {
        "seed": int(seed),
        "best_epoch": int(best_epoch),
        "validation_mse": vmse,
        "validation_persistence_mse": vpmse,
        "validation_improvement_vs_persistence": float((vpmse - vmse) / vpmse) if vpmse else 0.0,
        "validation_gate_passed": bool(vmse < vpmse),
        "phase2_mse": tmse,
        "phase2_persistence_mse": tpmse,
        "phase2_improvement_vs_persistence": float((tpmse - tmse) / tpmse) if tpmse else 0.0,
        "phase2_sanity_passed": bool(tmse < tpmse),
    }


def select_candidate(rows: dict) -> str:
    """Select using Phase-1 validation MSE only; never Phase-2 or external metrics."""
    if not rows:
        raise RecoveryContractError("No candidate rows")
    return min(rows, key=lambda key: (rows[key]["validation_mse"], int(key)))


def packet_presence(x: np.ndarray, mask: np.ndarray) -> float:
    idx = FEATURES.index("packet_features_present")
    observed = mask > 0
    values = x[:, :, :, idx][observed]
    return float(values.mean()) if len(values) else 0.0


def main() -> int:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--phase1", required=True, type=Path)
    p.add_argument("--phase2", required=True, type=Path)
    p.add_argument("--output-dir", required=True, type=Path)
    p.add_argument("--packet-limit", type=int, default=2_000_000)
    p.add_argument("--seeds", nargs="+", type=int, default=[42, 43, 44])
    p.add_argument("--epochs", type=int, default=8)
    p.add_argument("--batch-size", type=int, default=64)
    args = p.parse_args()
    if len(set(args.seeds)) < 3:
        p.error("At least three distinct development seeds are required")
    if args.packet_limit < 100_000:
        p.error("packet-limit must be at least 100000")
    if not 1 <= args.epochs <= 100:
        p.error("epochs must be 1..100")

    phase1_sha = verify_development_capture(args.phase1, PHASE1_NAME, PHASE1_SHA256)
    phase2_sha = verify_development_capture(args.phase2, PHASE2_NAME, PHASE2_SHA256)

    t1, x1, a1, m1, n1 = packet_service_graphs(args.phase1, args.packet_limit)
    t2, x2, a2, m2, n2 = packet_service_graphs(args.phase2, args.packet_limit)
    sx1, sa1, sm1, sy1, c1 = build_sequences(t1, x1, a1, m1)
    sx2, sa2, sm2, sy2, c2 = build_sequences(t2, x2, a2, m2)
    train_ids, valid_ids = chronological_phase1_split(len(sx1))

    train_arrays = (sx1[train_ids], sa1[train_ids], sm1[train_ids], sy1[train_ids])
    valid_arrays = (sx1[valid_ids], sa1[valid_ids], sm1[valid_ids], sy1[valid_ids])
    phase2_arrays = (sx2, sa2, sm2, sy2)

    train_packet_presence = packet_presence(train_arrays[0], train_arrays[2])
    valid_packet_presence = packet_presence(valid_arrays[0], valid_arrays[2])
    phase2_packet_presence = packet_presence(phase2_arrays[0], phase2_arrays[2])
    if min(train_packet_presence, valid_packet_presence, phase2_packet_presence) <= 0.0:
        raise RecoveryContractError("Packet-derived graph evidence is absent in a development split")

    rows = {}
    trained = {}
    curves = {}
    for seed in args.seeds:
        print(f"V101 training seed={seed}", flush=True)
        model, _, best_epoch, curve = train_seed(
            train_arrays, valid_arrays, int(seed), args.epochs, args.batch_size
        )
        row = candidate_row(model, valid_arrays, phase2_arrays, int(seed), best_epoch)
        rows[str(seed)] = row
        trained[str(seed)] = model
        curves[str(seed)] = curve
        print(json.dumps(row, indent=2), flush=True)

    selected_key = select_candidate(rows)
    selected = rows[selected_key]
    selected_model = trained[selected_key]

    gate = fit_support_gate(
        train_arrays[0], train_arrays[2], valid_arrays[0], valid_arrays[2]
    )
    # Explicit provenance beyond support_gate.py's mathematical contract.
    gate["fit_provenance"] = {
        "center_scale": "CICAPT Phase-1 train only",
        "threshold": "CICAPT Phase-1 validation only",
        "phase2_excluded_from_fit": True,
        "hikari_excluded_from_fit": True,
    }
    phase2_scores = support_score(gate, phase2_arrays[0], phase2_arrays[2])
    phase2_supported = phase2_scores <= float(gate["threshold"])

    adapter_contract = {
        "schema": SCHEMA,
        "features": list(FEATURES),
        "feature_count": len(FEATURES),
        "mode": "service",
        "window_seconds": WINDOW_SECONDS,
        "history_windows": HISTORY,
        "forecast_windows": HORIZON,
        "max_nodes": MAX_NODES,
        "mapping": "raw PCAP packet telemetry -> bidirectional connections -> v3.1 service graph",
        "packet_features_required": True,
    }

    args.output_dir.mkdir(parents=True, exist_ok=True)
    model_path = args.output_dir / "gnn_lstm_packet_candidate.npz"
    gate_path = args.output_dir / "support_gate.json"
    report_path = args.output_dir / "summary.json"

    metadata = {
        "schema": SCHEMA,
        "features": list(FEATURES),
        "architecture": "gnn_lstm",
        "history": HISTORY,
        "horizon": HORIZON,
        "mode": "service",
        "max_nodes": MAX_NODES,
        "window_seconds": WINDOW_SECONDS,
        "source_hashes": [phase1_sha, phase2_sha],
        "seed": int(selected_key),
        "decoder": "residual",
        "trained": True,
        "packet_features_trained": True,
        "risk_head_trained": False,
        "stage_supervised": False,
        "evaluation_scope": "development_reused_cross_phase",
        "hikari_used_for_fitting": False,
        "external_holdout_selected": False,
        "automatic_containment_approved": False,
        "claim_boundary": "Development-only packet-compatible state-transition candidate; risk/stage outputs are not certified.",
    }
    selected_model.save(model_path, metadata)
    gate_path.write_text(json.dumps(gate, indent=2, allow_nan=False) + "\n", encoding="utf-8")

    recovery_pass = bool(
        selected["validation_gate_passed"]
        and selected["phase2_sanity_passed"]
        and train_packet_presence > 0.95
        and valid_packet_presence > 0.95
    )
    report = {
        "schema_version": "v101.1",
        "status": "DEV_RECOVERY_PASS" if recovery_pass else "DEV_RECOVERY_FAIL",
        "recovery_gate_passed": recovery_pass,
        "claim_boundary": (
            "V101 is development-only recovery evidence. It does not alter the immutable V99 HIKARI FAIL "
            "and does not certify fresh external generalisation, attack recall/FPR, MITRE stages, "
            "or warning before successful compromise."
        ),
        "quarantine": {
            "hikari_consumed_external_holdout": True,
            "hikari_used_for_training": False,
            "hikari_used_for_normalization": False,
            "hikari_used_for_support_fit": False,
            "hikari_used_for_adapter_selection": False,
            "hikari_used_for_seed_or_checkpoint_selection": False,
            "future_external_requires_different_untouched_holdout": True,
        },
        "development_sources": {
            "dataset": "CICAPT-IIoT2024",
            "development_reuse": True,
            "phase1": {
                "capture": PHASE1_NAME,
                "sha256": phase1_sha,
                "decoded_packets": int(n1),
                "observed_windows": int(len(t1)),
                "contiguous_sequences": int(len(sx1)),
                "train_sequences": int(len(train_ids)),
                "validation_sequences": int(len(valid_ids)),
                "embargo_sequences": EMBARGO_SEQUENCES,
                "first_cutoff_epoch": int(c1[0]),
                "last_cutoff_epoch": int(c1[-1]),
            },
            "phase2": {
                "capture": PHASE2_NAME,
                "sha256": phase2_sha,
                "decoded_packets": int(n2),
                "observed_windows": int(len(t2)),
                "contiguous_sequences": int(len(sx2)),
                "first_cutoff_epoch": int(c2[0]),
                "last_cutoff_epoch": int(c2[-1]),
                "used_for_selection": False,
            },
        },
        "adapter_contract": adapter_contract,
        "adapter_contract_sha256": canonical_sha256(adapter_contract),
        "packet_features_present_mean": {
            "phase1_train": train_packet_presence,
            "phase1_validation": valid_packet_presence,
            "phase2_sanity": phase2_packet_presence,
        },
        "selection": {
            "rule": "minimum Phase-1 validation MSE only; ties by seed",
            "selected_seed": int(selected_key),
            "phase2_used_for_selection": False,
            "hikari_used_for_selection": False,
        },
        "seeds": rows,
        "selected_candidate": selected,
        "support_gate": {
            "threshold": float(gate["threshold"]),
            "method": gate["method"],
            "phase2_supported_sequences": int(phase2_supported.sum()),
            "phase2_total_sequences": int(len(phase2_supported)),
            "phase2_supported_fraction": float(phase2_supported.mean()),
            "phase2_median_score": float(np.median(phase2_scores)),
            "phase2_max_score": float(phase2_scores.max()),
            "fit_provenance": gate["fit_provenance"],
        },
        "freeze": {
            "model_file": model_path.name,
            "model_sha256": file_hash(model_path),
            "support_gate_file": gate_path.name,
            "support_gate_sha256": file_hash(gate_path),
            "candidate_frozen_before_any_new_external_holdout": True,
            "new_external_holdout_selected": False,
        },
        "training_curves": curves,
        "next_gate": (
            "Only after this development candidate is frozen: preregister a genuinely untouched, non-HIKARI "
            "external dataset/campaign and execute exactly one evaluation without retuning."
        ),
    }
    report_path.write_text(json.dumps(report, indent=2, allow_nan=False) + "\n", encoding="utf-8")
    print(json.dumps({k: report[k] for k in ("status", "recovery_gate_passed", "selection", "selected_candidate")}, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
