"""V107 PS-complete packet+flow GraphSAGE+LSTM development recovery.

This development-only runner closes the feature-contract gap left by the 21-feature
V101 checkpoint. It trains the same residual GraphSAGE+LSTM dynamics model directly
from hash-pinned CICAPT raw packet captures, but uses the full 34-feature SIH contract
from ps_complete.py, including PSH/URG, IAT variance/max, TTL variance, TCP window,
fragmentation, payload-size distribution, port-scan sequencing and retransmissions.

Consumed external holdouts (HIKARI/V99, MAWI/V102, CTU-IDSEVAL-6/V104 and
USTC-TFC2016 Miuref/V106) are excluded from fitting and selection. Phase 2 remains a
previously-used development sanity set, never a fresh external claim.
"""
from __future__ import annotations

import argparse
import json
from collections import defaultdict
from itertools import islice
from pathlib import Path
from typing import Dict, Iterable, List

import numpy as np

from .autograd import Adam
from .model import GraphWorldModel
from .pcap_reader import packets
from .ps_complete import FEATURES, SCHEMA, graph_snapshot, _connection_flow
from .support_gate import fit as fit_support_gate, score as support_score
from .v101_packet_graph_recovery import (
    HISTORY, HORIZON, WINDOW_SECONDS, MAX_NODES, EMBARGO_SEQUENCES,
    PHASE1_NAME, PHASE2_NAME, PHASE1_SHA256, PHASE2_SHA256,
    RecoveryContractError, file_hash, canonical_sha256,
    verify_development_capture, build_sequences, chronological_phase1_split,
    persistence_prediction, mse, infer_state, state_objective,
    candidate_row, select_candidate,
)

REQUIRED_FLOW = {
    "flow_count_log", "bytes_log", "packets_log", "duration_ms_log",
    "syn_fraction", "ack_fraction", "fin_fraction", "rst_fraction",
    "psh_fraction", "urg_fraction", "backward_packet_fraction",
    "tcp_fraction", "udp_fraction", "iat_ms_log", "iat_variance_log", "iat_max_log",
}
REQUIRED_PACKET = {
    "ttl_mean_scaled", "ttl_variance_scaled", "tcp_window_log", "fragment_fraction",
    "payload_mean_log", "payload_variance_log", "payload_max_log",
    "unique_destination_ports_log", "sequential_port_transition_fraction",
    "random_port_transition_fraction", "retransmission_fraction", "retransmission_count_log",
}
CONSUMED_EXTERNAL = [
    "HIKARI-2021/V99",
    "MAWI-200601011400/V102",
    "CTU-IDSEVAL-6/V104",
    "USTC-TFC2016/Miuref/V106",
]


def _flow_from_packets(observed: List[dict]) -> dict:
    return _connection_flow(observed)


def packet_service_graphs(path: Path, packet_limit: int):
    times: List[int] = []
    xs: List[np.ndarray] = []
    adjs: List[np.ndarray] = []
    masks: List[np.ndarray] = []
    current_bucket = None
    connections: Dict[tuple, List[dict]] = defaultdict(list)
    decoded = 0
    audit: dict = {}

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
        path, max_packets=max(packet_limit * 2, packet_limit + 1),
        allow_truncated=True, audit=audit,
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
        endpoints = sorted([(packet["src"], packet["sport"]), (packet["dst"], packet["dport"])])
        connections[(endpoints[0], endpoints[1], packet["protocol"])].append(packet)
    flush()

    if decoded < 1000:
        raise RecoveryContractError(f"Too few decoded IPv4 packets: {decoded}")
    if len(times) < HISTORY + HORIZON + 20:
        raise RecoveryContractError(f"Too few observed graph windows: {len(times)}")
    return (
        np.asarray(times, dtype=np.int64), np.asarray(xs, dtype=np.float32),
        np.asarray(adjs, dtype=np.float32), np.asarray(masks, dtype=np.float32),
        decoded, {k: int(v) for k, v in sorted(audit.items())},
    )


def train_seed(train_arrays, valid_arrays, seed: int, epochs: int, batch_size: int):
    tx, ta, tm, ty = train_arrays
    vx, va, vm, vy = valid_arrays
    model = GraphWorldModel(
        architecture="gnn_lstm", feature_dim=len(FEATURES), schema=SCHEMA,
        seed=int(seed), decoder="residual", stage_count=0,
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
            ids = order[offset:offset + batch_size]
            objective = state_objective(model, tx[ids], ta[ids], tm[ids], ty[ids])
            objective.backward(); optimizer.step(); losses.append(float(objective.data))
        val_pred = infer_state(model, vx, va, vm, batch_size=batch_size)
        val_mse = mse(val_pred, vy)
        curve.append({"epoch": epoch + 1, "train_objective": float(np.mean(losses)), "validation_mse": val_mse})
        if val_mse < best:
            best = val_mse; best_epoch = epoch + 1
            best_weights = {k: v.data.copy() for k, v in model.params.items()}

    for key, value in best_weights.items():
        model.params[key].data = value
    return model, float(best), int(best_epoch), curve


def packet_presence(x: np.ndarray, mask: np.ndarray) -> float:
    idx = FEATURES.index("packet_features_present")
    vals = x[:, :, :, idx][mask > 0]
    return float(vals.mean()) if len(vals) else 0.0


def feature_nonzero_fraction(x: np.ndarray, mask: np.ndarray, name: str) -> float:
    idx = FEATURES.index(name)
    vals = x[:, :, :, idx][mask > 0]
    return float((vals > 0).mean()) if len(vals) else 0.0


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

    missing = (REQUIRED_FLOW | REQUIRED_PACKET) - set(FEATURES)
    if missing:
        raise RecoveryContractError(f"PS-complete schema missing required features: {sorted(missing)}")
    if len(FEATURES) != 34:
        raise RecoveryContractError(f"Unexpected PS-complete feature count: {len(FEATURES)}")
    if len(set(args.seeds)) < 3:
        p.error("At least three distinct development seeds are required")

    phase1_sha = verify_development_capture(args.phase1, PHASE1_NAME, PHASE1_SHA256)
    phase2_sha = verify_development_capture(args.phase2, PHASE2_NAME, PHASE2_SHA256)

    t1, x1, a1, m1, n1, audit1 = packet_service_graphs(args.phase1, args.packet_limit)
    t2, x2, a2, m2, n2, audit2 = packet_service_graphs(args.phase2, args.packet_limit)
    sx1, sa1, sm1, sy1, c1 = build_sequences(t1, x1, a1, m1)
    sx2, sa2, sm2, sy2, c2 = build_sequences(t2, x2, a2, m2)
    train_ids, valid_ids = chronological_phase1_split(len(sx1))

    train_arrays = (sx1[train_ids], sa1[train_ids], sm1[train_ids], sy1[train_ids])
    valid_arrays = (sx1[valid_ids], sa1[valid_ids], sm1[valid_ids], sy1[valid_ids])
    phase2_arrays = (sx2, sa2, sm2, sy2)

    presence = {
        "phase1_train": packet_presence(train_arrays[0], train_arrays[2]),
        "phase1_validation": packet_presence(valid_arrays[0], valid_arrays[2]),
        "phase2_sanity": packet_presence(phase2_arrays[0], phase2_arrays[2]),
    }
    if min(presence.values()) <= 0.95:
        raise RecoveryContractError(f"Packet evidence missing from split: {presence}")

    rows, trained, curves = {}, {}, {}
    for seed in args.seeds:
        model, _, best_epoch, curve = train_seed(train_arrays, valid_arrays, seed, args.epochs, args.batch_size)
        row = candidate_row(model, valid_arrays, phase2_arrays, seed, best_epoch)
        rows[str(seed)] = row; trained[str(seed)] = model; curves[str(seed)] = curve
        print(json.dumps(row, indent=2), flush=True)

    selected_key = select_candidate(rows)
    selected = rows[selected_key]
    selected_model = trained[selected_key]

    gate = fit_support_gate(train_arrays[0], train_arrays[2], valid_arrays[0], valid_arrays[2])
    gate["fit_provenance"] = {
        "center_scale": "CICAPT Phase-1 train only",
        "threshold": "CICAPT Phase-1 validation only",
        "phase2_excluded_from_fit": True,
        "consumed_external_excluded_from_fit": list(CONSUMED_EXTERNAL),
    }
    phase2_scores = support_score(gate, phase2_arrays[0], phase2_arrays[2])
    phase2_supported = phase2_scores <= float(gate["threshold"])

    adapter_contract = {
        "schema": SCHEMA,
        "features": list(FEATURES),
        "feature_count": len(FEATURES),
        "required_flow_features": sorted(REQUIRED_FLOW),
        "required_packet_features": sorted(REQUIRED_PACKET),
        "all_ps_required_features_present": True,
        "mode": "service", "window_seconds": WINDOW_SECONDS,
        "history_windows": HISTORY, "forecast_windows": HORIZON,
        "max_nodes": MAX_NODES,
        "mapping": "raw PCAP packet telemetry -> bidirectional connections -> PS-complete service graph",
        "packet_features_required": True,
    }

    args.output_dir.mkdir(parents=True, exist_ok=True)
    model_path = args.output_dir / "gnn_lstm_ps_complete_candidate.npz"
    gate_path = args.output_dir / "support_gate.json"
    report_path = args.output_dir / "summary.json"
    metadata = {
        "schema": SCHEMA, "features": list(FEATURES), "architecture": "gnn_lstm",
        "history": HISTORY, "horizon": HORIZON, "mode": "service", "max_nodes": MAX_NODES,
        "window_seconds": WINDOW_SECONDS, "source_hashes": [phase1_sha, phase2_sha],
        "seed": int(selected_key), "decoder": "residual", "trained": True,
        "packet_features_trained": True, "ps_complete_features_trained": True,
        "risk_head_trained": False, "stage_supervised": False,
        "evaluation_scope": "development_reused_cross_phase",
        "consumed_external_used_for_fitting": False,
        "external_holdout_selected": False,
        "claim_boundary": "Development-only PS-complete state-transition candidate; risk/stage/external claims are not certified.",
    }
    selected_model.save(model_path, metadata)
    gate_path.write_text(json.dumps(gate, indent=2, allow_nan=False) + "\n")

    observed = {
        name: {
            "phase1_train_nonzero_fraction": feature_nonzero_fraction(train_arrays[0], train_arrays[2], name),
            "phase1_validation_nonzero_fraction": feature_nonzero_fraction(valid_arrays[0], valid_arrays[2], name),
            "phase2_nonzero_fraction": feature_nonzero_fraction(phase2_arrays[0], phase2_arrays[2], name),
        }
        for name in sorted(REQUIRED_FLOW | REQUIRED_PACKET)
    }

    recovery_pass = bool(selected["validation_gate_passed"] and selected["phase2_sanity_passed"] and min(presence.values()) > 0.95)
    report = {
        "schema_version": "v107.1",
        "status": "DEV_PS_COMPLETE_PASS" if recovery_pass else "DEV_PS_COMPLETE_FAIL",
        "recovery_gate_passed": recovery_pass,
        "claim_boundary": "Development-only PS-complete packet+flow GraphSAGE+LSTM evidence; no fresh external, MITRE-stage or successful-compromise warning claim.",
        "quarantine": {"consumed_external": list(CONSUMED_EXTERNAL), "used_for_training_or_selection": False},
        "development_sources": {
            "dataset": "CICAPT-IIoT2024", "development_reuse": True,
            "phase1": {"capture": PHASE1_NAME, "sha256": phase1_sha, "decoded_packets": n1, "parser_audit": audit1,
                       "observed_windows": int(len(t1)), "contiguous_sequences": int(len(sx1)), "train_sequences": int(len(train_ids)),
                       "validation_sequences": int(len(valid_ids)), "embargo_sequences": EMBARGO_SEQUENCES},
            "phase2": {"capture": PHASE2_NAME, "sha256": phase2_sha, "decoded_packets": n2, "parser_audit": audit2,
                       "observed_windows": int(len(t2)), "contiguous_sequences": int(len(sx2)), "used_for_selection": False},
        },
        "adapter_contract": adapter_contract,
        "adapter_contract_sha256": canonical_sha256(adapter_contract),
        "packet_features_present_mean": presence,
        "required_feature_observation": observed,
        "selection": {"rule": "minimum Phase-1 validation MSE only; ties by seed", "selected_seed": int(selected_key), "phase2_used_for_selection": False},
        "seeds": rows,
        "selected_candidate": selected,
        "support_gate": {"threshold": float(gate["threshold"]), "method": gate["method"],
                         "phase2_supported_sequences": int(phase2_supported.sum()), "phase2_total_sequences": int(len(phase2_supported)),
                         "phase2_supported_fraction": float(phase2_supported.mean()), "phase2_median_score": float(np.median(phase2_scores)),
                         "phase2_max_score": float(phase2_scores.max()), "fit_provenance": gate["fit_provenance"]},
        "freeze": {"model_file": model_path.name, "model_sha256": file_hash(model_path),
                   "support_gate_file": gate_path.name, "support_gate_sha256": file_hash(gate_path),
                   "candidate_frozen_before_any_new_external_holdout": True, "new_external_holdout_selected": False},
        "training_curves": curves,
        "next_gate": "Keep V106 quarantined. After this candidate is frozen, select a genuinely untouched external holdout only once; V97 stage and V98 successful-compromise gates remain separate.",
    }
    report_path.write_text(json.dumps(report, indent=2, allow_nan=False) + "\n")
    print(json.dumps({"status": report["status"], "selected_candidate": selected, "feature_count": len(FEATURES)}, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
