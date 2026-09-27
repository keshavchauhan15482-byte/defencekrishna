"""V115 development-only history-relative PS-complete world-model recovery.

External failures V99/V106/V113/V114 are quarantined and never supplied here. The raw
SIH 34-feature packet/flow graph contract is retained at ingestion, but the transition
model is trained in history-relative state coordinates: every non-availability feature
is centered by that sequence's history-only pooled median and divided by a robust scale
fit on Phase-1 training histories only. Availability/sensor-presence indicators remain
literal. This makes the learned dynamics less dependent on absolute network scale while
preserving an invertible mapping back to raw pooled state.

Selection uses Phase-1 validation only. Phase-2 is reused development sanity only.
No fresh external, stage, attack-risk, or successful-compromise claim is created.
"""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path

import numpy as np

from .autograd import Adam
from .model import GraphWorldModel
from .ps_complete import FEATURES
from .support_gate import fit as fit_support_gate, score as support_score
from .v101_packet_graph_recovery import (
    HISTORY, HORIZON, WINDOW_SECONDS, MAX_NODES, EMBARGO_SEQUENCES,
    PHASE1_NAME, PHASE2_NAME, PHASE1_SHA256, PHASE2_SHA256,
    RecoveryContractError, file_hash, canonical_sha256, verify_development_capture,
    build_sequences, chronological_phase1_split, pooled_history,
    persistence_prediction, infer_state, state_objective, mse,
)
from .v112_tolerant_ps_complete_runtime import tolerant_packet_service_graphs

RELATIVE_SCHEMA = "garuda-observed-graph-v46-ps-complete-relative-v1"
RAW_SCHEMA = "garuda-observed-graph-v46-ps-complete"
SCALE_FLOOR = 0.05
# First 29 features are behavioural state values. Last five are sensor/presence flags
# and remain literal so the model cannot normalize away missing telemetry capability.
RELATIVE_FEATURES = tuple(FEATURES[:29])
PRESENCE_FEATURES = tuple(FEATURES[29:])
EXPECTED_PRESENCE = (
    "packet_features_present", "iat_present", "tcp_window_present",
    "payload_present", "scan_sequence_present",
)


def fit_transform(train_x: np.ndarray, train_mask: np.ndarray) -> dict:
    pooled = pooled_history(train_x, train_mask).reshape(-1, len(FEATURES))
    median = np.median(pooled, axis=0)
    mad_scale = 1.4826 * np.median(np.abs(pooled - median), axis=0)
    scale = np.maximum(mad_scale, SCALE_FLOOR)
    # Presence features are identity transformed.
    for name in PRESENCE_FEATURES:
        scale[FEATURES.index(name)] = 1.0
    return {
        "schema_version": "v115-relative-transform.1",
        "raw_schema": RAW_SCHEMA,
        "model_schema": RELATIVE_SCHEMA,
        "features": list(FEATURES),
        "relative_features": list(RELATIVE_FEATURES),
        "presence_features_identity": list(PRESENCE_FEATURES),
        "local_center": "per-sequence median of pooled history only",
        "scale_fit": "1.4826*MAD of pooled Phase-1 training histories only",
        "scale_floor": SCALE_FLOOR,
        "scale": scale.tolist(),
        "future_information_used_for_transform": False,
    }


def apply_transform(
    x: np.ndarray,
    target: np.ndarray,
    mask: np.ndarray,
    transform: dict,
):
    if list(transform["features"]) != list(FEATURES):
        raise RecoveryContractError("V115 transform feature ordering drift")
    scale = np.asarray(transform["scale"], dtype=np.float32)
    pooled = pooled_history(x, mask)
    local_center = np.median(pooled, axis=1).astype(np.float32)
    out_x = x.astype(np.float32, copy=True)
    out_y = target.astype(np.float32, copy=True)
    relative_ids = np.asarray([FEATURES.index(n) for n in RELATIVE_FEATURES], dtype=np.int64)
    for j in relative_ids:
        out_x[..., j] = (out_x[..., j] - local_center[:, None, None, j]) / scale[j]
        out_y[..., j] = (out_y[..., j] - local_center[:, None, j]) / scale[j]
    # Keep padded graph nodes exactly zero after centering.
    out_x *= mask[..., None]
    return out_x, out_y, local_center


def inverse_pooled(pred: np.ndarray, local_center: np.ndarray, transform: dict) -> np.ndarray:
    raw = pred.astype(np.float32, copy=True)
    scale = np.asarray(transform["scale"], dtype=np.float32)
    for name in RELATIVE_FEATURES:
        j = FEATURES.index(name)
        raw[..., j] = raw[..., j] * scale[j] + local_center[:, None, j]
    return raw


def normalized_and_raw_metrics(model, arrays, raw_target, center, transform, batch_size=64):
    x, adj, mask, target = arrays
    pred = infer_state(model, x, adj, mask, batch_size=batch_size)
    persist = persistence_prediction(x, mask)
    norm_model = mse(pred, target)
    norm_persist = mse(persist, target)
    pred_raw = inverse_pooled(pred, center, transform)
    persist_raw = inverse_pooled(persist, center, transform)
    raw_model = mse(pred_raw, raw_target)
    raw_persist = mse(persist_raw, raw_target)
    return {
        "normalized_model_mse": norm_model,
        "normalized_persistence_mse": norm_persist,
        "normalized_improvement_vs_persistence": float((norm_persist - norm_model) / norm_persist) if norm_persist else 0.0,
        "normalized_beats_persistence": bool(norm_model < norm_persist),
        "raw_reconstructed_model_mse": raw_model,
        "raw_persistence_mse": raw_persist,
        "raw_improvement_vs_persistence": float((raw_persist - raw_model) / raw_persist) if raw_persist else 0.0,
        "raw_beats_persistence": bool(raw_model < raw_persist),
    }


def train_seed(train_arrays, valid_arrays, seed: int, epochs: int, batch_size: int):
    tx, ta, tm, ty = train_arrays
    vx, va, vm, vy = valid_arrays
    model = GraphWorldModel(
        architecture="gnn_lstm", feature_dim=len(FEATURES), seed=int(seed),
        decoder="residual", stage_count=0, schema=RELATIVE_SCHEMA,
    )
    optimizer = Adam(model.parameters(), lr=0.003)
    rng = np.random.default_rng(seed)
    initial = infer_state(model, vx, va, vm, batch_size=batch_size)
    best = mse(initial, vy)
    best_epoch = 0
    best_weights = {k: v.data.copy() for k, v in model.params.items()}
    curve = [{"epoch": 0, "train_objective": None, "validation_mse": best}]
    for epoch in range(epochs):
        order = rng.permutation(len(tx)); losses = []
        for offset in range(0, len(order), batch_size):
            ids = order[offset:offset + batch_size]
            objective = state_objective(model, tx[ids], ta[ids], tm[ids], ty[ids])
            objective.backward(); optimizer.step(); losses.append(float(objective.data))
        val = mse(infer_state(model, vx, va, vm, batch_size=batch_size), vy)
        curve.append({"epoch": epoch + 1, "train_objective": float(np.mean(losses)), "validation_mse": val})
        if val < best:
            best = val; best_epoch = epoch + 1
            best_weights = {k: v.data.copy() for k, v in model.params.items()}
    for key, value in best_weights.items():
        model.params[key].data = value
    return model, int(best_epoch), curve


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
    if tuple(PRESENCE_FEATURES) != EXPECTED_PRESENCE:
        raise RecoveryContractError(f"V115 expected final five presence features, got {PRESENCE_FEATURES}")
    if len(FEATURES) != 34 or len(RELATIVE_FEATURES) != 29:
        raise RecoveryContractError("V115 requires the 34-feature PS-complete contract")
    if len(set(args.seeds)) < 3:
        p.error("At least three distinct seeds are required")
    if args.packet_limit < 100_000:
        p.error("packet-limit must be at least 100000")

    phase1_sha = verify_development_capture(args.phase1, PHASE1_NAME, PHASE1_SHA256)
    phase2_sha = verify_development_capture(args.phase2, PHASE2_NAME, PHASE2_SHA256)
    t1, x1, a1, m1, n1, audit1 = tolerant_packet_service_graphs(args.phase1, args.packet_limit)
    t2, x2, a2, m2, n2, audit2 = tolerant_packet_service_graphs(args.phase2, args.packet_limit)
    sx1, sa1, sm1, sy1_raw, c1 = build_sequences(t1, x1, a1, m1)
    sx2, sa2, sm2, sy2_raw, c2 = build_sequences(t2, x2, a2, m2)
    train_ids, valid_ids = chronological_phase1_split(len(sx1))

    transform = fit_transform(sx1[train_ids], sm1[train_ids])
    nx1, ny1, centers1 = apply_transform(sx1, sy1_raw, sm1, transform)
    nx2, ny2, centers2 = apply_transform(sx2, sy2_raw, sm2, transform)

    train = (nx1[train_ids], sa1[train_ids], sm1[train_ids], ny1[train_ids])
    valid = (nx1[valid_ids], sa1[valid_ids], sm1[valid_ids], ny1[valid_ids])
    phase2 = (nx2, sa2, sm2, ny2)

    rows = {}; models = {}; curves = {}
    for seed in args.seeds:
        print(f"V115 training seed={seed}", flush=True)
        model, epoch, curve = train_seed(train, valid, int(seed), args.epochs, args.batch_size)
        vm = normalized_and_raw_metrics(
            model, valid, sy1_raw[valid_ids], centers1[valid_ids], transform, args.batch_size
        )
        pm = normalized_and_raw_metrics(
            model, phase2, sy2_raw, centers2, transform, args.batch_size
        )
        rows[str(seed)] = {"seed": int(seed), "best_epoch": epoch, "validation": vm, "phase2": pm}
        models[str(seed)] = model; curves[str(seed)] = curve
        print(json.dumps(rows[str(seed)], indent=2), flush=True)

    selected_key = min(rows, key=lambda k: (rows[k]["validation"]["normalized_model_mse"], int(k)))
    selected = rows[selected_key]; model = models[selected_key]

    gate = fit_support_gate(train[0], train[2], valid[0], valid[2])
    gate["fit_provenance"] = {
        "center_scale": "history-relative Phase-1 train only",
        "threshold": "history-relative Phase-1 validation only",
        "phase2_excluded_from_fit": True,
        "all_consumed_external_holdouts_excluded_from_fit": True,
    }
    p2_scores = support_score(gate, phase2[0], phase2[2])
    p2_supported = p2_scores <= float(gate["threshold"])
    p2_support_fraction = float(p2_supported.mean())

    gates = {
        "validation_normalized_beats_persistence": bool(selected["validation"]["normalized_beats_persistence"]),
        "validation_raw_reconstructed_beats_persistence": bool(selected["validation"]["raw_beats_persistence"]),
        "phase2_normalized_beats_persistence": bool(selected["phase2"]["normalized_beats_persistence"]),
        "phase2_raw_reconstructed_beats_persistence": bool(selected["phase2"]["raw_beats_persistence"]),
        "phase2_supported_fraction_at_least_0_95": bool(p2_support_fraction >= 0.95),
    }
    passed = all(gates.values())

    args.output_dir.mkdir(parents=True, exist_ok=True)
    model_path = args.output_dir / "gnn_lstm_relative_candidate.npz"
    gate_path = args.output_dir / "support_gate.json"
    transform_path = args.output_dir / "relative_transform.json"
    transform_path.write_text(json.dumps(transform, indent=2, allow_nan=False) + "\n")
    gate_path.write_text(json.dumps(gate, indent=2, allow_nan=False) + "\n")
    transform_sha = file_hash(transform_path)
    metadata = {
        "schema": RELATIVE_SCHEMA,
        "raw_input_schema": RAW_SCHEMA,
        "features": list(FEATURES),
        "architecture": "gnn_lstm", "history": HISTORY, "horizon": HORIZON,
        "mode": "service", "max_nodes": MAX_NODES, "window_seconds": WINDOW_SECONDS,
        "seed": int(selected_key), "decoder": "residual", "trained": True,
        "packet_features_trained": True, "ps_complete_features_trained": True,
        "history_relative_state": True, "relative_transform_sha256": transform_sha,
        "risk_head_trained": False, "stage_supervised": False,
        "evaluation_scope": "development_reused_cross_phase",
        "consumed_external_used_for_fitting": False,
        "claim_boundary": "Development-only history-relative state-transition candidate; no external/stage/precompromise claim.",
    }
    model.save(model_path, metadata)

    transform_contract = {
        "raw_schema": RAW_SCHEMA,
        "model_schema": RELATIVE_SCHEMA,
        "raw_features": list(FEATURES),
        "relative_feature_count": len(RELATIVE_FEATURES),
        "presence_identity_count": len(PRESENCE_FEATURES),
        "local_center": transform["local_center"],
        "scale_fit": transform["scale_fit"],
        "scale_floor": SCALE_FLOOR,
        "future_information_used_for_transform": False,
        "external_statistics_used": False,
    }
    report = {
        "schema_version": "v115.1",
        "status": "DEV_RELATIVE_STATE_PASS" if passed else "DEV_RELATIVE_STATE_FAIL",
        "recovery_gate_passed": passed,
        "claim_boundary": "Development-only scale-robust state-transition recovery. No consumed external holdout is used for fitting/selection and no new external, MITRE-stage, risk, or pre-compromise claim is created.",
        "development_sources": {
            "dataset": "CICAPT-IIoT2024", "development_reuse": True,
            "phase1": {"capture": PHASE1_NAME, "sha256": phase1_sha, "decoded_ipv4_packets": int(n1), "parser_audit": audit1, "sequences": int(len(sx1)), "train_sequences": int(len(train_ids)), "validation_sequences": int(len(valid_ids)), "embargo_sequences": EMBARGO_SEQUENCES},
            "phase2": {"capture": PHASE2_NAME, "sha256": phase2_sha, "decoded_ipv4_packets": int(n2), "parser_audit": audit2, "sequences": int(len(sx2)), "used_for_selection": False},
        },
        "representation": {
            "raw_schema": RAW_SCHEMA, "model_schema": RELATIVE_SCHEMA,
            "raw_feature_count": len(FEATURES), "relative_feature_count": len(RELATIVE_FEATURES),
            "presence_identity_features": list(PRESENCE_FEATURES),
            "transform_sha256": transform_sha,
            "contract": transform_contract,
            "contract_sha256": canonical_sha256(transform_contract),
        },
        "selection": {"rule": "minimum Phase-1 validation normalized MSE only; ties by seed", "selected_seed": int(selected_key), "phase2_used_for_selection": False, "external_used_for_selection": False},
        "seeds": rows, "selected_candidate": selected,
        "support_gate": {
            "method": gate["method"], "threshold": float(gate["threshold"]),
            "phase2_supported_sequences": int(p2_supported.sum()), "phase2_total_sequences": int(len(p2_supported)),
            "phase2_supported_fraction": p2_support_fraction,
            "phase2_median_score": float(np.median(p2_scores)), "phase2_max_score": float(p2_scores.max()),
            "fit_provenance": gate["fit_provenance"],
        },
        "gates": gates,
        "freeze": {
            "model_file": model_path.name, "model_sha256": file_hash(model_path),
            "support_gate_file": gate_path.name, "support_gate_sha256": file_hash(gate_path),
            "relative_transform_file": transform_path.name, "relative_transform_sha256": transform_sha,
            "candidate_frozen_before_new_external_selection": bool(passed),
            "new_external_holdout_selected": False,
        },
        "training_curves": curves,
    }
    (args.output_dir / "summary.json").write_text(json.dumps(report, indent=2, allow_nan=False) + "\n")
    print(json.dumps({"status": report["status"], "selected_seed": int(selected_key), "selected": selected, "support": report["support_gate"], "gates": gates}, indent=2), flush=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
