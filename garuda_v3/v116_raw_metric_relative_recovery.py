"""V116 development-only raw-metric-aligned relative PS-complete recovery.

V115 showed that history-relative coordinates improve support coverage and raw
reconstructed forecasting, but its unweighted normalized objective can overweight
small-scale coordinates. V116 keeps the same history-only relative representation
and 34-feature SIH packet/flow contract, while weighting normalized-coordinate
squared error by the square of the frozen train-only transform scale. Up to one
constant factor this is the raw reconstructed-state MSE used by external gates.

No consumed external holdout is used for fitting, selection, normalization,
support fitting, threshold fitting, or adapter design. Phase-1 CICAPT supplies
train/validation; Phase-2 CICAPT is reused development sanity only.
"""
from __future__ import annotations

import argparse
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
    build_sequences, chronological_phase1_split, infer_state, mse,
)
from .v112_tolerant_ps_complete_runtime import tolerant_packet_service_graphs
from .v115_relative_state_world_model import (
    RELATIVE_SCHEMA, RAW_SCHEMA, RELATIVE_FEATURES, PRESENCE_FEATURES,
    fit_transform, apply_transform, normalized_and_raw_metrics,
)


def raw_metric_weights(transform: dict) -> np.ndarray:
    scale = np.asarray(transform["scale"], dtype=np.float32)
    weights = scale * scale
    mean = float(np.mean(weights))
    if not np.isfinite(weights).all() or mean <= 0.0:
        raise RecoveryContractError("Invalid V116 raw-metric weights")
    return (weights / mean).astype(np.float32)


def raw_metric_objective(model, x, adj, mask, target, weights):
    mean, sigma, _ = model.forward(x, adj, mask, HORIZON)
    error = mean - target
    w = weights.reshape(1, 1, -1)
    weighted_mse = (error.power(2) * w).mean()
    nll = ((error / sigma).power(2) * 0.5 + sigma.log()).mean()
    return 10.0 * weighted_mse + 0.01 * nll


def train_seed(train_arrays, valid_arrays, valid_raw_target, valid_center, transform,
               seed: int, epochs: int, batch_size: int):
    tx, ta, tm, ty = train_arrays
    vx, va, vm, vy = valid_arrays
    weights = raw_metric_weights(transform)
    model = GraphWorldModel(
        architecture="gnn_lstm", feature_dim=len(FEATURES), seed=int(seed),
        decoder="residual", stage_count=0, schema=RELATIVE_SCHEMA,
    )
    optimizer = Adam(model.parameters(), lr=0.003)
    rng = np.random.default_rng(seed)

    initial = normalized_and_raw_metrics(
        model, valid_arrays, valid_raw_target, valid_center, transform, batch_size
    )
    best = float(initial["raw_reconstructed_model_mse"])
    best_epoch = 0
    best_weights = {k: v.data.copy() for k, v in model.params.items()}
    curve = [{"epoch": 0, "train_objective": None, "validation_raw_mse": best}]

    for epoch in range(epochs):
        order = rng.permutation(len(tx)); losses = []
        for offset in range(0, len(order), batch_size):
            ids = order[offset:offset + batch_size]
            objective = raw_metric_objective(
                model, tx[ids], ta[ids], tm[ids], ty[ids], weights
            )
            objective.backward(); optimizer.step(); losses.append(float(objective.data))
        metrics = normalized_and_raw_metrics(
            model, valid_arrays, valid_raw_target, valid_center, transform, batch_size
        )
        raw_val = float(metrics["raw_reconstructed_model_mse"])
        curve.append({
            "epoch": epoch + 1,
            "train_objective": float(np.mean(losses)),
            "validation_raw_mse": raw_val,
            "validation_normalized_mse": float(metrics["normalized_model_mse"]),
        })
        if raw_val < best:
            best = raw_val; best_epoch = epoch + 1
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

    if len(FEATURES) != 34 or len(RELATIVE_FEATURES) != 29 or len(PRESENCE_FEATURES) != 5:
        raise RecoveryContractError("V116 requires the V115 34-feature relative contract")
    if len(set(args.seeds)) < 3:
        p.error("At least three distinct seeds are required")
    if args.packet_limit < 100_000:
        p.error("packet-limit must be at least 100000")

    phase1_sha = verify_development_capture(args.phase1, PHASE1_NAME, PHASE1_SHA256)
    phase2_sha = verify_development_capture(args.phase2, PHASE2_NAME, PHASE2_SHA256)
    t1, x1, a1, m1, n1, audit1 = tolerant_packet_service_graphs(args.phase1, args.packet_limit)
    t2, x2, a2, m2, n2, audit2 = tolerant_packet_service_graphs(args.phase2, args.packet_limit)
    sx1, sa1, sm1, sy1_raw, _ = build_sequences(t1, x1, a1, m1)
    sx2, sa2, sm2, sy2_raw, _ = build_sequences(t2, x2, a2, m2)
    train_ids, valid_ids = chronological_phase1_split(len(sx1))

    transform = fit_transform(sx1[train_ids], sm1[train_ids])
    nx1, ny1, centers1 = apply_transform(sx1, sy1_raw, sm1, transform)
    nx2, ny2, centers2 = apply_transform(sx2, sy2_raw, sm2, transform)
    train = (nx1[train_ids], sa1[train_ids], sm1[train_ids], ny1[train_ids])
    valid = (nx1[valid_ids], sa1[valid_ids], sm1[valid_ids], ny1[valid_ids])
    phase2 = (nx2, sa2, sm2, ny2)

    rows = {}; models = {}; curves = {}
    for seed in args.seeds:
        print(f"V116 training seed={seed}", flush=True)
        model, epoch, curve = train_seed(
            train, valid, sy1_raw[valid_ids], centers1[valid_ids], transform,
            int(seed), args.epochs, args.batch_size,
        )
        vm = normalized_and_raw_metrics(
            model, valid, sy1_raw[valid_ids], centers1[valid_ids], transform, args.batch_size
        )
        pm = normalized_and_raw_metrics(
            model, phase2, sy2_raw, centers2, transform, args.batch_size
        )
        rows[str(seed)] = {"seed": int(seed), "best_epoch": epoch, "validation": vm, "phase2": pm}
        models[str(seed)] = model; curves[str(seed)] = curve
        print(json.dumps(rows[str(seed)], indent=2), flush=True)

    selected_key = min(
        rows,
        key=lambda k: (rows[k]["validation"]["raw_reconstructed_model_mse"], int(k)),
    )
    selected = rows[selected_key]; model = models[selected_key]

    gate = fit_support_gate(train[0], train[2], valid[0], valid[2])
    gate["fit_provenance"] = {
        "center_scale": "history-relative CICAPT Phase-1 train only",
        "threshold": "history-relative CICAPT Phase-1 validation only",
        "phase2_excluded_from_fit": True,
        "all_consumed_external_holdouts_excluded_from_fit": True,
    }
    p2_scores = support_score(gate, phase2[0], phase2[2])
    p2_supported = p2_scores <= float(gate["threshold"])
    p2_support_fraction = float(p2_supported.mean())

    gates = {
        "validation_raw_reconstructed_beats_persistence": bool(selected["validation"]["raw_beats_persistence"]),
        "phase2_raw_reconstructed_beats_persistence": bool(selected["phase2"]["raw_beats_persistence"]),
        "phase2_supported_fraction_at_least_0_95": bool(p2_support_fraction >= 0.95),
        "validation_metrics_finite": bool(np.isfinite(selected["validation"]["normalized_model_mse"])),
        "phase2_metrics_finite": bool(np.isfinite(selected["phase2"]["normalized_model_mse"])),
    }
    passed = all(gates.values())

    args.output_dir.mkdir(parents=True, exist_ok=True)
    model_path = args.output_dir / "gnn_lstm_raw_metric_relative_candidate.npz"
    gate_path = args.output_dir / "support_gate.json"
    transform_path = args.output_dir / "relative_transform.json"
    transform_path.write_text(json.dumps(transform, indent=2, allow_nan=False) + "\n")
    gate_path.write_text(json.dumps(gate, indent=2, allow_nan=False) + "\n")
    transform_sha = file_hash(transform_path)
    raw_weights = raw_metric_weights(transform)

    metadata = {
        "schema": RELATIVE_SCHEMA,
        "raw_input_schema": RAW_SCHEMA,
        "features": list(FEATURES),
        "architecture": "gnn_lstm", "history": HISTORY, "horizon": HORIZON,
        "mode": "service", "max_nodes": MAX_NODES, "window_seconds": WINDOW_SECONDS,
        "seed": int(selected_key), "decoder": "residual", "trained": True,
        "packet_features_trained": True, "ps_complete_features_trained": True,
        "history_relative_state": True, "relative_transform_sha256": transform_sha,
        "training_objective": "raw-reconstructed-MSE-aligned weighted relative error",
        "risk_head_trained": False, "stage_supervised": False,
        "evaluation_scope": "development_reused_cross_phase",
        "consumed_external_used_for_fitting": False,
        "claim_boundary": "Development-only raw-metric-aligned state-transition candidate; no external/stage/precompromise claim.",
    }
    model.save(model_path, metadata)

    objective_contract = {
        "representation": RELATIVE_SCHEMA,
        "raw_metric": "mean squared error after inverse history-relative transform",
        "training_equivalence": "relative squared error weighted by train-only transform scale squared; normalized by a constant mean weight",
        "weight_source": "CICAPT Phase-1 train-only transform",
        "weights_sha256": canonical_sha256({"weights": raw_weights.tolist()}),
        "future_information_used": False,
        "external_statistics_used": False,
        "selection_metric": "Phase-1 validation raw reconstructed MSE",
        "phase2_used_for_selection": False,
    }

    report = {
        "schema_version": "v116.1",
        "status": "DEV_RAW_METRIC_RELATIVE_PASS" if passed else "DEV_RAW_METRIC_RELATIVE_FAIL",
        "recovery_gate_passed": passed,
        "claim_boundary": "Development-only objective alignment recovery. All consumed external holdouts remain quarantined; no fresh external, MITRE-stage, risk, or successful-compromise claim is created.",
        "v115_diagnostic": {
            "status": "DEV_RELATIVE_STATE_FAIL",
            "reason": "V115 raw reconstructed Phase-2 metric beat persistence but normalized-space Phase-2 diagnostic did not; V116 preregisters the deployment raw-state metric as the training/selection target.",
            "external_failures_used_for_fitting": False,
        },
        "development_sources": {
            "dataset": "CICAPT-IIoT2024", "development_reuse": True,
            "phase1": {"capture": PHASE1_NAME, "sha256": phase1_sha, "decoded_ipv4_packets": int(n1), "parser_audit": audit1, "sequences": int(len(sx1)), "train_sequences": int(len(train_ids)), "validation_sequences": int(len(valid_ids)), "embargo_sequences": EMBARGO_SEQUENCES},
            "phase2": {"capture": PHASE2_NAME, "sha256": phase2_sha, "decoded_ipv4_packets": int(n2), "parser_audit": audit2, "sequences": int(len(sx2)), "used_for_selection": False},
        },
        "objective_contract": objective_contract,
        "selection": {
            "rule": "minimum Phase-1 validation raw reconstructed MSE only; ties by seed",
            "selected_seed": int(selected_key),
            "phase2_used_for_selection": False,
            "external_used_for_selection": False,
        },
        "seeds": rows,
        "selected_candidate": selected,
        "support_gate": {
            "method": gate["method"],
            "threshold": float(gate["threshold"]),
            "phase2_supported_sequences": int(p2_supported.sum()),
            "phase2_total_sequences": int(len(p2_supported)),
            "phase2_supported_fraction": p2_support_fraction,
            "phase2_median_score": float(np.median(p2_scores)),
            "phase2_max_score": float(np.max(p2_scores)),
            "fit_provenance": gate["fit_provenance"],
        },
        "gates": gates,
        "freeze": {
            "model_file": model_path.name,
            "model_sha256": file_hash(model_path),
            "support_gate_file": gate_path.name,
            "support_gate_sha256": file_hash(gate_path),
            "relative_transform_file": transform_path.name,
            "relative_transform_sha256": transform_sha,
            "candidate_frozen_before_new_external_selection": bool(passed),
            "new_external_holdout_selected": False,
        },
        "training_curves": curves,
    }
    (args.output_dir / "summary.json").write_text(json.dumps(report, indent=2, allow_nan=False) + "\n")
    print(json.dumps({"status": report["status"], "selected": selected, "gates": gates}, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
