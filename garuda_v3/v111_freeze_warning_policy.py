"""Freeze the V111 prediction-only warning policy using development data only.

The policy is intentionally separate from the operational support score and the
untrained risk head. It uses only the frozen V108 model's predicted trajectory versus
same-history persistence, then fixes an upper-tail threshold on CICAPT Phase-2, which
was excluded from V108 candidate selection. No V111 external packet, label, infection
timestamp or outcome enters this calculation.
"""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path

import numpy as np

from .model import GraphWorldModel
from .v101_packet_graph_recovery import (
    PHASE2_NAME,
    PHASE2_SHA256,
    build_sequences,
    infer_state,
    persistence_prediction,
    verify_development_capture,
)
from .v108_ps_complete_graph_recovery import packet_service_graphs

MODEL_SHA256 = "f063ae8c890f9e805c913c02c92b8174cc1d58552514484ea2ef723611258fed"
POLICY_BUDGET = 0.005


class WarningPolicyError(RuntimeError):
    pass


def file_sha256(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for block in iter(lambda: f.read(1024 * 1024), b""):
            h.update(block)
    return h.hexdigest()


def transition_score(predicted: np.ndarray, persistence: np.ndarray) -> np.ndarray:
    predicted = np.asarray(predicted, dtype=np.float64)
    persistence = np.asarray(persistence, dtype=np.float64)
    if predicted.shape != persistence.shape or predicted.ndim != 3:
        raise WarningPolicyError(
            f"prediction/persistence shape mismatch: {predicted.shape} vs {persistence.shape}"
        )
    # Prediction-only future change magnitude. Observed future truth is not used.
    return np.mean(np.abs(predicted - persistence), axis=(1, 2))


def upper_tail_threshold(values: np.ndarray, budget: float = POLICY_BUDGET) -> float:
    x = np.sort(np.asarray(values, dtype=np.float64))
    if len(x) < 100:
        raise WarningPolicyError(f"policy reference too small: {len(x)}")
    if not 0.0 < float(budget) < 1.0:
        raise WarningPolicyError("budget must be in (0,1)")
    q = 1.0 - float(budget)
    # Same higher empirical-quantile rule used by the audited V72/V93 warning policy.
    idx = int(np.ceil(q * len(x)) - 1)
    idx = max(0, min(idx, len(x) - 1))
    return float(x[idx])


def freeze_policy(phase2: Path, model_path: Path, output: Path, packet_limit: int, batch_size: int) -> dict:
    phase2_sha = verify_development_capture(phase2, PHASE2_NAME, PHASE2_SHA256)
    if file_sha256(model_path) != MODEL_SHA256:
        raise WarningPolicyError("frozen V108 model SHA-256 mismatch")

    model, metadata = GraphWorldModel.load(model_path)
    if metadata.get("ps_complete_features_trained") is not True:
        raise WarningPolicyError("V111 requires the V108 PS-complete trained candidate")
    if metadata.get("evaluation_scope") != "development_reused_cross_phase":
        raise WarningPolicyError("unexpected V108 metadata evaluation scope")

    times, x, adj, mask, decoded = packet_service_graphs(phase2, packet_limit)
    sx, sa, sm, _future, cutoffs = build_sequences(times, x, adj, mask)
    predicted = infer_state(model, sx, sa, sm, batch_size=batch_size)
    persistence = persistence_prediction(sx, sm)
    scores = transition_score(predicted, persistence)
    threshold = upper_tail_threshold(scores, POLICY_BUDGET)
    exceed = scores > threshold

    report = {
        "schema_version": "v111-warning-policy.1",
        "status": "DEV_ONLY_WARNING_POLICY_FROZEN",
        "claim_boundary": (
            "Prediction-warning policy frozen solely from reused CICAPT development Phase-2. "
            "It is not a certified benign FPR, attack detector, operational support score, or "
            "successful-compromise result. No V111 external packet/timestamp/label/outcome is used."
        ),
        "model": {
            "file": str(model_path),
            "sha256": MODEL_SHA256,
            "schema": metadata.get("schema"),
            "feature_count": len(metadata.get("features", [])),
            "packet_features_trained": bool(metadata.get("packet_features_trained")),
            "ps_complete_features_trained": bool(metadata.get("ps_complete_features_trained")),
        },
        "reference": {
            "dataset": "CICAPT-IIoT2024",
            "capture": PHASE2_NAME,
            "capture_sha256": phase2_sha,
            "development_reuse": True,
            "used_for_v108_candidate_selection": False,
            "decoded_ipv4_packets": int(decoded),
            "observed_windows": int(len(times)),
            "contiguous_sequences": int(len(sx)),
            "cutoff_timestamps_sha256": hashlib.sha256(
                np.asarray(cutoffs, dtype=np.int64).tobytes()
            ).hexdigest(),
        },
        "score": {
            "name": "predicted_transition_magnitude_vs_persistence",
            "definition": "mean(abs(frozen_model_predicted_future_state - same_history_persistence), axes=(horizon,features))",
            "prediction_only": True,
            "observed_future_ground_truth_used": False,
            "support_score_used": False,
            "risk_head_used": False,
        },
        "threshold": {
            "method": "higher empirical upper-tail quantile",
            "reference_tail_budget": POLICY_BUDGET,
            "value": float(threshold),
            "reference_alerts": int(exceed.sum()),
            "reference_sequences": int(len(scores)),
            "reference_alert_fraction": float(exceed.mean()),
            "minimum_score": float(scores.min()),
            "median_score": float(np.median(scores)),
            "maximum_score": float(scores.max()),
        },
        "leakage_contract": {
            "v111_external_packet_used": False,
            "v111_external_label_used": False,
            "v111_publisher_infection_timestamp_used": False,
            "v111_outcome_used": False,
            "consumed_external_holdouts_used": False,
            "threshold_refit_on_external_permitted": False,
        },
    }
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(report, indent=2, sort_keys=True, allow_nan=False) + "\n")
    return report


def main() -> int:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--phase2", required=True, type=Path)
    p.add_argument("--model", required=True, type=Path)
    p.add_argument("--output", required=True, type=Path)
    p.add_argument("--packet-limit", type=int, default=2_000_000)
    p.add_argument("--batch-size", type=int, default=64)
    args = p.parse_args()
    report = freeze_policy(args.phase2, args.model, args.output, args.packet_limit, args.batch_size)
    print(json.dumps(report, indent=2, allow_nan=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
