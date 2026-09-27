"""V100 audit for the consumed V99 HIKARI external one-shot.

This module does not rerun or reinterpret the HIKARI holdout.  It consumes the
immutable V99 result and records what can be established from already-recorded
training/runtime provenance.  In particular it checks whether a feature-
availability mismatch is sufficient to force every HIKARI sequence outside the
V95 runtime support gate.

The output is a recovery audit, not a new performance result.  HIKARI remains a
consumed holdout and must not be used for retraining, normalization, threshold
selection, support fitting, adapter tuning, or model selection.
"""
from __future__ import annotations

import argparse
import json
import math
from pathlib import Path
from typing import Any, Dict


class AuditError(RuntimeError):
    """Raised when the recorded evidence no longer satisfies the V100 contract."""


def _require(condition: bool, message: str) -> None:
    if not condition:
        raise AuditError(message)


def _load(path: Path) -> Dict[str, Any]:
    value = json.loads(path.read_text(encoding="utf-8"))
    _require(isinstance(value, dict), f"{path} must contain a JSON object")
    return value


def build_audit(
    v99: Dict[str, Any],
    metrics: Dict[str, Any],
    support_gate: Dict[str, Any],
    v97: Dict[str, Any],
    v98: Dict[str, Any],
) -> Dict[str, Any]:
    """Build the deterministic V100 recovery audit from frozen evidence."""
    _require(v99.get("schema_version") == "v99.1", "unexpected V99 schema")
    _require(v99.get("status") == "FAIL", "V99 first one-shot result must remain FAIL")
    _require(v99.get("dataset", {}).get("name") == "HIKARI-2021", "unexpected V99 dataset")
    _require(
        v99.get("one_shot_integrity", {}).get("rerun_for_better_metrics") is False,
        "V99 one-shot integrity changed",
    )
    _require(
        v99.get("one_shot_integrity", {}).get("retrained_on_hikari") is False,
        "V99 must remain free of HIKARI retraining",
    )
    _require(metrics.get("schema") == "garuda-observed-graph-v3.1", "unexpected training schema")
    _require(v97.get("declared_status") == "SHADOW_UNRESOLVED", "V97 status changed")
    _require(v98.get("declared_status") == "SHADOW_UNRESOLVED", "V98 status changed")

    sources = metrics.get("sources") or []
    _require(sources, "training metrics contain no source provenance")
    source_packet_flags = [bool(source.get("packet_features", False)) for source in sources]
    _require(not any(source_packet_flags), "V100 diagnosis assumes the frozen V99 model was not packet-feature trained")

    adapter = v99.get("adapter") or {}
    features = adapter.get("features") or []
    _require("packet_features_present" in features, "V99 adapter lacks packet feature availability flag")
    packet_index = features.index("packet_features_present")
    packet_mean = float(adapter.get("packet_features_present_mean_on_observed_nodes", 0.0))

    center = support_gate.get("center") or []
    scale = support_gate.get("scale") or []
    _require(packet_index < len(center) and packet_index < len(scale), "support gate is incompatible with V99 feature order")
    packet_center = float(center[packet_index])
    packet_scale = float(scale[packet_index])
    _require(packet_scale > 0.0, "support scale must be positive")
    packet_z = abs(packet_mean - packet_center) / packet_scale
    threshold = float(support_gate["threshold"])

    runtime_support = v99.get("runtime_support") or {}
    total_sequences = int(runtime_support.get("total_sequences", 0))
    supported_sequences = int(runtime_support.get("supported_sequences", -1))
    median_support = float(runtime_support.get("median_support_score", float("nan")))
    max_support = float(runtime_support.get("max_support_score", float("nan")))
    _require(total_sequences > 0, "V99 recorded no compatible sequences")
    _require(supported_sequences == 0, "V99 support result changed")
    _require(math.isfinite(median_support) and math.isfinite(max_support), "invalid V99 support scores")

    packet_flag_alone_exceeds_gate = packet_z > threshold
    packet_flag_matches_recorded_support = math.isclose(packet_z, median_support, rel_tol=1e-6, abs_tol=1e-4)
    _require(packet_flag_alone_exceeds_gate, "packet availability shift no longer explains outside-support status")
    _require(
        packet_flag_matches_recorded_support,
        "recorded median support score no longer matches packet-availability deviation",
    )

    state = v99.get("state_forecasting") or {}
    model_mse = float(state["model_mse"])
    persistence_mse = float(state["persistence_mse"])
    improvement = float(state["improvement_vs_persistence"])
    _require(model_mse >= persistence_mse, "V99 state gate is no longer the recorded failure")
    _require(state.get("beats_persistence") is False, "V99 persistence verdict changed")

    capture_sha256 = str(v99["dataset"]["sha256"])
    capture_name = str(v99["dataset"]["capture"])

    return {
        "schema_version": "v100.1",
        "status": "RECOVERY_REQUIRED",
        "source_result": {
            "schema_version": v99["schema_version"],
            "status": v99["status"],
            "dataset": "HIKARI-2021",
            "capture": capture_name,
            "capture_sha256": capture_sha256,
            "consumed_external_holdout": True,
            "rerun_permitted_for_claim_improvement": False,
        },
        "state_forecasting": {
            "model_mse": model_mse,
            "persistence_mse": persistence_mse,
            "improvement_vs_persistence": improvement,
            "gate_passed": False,
        },
        "support_diagnosis": {
            "training_sources_packet_features": source_packet_flags,
            "frozen_checkpoint_packet_features_trained": bool(
                v99.get("frozen_runtime", {}).get("checkpoint_packet_features_trained", False)
            ),
            "external_packet_features_present_mean": packet_mean,
            "packet_features_present_feature_index": packet_index,
            "train_support_center": packet_center,
            "train_support_scale": packet_scale,
            "packet_presence_standardized_deviation": packet_z,
            "support_threshold": threshold,
            "recorded_supported_sequences": supported_sequences,
            "recorded_total_sequences": total_sequences,
            "recorded_median_support_score": median_support,
            "recorded_max_support_score": max_support,
            "packet_availability_shift_alone_exceeds_support_threshold": packet_flag_alone_exceeds_gate,
            "packet_availability_shift_matches_recorded_median_score": packet_flag_matches_recorded_support,
            "interpretation": (
                "The frozen model was trained on sources marked packet_features=false, while the V99 raw-PCAP adapter "
                "presented packet_features_present=1 on observed nodes. Under the max-standardized-deviation support "
                "gate, this single availability feature is sufficient to force the HIKARI histories outside training "
                "support. This is a feature-contract/generalisation diagnosis, not attack or OOD detection, and it does "
                "not erase the failed persistence comparison."
            ),
        },
        "other_open_evidence_gates": {
            "v97_stage_packet_evidence": v97["declared_status"],
            "v98_verified_precompromise": v98["declared_status"],
        },
        "holdout_quarantine": {
            "dataset": "HIKARI-2021",
            "capture_sha256": capture_sha256,
            "prohibited_for_future_claim_fitting": [
                "model training or fine-tuning",
                "normalization fitting",
                "risk-threshold fitting",
                "support center/scale fitting",
                "support-threshold selection",
                "adapter/feature mapping selection",
                "checkpoint or hyperparameter selection",
            ],
            "note": (
                "The recorded HIKARI capture may be retained for postmortem analysis, but any candidate changed after "
                "observing V99 needs a different untouched external holdout for a fresh generalisation claim."
            ),
        },
        "recovery_contract": {
            "before_next_external_one_shot": [
                "Build and hash-pin packet-compatible development/training evidence without using HIKARI for fitting.",
                "Fit support center/scale on training only and support threshold on validation only.",
                "Demonstrate the frozen candidate beats persistence on its non-external development validation protocol.",
                "Freeze model, adapter contract, normalization, support gate, thresholds, and their hashes before external observation.",
                "Select and preregister a genuinely untouched external dataset/campaign that was not used to design the post-V99 candidate.",
                "Run that external holdout once and record PASS/FAIL without retuning or rerunning for a better metric.",
            ],
            "precompromise_gate": (
                "V98 remains separate: a verified pre-compromise claim still requires an objective successful-compromise "
                "timestamp paired with an earlier model-emitted warning for the same provenance-disjoint campaign."
            ),
            "stage_packet_gate": (
                "V97 remains separate: five-stage supervised evidence and artifact-backed packet-feature consumption are "
                "not certified by V99/V100."
            ),
        },
        "claim_boundary": (
            "V100 certifies only the integrity-preserving diagnosis and recovery constraints for the already-consumed "
            "V99 external run. It does not convert V99 to PASS and does not certify fresh external generalisation, "
            "five-stage MITRE accuracy, attack recall/FPR, or warning before successful compromise."
        ),
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--v99", type=Path, required=True)
    parser.add_argument("--metrics", type=Path, required=True)
    parser.add_argument("--support-gate", type=Path, required=True)
    parser.add_argument("--v97", type=Path, required=True)
    parser.add_argument("--v98", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()

    report = build_audit(
        _load(args.v99),
        _load(args.metrics),
        _load(args.support_gate),
        _load(args.v97),
        _load(args.v98),
    )
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report, indent=2, allow_nan=False) + "\n", encoding="utf-8")
    print(json.dumps(report, indent=2, allow_nan=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
