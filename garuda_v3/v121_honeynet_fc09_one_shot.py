"""V121 frozen one-shot evaluation on Honeynet FC09 mobile-malware traffic.

The official challenge archive and traffic.pcap are selected and hash-frozen before
packet decode. This runner evaluates only the frozen V120 runtime: V116 packet-trained
history-relative GraphSAGE+LSTM world model, V118 validation-only innovation
calibration, and V120 development-only robust support envelope. External bytes are
never used for fitting/thresholding and no labels are accessed.
"""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path

import numpy as np

from .model import GraphWorldModel
from .ps_complete import FEATURES
from .v101_packet_graph_recovery import (
    HISTORY, HORIZON, WINDOW_SECONDS, MAX_NODES,
    build_sequences, infer_state, persistence_prediction,
)
from .v112_tolerant_ps_complete_runtime import tolerant_packet_service_graphs
from .v115_relative_state_world_model import (
    RELATIVE_SCHEMA, RAW_SCHEMA, apply_transform, inverse_pooled,
)
from .v120_robust_support_envelope import decisions as robust_support_decisions

MODEL_SHA256 = "1c326e66f487f5947f526c68469025ffb3410b6f0e63bfc3ee0e9f72ba81031c"
TRANSFORM_SHA256 = "6d5dee6ce930ed041e9921e5f5d1e8281838eb3799c96f338ed3a9d8a7e37643"
CALIBRATION_SHA256 = "c130d235cfcc59803cc27b29cfe67b6e8245b1b8296f98dd3acfe922d023b701"
ROBUST_SUPPORT_SHA256 = "3218ff33b0ada393b1a6aa16c9d5948a848a2d6648a9f900c07bd9c91c8028c4"
ARCHIVE_SHA256 = "90938c45d4309f9af0ef29cd308e4d201be905998b98778511a04c3bebd81cc3"
PCAP_SHA256 = "712ee23b7b43e12e4e94945e4e1d9ad60b85ee48d3adf78fb9b4ae49dbb262e1"
PCAP_BYTES = 10207674
MIN_SEQUENCES = 32
MIN_SUPPORTED_FRACTION = 0.50
MAX_PACKETS = 2_000_000


class V121ContractError(RuntimeError):
    pass


def file_hash(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for block in iter(lambda: f.read(1024 * 1024), b""):
            h.update(block)
    return h.hexdigest()


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--pcap", required=True, type=Path)
    ap.add_argument("--model", required=True, type=Path)
    ap.add_argument("--relative-transform", required=True, type=Path)
    ap.add_argument("--calibration", required=True, type=Path)
    ap.add_argument("--robust-support-gate", required=True, type=Path)
    ap.add_argument("--prereg", required=True, type=Path)
    ap.add_argument("--acquisition", required=True, type=Path)
    ap.add_argument("--execution-lock", required=True, type=Path)
    ap.add_argument("--output", required=True, type=Path)
    args = ap.parse_args()
    if args.output.exists():
        ap.error("V121 one-shot result already exists and is immutable")

    prereg = json.loads(args.prereg.read_text())
    acq = json.loads(args.acquisition.read_text())
    lock = json.loads(args.execution_lock.read_text())
    if prereg.get("status") != "HASH_FROZEN_ONE_SHOT_ARMED" or prereg.get("evaluation_permitted") is not True:
        raise V121ContractError("V121 preregistration is not armed")
    if acq.get("status") != "HASH_FROZEN_NO_PACKET_DECODE":
        raise V121ContractError("V121 acquisition was not frozen before packet decode")
    if acq.get("packet_records_decoded") is not False or acq.get("model_inference_performed") is not False:
        raise V121ContractError("V121 acquisition boundary violated")
    if acq.get("labels_accessed") is not False:
        raise V121ContractError("V121 acquisition accessed labels")
    if lock.get("status") != "IRREVERSIBLE_PRE_DECODE_LOCK":
        raise V121ContractError("V121 execution lock missing")
    if lock.get("packet_records_decoded_before_lock") is not False or lock.get("model_inference_performed_before_lock") is not False:
        raise V121ContractError("V121 execution-lock boundary violated")

    ext = prereg["external_holdout"]
    if args.pcap.stat().st_size != PCAP_BYTES or file_hash(args.pcap) != PCAP_SHA256:
        raise V121ContractError("Frozen Honeynet traffic.pcap identity mismatch")
    if ext.get("pcap_sha256") != PCAP_SHA256 or int(ext.get("pcap_bytes", -1)) != PCAP_BYTES:
        raise V121ContractError("Preregistered PCAP identity mismatch")
    if acq.get("selected_pcap_sha256") != PCAP_SHA256 or int(acq.get("selected_pcap_bytes", -1)) != PCAP_BYTES:
        raise V121ContractError("Acquisition PCAP identity mismatch")
    if ext.get("archive_sha256") != ARCHIVE_SHA256 or acq.get("archive_sha256") != ARCHIVE_SHA256:
        raise V121ContractError("Archive identity mismatch")

    expected_hashes = {
        "base_model_sha256": MODEL_SHA256,
        "relative_transform_sha256": TRANSFORM_SHA256,
        "innovation_calibration_sha256": CALIBRATION_SHA256,
        "robust_support_gate_sha256": ROBUST_SUPPORT_SHA256,
    }
    paths = {
        "base_model_sha256": args.model,
        "relative_transform_sha256": args.relative_transform,
        "innovation_calibration_sha256": args.calibration,
        "robust_support_gate_sha256": args.robust_support_gate,
    }
    reg = prereg["registered_runtime"]
    for key, expected in expected_hashes.items():
        if file_hash(paths[key]) != expected:
            raise V121ContractError(f"Frozen runtime file hash mismatch: {key}")
        if reg.get(key) != expected or lock.get(key) != expected:
            raise V121ContractError(f"Frozen runtime registered identity mismatch: {key}")

    calibration = json.loads(args.calibration.read_text())
    alpha = float(calibration.get("alpha", -1.0))
    if not (0.0 < alpha <= 1.0):
        raise V121ContractError("Invalid V118 innovation alpha")
    if abs(alpha - float(reg.get("alpha", -2.0))) > 1e-15:
        raise V121ContractError("Preregistered calibration alpha mismatch")
    if calibration.get("external_used_for_fit") is not False or calibration.get("consumed_external_used_for_fit") is not False:
        raise V121ContractError("V118 calibration fit provenance is not external-clean")

    transform = json.loads(args.relative_transform.read_text())
    if transform.get("model_schema") != RELATIVE_SCHEMA or transform.get("raw_schema") != RAW_SCHEMA:
        raise V121ContractError("V116 transform schema mismatch")
    if transform.get("future_information_used_for_transform") is not False:
        raise V121ContractError("V116 transform violates history-only contract")

    robust_gate = json.loads(args.robust_support_gate.read_text())
    if robust_gate.get("schema_version") != "v120-support.2":
        raise V121ContractError("Frozen V120 support schema mismatch")
    provenance = robust_gate.get("fit_provenance", {})
    if provenance.get("phase2_excluded_from_fit") is not True or provenance.get("all_consumed_external_holdouts_excluded_from_fit") is not True:
        raise V121ContractError("V120 robust support provenance is not external-clean")
    if robust_gate.get("required_capability") != "packet_features_present":
        raise V121ContractError("V120 packet capability contract mismatch")

    model, meta = GraphWorldModel.load(args.model)
    if model.schema != RELATIVE_SCHEMA or model.f != len(FEATURES):
        raise V121ContractError("Frozen V116 model schema/feature count mismatch")
    if meta.get("raw_input_schema") != RAW_SCHEMA:
        raise V121ContractError("Frozen V116 raw input schema mismatch")
    if not bool(meta.get("packet_features_trained")) or not bool(meta.get("ps_complete_features_trained")):
        raise V121ContractError("Frozen V116 model is not PS-complete packet trained")
    if list(meta.get("features", [])) != list(FEATURES):
        raise V121ContractError("Frozen V116 feature ordering mismatch")
    if int(meta.get("history", -1)) != HISTORY or int(meta.get("horizon", -1)) != HORIZON:
        raise V121ContractError("Frozen V116 temporal contract mismatch")

    times, raw_x, adj, mask, decoded, audit = tolerant_packet_service_graphs(args.pcap, MAX_PACKETS)
    try:
        sx_raw, sa, sm, target_raw, cutoffs = build_sequences(times, raw_x, adj, mask)
    except Exception as exc:
        raise V121ContractError(f"No valid contiguous V121 sequence: {exc}") from exc

    sx_rel, _, centers = apply_transform(sx_raw, target_raw, sm, transform)
    model_rel = infer_state(model, sx_rel, sa, sm)
    persistence_rel = persistence_prediction(sx_rel, sm)
    model_raw = inverse_pooled(model_rel, centers, transform)
    persistence_raw = inverse_pooled(persistence_rel, centers, transform)
    calibrated_raw = persistence_raw + alpha * (model_raw - persistence_raw)

    base_mse = float(np.mean((model_raw - target_raw) ** 2, dtype=np.float64))
    calibrated_mse = float(np.mean((calibrated_raw - target_raw) ** 2, dtype=np.float64))
    persistence_mse = float(np.mean((persistence_raw - target_raw) ** 2, dtype=np.float64))
    improvement = float((persistence_mse - calibrated_mse) / persistence_mse) if persistence_mse else 0.0
    base_improvement = float((persistence_mse - base_mse) / persistence_mse) if persistence_mse else 0.0

    support_scores, presence, telemetry_ok, supported = robust_support_decisions(robust_gate, sx_rel, sm)
    total_sequences = int(len(supported))
    supported_sequences = int(supported.sum())
    supported_fraction = float(supported_sequences / total_sequences) if total_sequences else 0.0
    telemetry_fraction = float(telemetry_ok.mean()) if len(telemetry_ok) else 0.0

    packet_idx = FEATURES.index("packet_features_present")
    packet_vals = raw_x[:, :, packet_idx][mask > 0]
    enough_sequences = total_sequences >= MIN_SEQUENCES
    enough_support = supported_fraction >= MIN_SUPPORTED_FRACTION
    beats_persistence = calibrated_mse < persistence_mse
    positive_improvement = improvement > 0.0
    finite = bool(np.isfinite([base_mse, calibrated_mse, persistence_mse, improvement, base_improvement]).all())
    passed = bool(enough_sequences and enough_support and beats_persistence and positive_improvement and finite)

    result = {
        "schema_version": "v121.1",
        "status": "PASS" if passed else "FAIL",
        "gate": {
            "minimum_total_sequences": MIN_SEQUENCES,
            "minimum_supported_fraction": MIN_SUPPORTED_FRACTION,
            "requires_calibrated_mse_strictly_less_than_persistence_mse": True,
            "requires_positive_improvement": True,
            "requires_finite_metrics": True,
            "total_sequences_gate_passed": enough_sequences,
            "support_gate_passed": enough_support,
            "persistence_gate_passed": beats_persistence,
            "positive_improvement_gate_passed": positive_improvement,
            "finite_metrics_gate_passed": finite,
            "all_gates_passed": passed,
        },
        "dataset": {
            "name": ext["dataset"],
            "scenario": ext["scenario"],
            "publisher": ext["publisher"],
            "publisher_repository": ext["publisher_repository"],
            "source_page": ext["source_page"],
            "source_url": ext["source_url"],
            "archive_sha256": ARCHIVE_SHA256,
            "pcap_member": ext["pcap_member"],
            "pcap_sha256": PCAP_SHA256,
            "pcap_bytes": PCAP_BYTES,
            "labels_accessed": False,
        },
        "frozen_runtime": {
            "base_model_sha256": MODEL_SHA256,
            "relative_transform_sha256": TRANSFORM_SHA256,
            "innovation_calibration_sha256": CALIBRATION_SHA256,
            "robust_support_gate_sha256": ROBUST_SUPPORT_SHA256,
            "alpha": alpha,
            "raw_schema": RAW_SCHEMA,
            "model_schema": RELATIVE_SCHEMA,
            "feature_count": len(FEATURES),
            "history_windows": HISTORY,
            "forecast_windows": HORIZON,
            "window_seconds": WINDOW_SECONDS,
            "max_nodes": MAX_NODES,
            "adapter_mode": "V112 tolerant packet decoder -> 34-feature PS-complete graph -> V116 history-relative model -> V118 validation-only innovation calibration -> V120 robust support envelope",
        },
        "capture_processing": {
            "decoded_ipv4_packets": int(decoded),
            "packet_limit": MAX_PACKETS,
            "observed_windows": int(len(times)),
            "contiguous_sequences": total_sequences,
            "first_window_epoch": int(times[0]),
            "last_window_epoch": int(times[-1]),
            "cutoff_timestamps_sha256": hashlib.sha256(cutoffs.astype(np.int64).tobytes()).hexdigest(),
            "packet_features_present_mean_on_observed_nodes": float(packet_vals.mean()) if len(packet_vals) else 0.0,
            "parser_audit": audit,
        },
        "state_forecasting": {
            "metric": "raw reconstructed pooled-state MSE",
            "base_v116_model_mse_diagnostic": base_mse,
            "calibrated_v118_mse": calibrated_mse,
            "persistence_mse": persistence_mse,
            "base_v116_improvement_vs_persistence_diagnostic": base_improvement,
            "calibrated_improvement_vs_persistence": improvement,
            "calibrated_beats_persistence": beats_persistence,
        },
        "runtime_support": {
            "method": robust_gate.get("method"),
            "threshold": float(robust_gate["threshold"]),
            "supported_sequences": supported_sequences,
            "total_sequences": total_sequences,
            "supported_fraction": supported_fraction,
            "telemetry_compatible_sequences": int(telemetry_ok.sum()),
            "telemetry_compatible_fraction": telemetry_fraction,
            "required_packet_capability_mean": float(presence[:, 0].mean()) if len(presence) else 0.0,
            "median_exceedance_fraction": float(np.median(support_scores)) if len(support_scores) else 1.0,
            "max_exceedance_fraction": float(np.max(support_scores)) if len(support_scores) else 1.0,
            "interpretation": "training-support diagnostic only; outside support is not attack/OOD detection",
        },
        "one_shot_integrity": {
            "runs_allowed_for_claim": 1,
            "model_inference_performed_once": True,
            "retrained_on_external": False,
            "transform_fit_on_external": False,
            "calibration_fit_on_external": False,
            "support_fit_on_external": False,
            "threshold_fit_on_external": False,
            "labels_accessed": False,
            "rerun_for_claim_improvement": False,
        },
        "claim_boundary": "Fresh publisher-independent external state-transition forecasting only. No attack recall/FPR, MITRE-stage, or successful-compromise warning claim is made."
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(result, indent=2, allow_nan=False) + "\n")
    print(json.dumps(result, indent=2, allow_nan=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
