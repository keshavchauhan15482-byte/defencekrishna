"""V119 frozen one-shot evaluation on Malware-Traffic-Analysis.net FormBook traffic.

The archive and inner PCAP are selected and hash-frozen before packet decode. This
runner evaluates the frozen V118 runtime: V116 packet-trained relative world model,
train/validation-fitted transform/support gate, plus the validation-only persistence-
innovation calibration. External bytes are never used for fitting or thresholding and
no labels are accessed.
"""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path

import numpy as np

from .model import GraphWorldModel
from .ps_complete import FEATURES
from .support_gate import score as support_score
from .v101_packet_graph_recovery import (
    HISTORY, HORIZON, WINDOW_SECONDS, MAX_NODES,
    build_sequences, infer_state, persistence_prediction,
)
from .v112_tolerant_ps_complete_runtime import tolerant_packet_service_graphs
from .v115_relative_state_world_model import (
    RELATIVE_SCHEMA, RAW_SCHEMA, apply_transform, inverse_pooled,
)

MODEL_SHA256 = "1c326e66f487f5947f526c68469025ffb3410b6f0e63bfc3ee0e9f72ba81031c"
SUPPORT_SHA256 = "8a7eb42d73797d59ccb84644b93253f70c5552a7be38b205530cc9fc69044fc5"
TRANSFORM_SHA256 = "6d5dee6ce930ed041e9921e5f5d1e8281838eb3799c96f338ed3a9d8a7e37643"
CALIBRATION_SHA256 = "c130d235cfcc59803cc27b29cfe67b6e8245b1b8296f98dd3acfe922d023b701"
ARCHIVE_SHA256 = "676bf6b5f269a8da49e8da6b6dcb3aed0ca2629f99005dc39f4b887ad9bee822"
PCAP_SHA256 = "0ea6b597732a9ce6af9a7e3adff4512c9a91b4bce27184c8fdeb746f05cce170"
PCAP_BYTES = 16007378
MIN_SEQUENCES = 32
MIN_SUPPORTED_FRACTION = 0.50
MAX_PACKETS = 2_000_000


class V119ContractError(RuntimeError):
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
    ap.add_argument("--support-gate", required=True, type=Path)
    ap.add_argument("--relative-transform", required=True, type=Path)
    ap.add_argument("--calibration", required=True, type=Path)
    ap.add_argument("--prereg", required=True, type=Path)
    ap.add_argument("--acquisition", required=True, type=Path)
    ap.add_argument("--execution-lock", required=True, type=Path)
    ap.add_argument("--output", required=True, type=Path)
    args = ap.parse_args()
    if args.output.exists():
        ap.error("V119 one-shot result already exists and is immutable")

    prereg = json.loads(args.prereg.read_text())
    acq = json.loads(args.acquisition.read_text())
    lock = json.loads(args.execution_lock.read_text())
    if prereg.get("status") != "HASH_FROZEN_ONE_SHOT_ARMED" or prereg.get("evaluation_permitted") is not True:
        raise V119ContractError("V119 preregistration is not armed")
    if acq.get("status") != "HASH_FROZEN_NO_PACKET_DECODE":
        raise V119ContractError("V119 acquisition was not frozen before packet decode")
    if acq.get("packet_records_decoded") is not False or acq.get("model_inference_performed") is not False:
        raise V119ContractError("V119 acquisition boundary violated")
    if acq.get("labels_accessed") is not False:
        raise V119ContractError("V119 acquisition accessed labels")
    if lock.get("status") != "IRREVERSIBLE_PRE_DECODE_LOCK" or lock.get("model_inference_performed_before_lock") is not False:
        raise V119ContractError("V119 execution lock missing or invalid")

    ext = prereg["external_holdout"]
    if args.pcap.stat().st_size != PCAP_BYTES or file_hash(args.pcap) != PCAP_SHA256:
        raise V119ContractError("Frozen MTA FormBook PCAP identity mismatch")
    if ext.get("pcap_sha256") != PCAP_SHA256 or int(ext.get("pcap_bytes", -1)) != PCAP_BYTES:
        raise V119ContractError("Preregistered PCAP identity mismatch")
    if acq.get("selected_pcap_sha256") != PCAP_SHA256 or int(acq.get("selected_pcap_bytes", -1)) != PCAP_BYTES:
        raise V119ContractError("Acquisition PCAP identity mismatch")
    if ext.get("archive_sha256") != ARCHIVE_SHA256 or acq.get("archive_sha256") != ARCHIVE_SHA256:
        raise V119ContractError("Archive identity mismatch")

    if file_hash(args.model) != MODEL_SHA256:
        raise V119ContractError("Frozen V116 model hash mismatch")
    if file_hash(args.support_gate) != SUPPORT_SHA256:
        raise V119ContractError("Frozen V116 support-gate hash mismatch")
    if file_hash(args.relative_transform) != TRANSFORM_SHA256:
        raise V119ContractError("Frozen V116 relative-transform hash mismatch")
    if file_hash(args.calibration) != CALIBRATION_SHA256:
        raise V119ContractError("Frozen V118 calibration hash mismatch")

    reg = prereg["registered_runtime"]
    expected_hashes = {
        "base_model_sha256": MODEL_SHA256,
        "support_gate_sha256": SUPPORT_SHA256,
        "relative_transform_sha256": TRANSFORM_SHA256,
        "innovation_calibration_sha256": CALIBRATION_SHA256,
    }
    for key, expected in expected_hashes.items():
        if reg.get(key) != expected or lock.get(key) != expected:
            raise V119ContractError(f"Frozen runtime identity mismatch: {key}")

    calibration = json.loads(args.calibration.read_text())
    alpha = float(calibration.get("alpha", -1.0))
    if not (0.0 < alpha <= 1.0):
        raise V119ContractError("Invalid V118 innovation alpha")
    if abs(alpha - float(reg.get("alpha", -2.0))) > 1e-15:
        raise V119ContractError("Preregistered calibration alpha mismatch")
    if calibration.get("external_used_for_fit") is not False or calibration.get("consumed_external_used_for_fit") is not False:
        raise V119ContractError("Calibration fit provenance is not external-clean")

    model, meta = GraphWorldModel.load(args.model)
    if model.schema != RELATIVE_SCHEMA or model.f != len(FEATURES):
        raise V119ContractError("Frozen V116 model schema/feature count mismatch")
    if meta.get("raw_input_schema") != RAW_SCHEMA:
        raise V119ContractError("Frozen V116 raw input schema mismatch")
    if not bool(meta.get("packet_features_trained")) or not bool(meta.get("ps_complete_features_trained")):
        raise V119ContractError("Frozen V116 model is not PS-complete packet trained")
    if list(meta.get("features", [])) != list(FEATURES):
        raise V119ContractError("Frozen V116 feature ordering mismatch")
    if int(meta.get("history", -1)) != HISTORY or int(meta.get("horizon", -1)) != HORIZON:
        raise V119ContractError("Frozen V116 temporal contract mismatch")

    transform = json.loads(args.relative_transform.read_text())
    if transform.get("model_schema") != RELATIVE_SCHEMA or transform.get("raw_schema") != RAW_SCHEMA:
        raise V119ContractError("V116 transform schema mismatch")
    if transform.get("future_information_used_for_transform") is not False:
        raise V119ContractError("V116 transform violates history-only contract")

    times, raw_x, adj, mask, decoded, audit = tolerant_packet_service_graphs(args.pcap, MAX_PACKETS)
    try:
        sx_raw, sa, sm, target_raw, cutoffs = build_sequences(times, raw_x, adj, mask)
    except Exception as exc:
        raise V119ContractError(f"No valid contiguous V119 sequence: {exc}") from exc

    sx_rel, target_rel, centers = apply_transform(sx_raw, target_raw, sm, transform)
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

    gate = json.loads(args.support_gate.read_text())
    scores = support_score(gate, sx_rel, sm)
    threshold = float(gate["threshold"])
    supported = scores <= threshold
    total_sequences = int(len(supported))
    supported_sequences = int(supported.sum())
    supported_fraction = float(supported_sequences / total_sequences) if total_sequences else 0.0

    pidx = FEATURES.index("packet_features_present")
    packet_vals = raw_x[:, :, pidx][mask > 0]
    enough_sequences = total_sequences >= MIN_SEQUENCES
    enough_support = supported_fraction >= MIN_SUPPORTED_FRACTION
    beats_persistence = calibrated_mse < persistence_mse
    positive_improvement = improvement > 0.0
    finite = bool(np.isfinite([base_mse, calibrated_mse, persistence_mse, improvement, base_improvement]).all())
    passed = bool(enough_sequences and enough_support and beats_persistence and positive_improvement and finite)

    result = {
        "schema_version": "v119.1",
        "status": "PASS" if passed else "FAIL",
        "gate": {
            "minimum_total_sequences": MIN_SEQUENCES,
            "minimum_supported_fraction": MIN_SUPPORTED_FRACTION,
            "requires_calibrated_mse_strictly_less_than_persistence_mse": True,
            "requires_positive_improvement": True,
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
            "source_url": ext["source_url"],
            "archive_sha256": ARCHIVE_SHA256,
            "pcap_member": ext["pcap_member"],
            "pcap_sha256": PCAP_SHA256,
            "pcap_bytes": PCAP_BYTES,
            "labels_accessed": False,
        },
        "frozen_runtime": {
            "base_model_sha256": MODEL_SHA256,
            "support_gate_sha256": SUPPORT_SHA256,
            "relative_transform_sha256": TRANSFORM_SHA256,
            "innovation_calibration_sha256": CALIBRATION_SHA256,
            "alpha": alpha,
            "raw_schema": RAW_SCHEMA,
            "model_schema": RELATIVE_SCHEMA,
            "feature_count": len(FEATURES),
            "history_windows": HISTORY,
            "forecast_windows": HORIZON,
            "window_seconds": WINDOW_SECONDS,
            "max_nodes": MAX_NODES,
            "adapter_mode": "V112 tolerant packet decoder -> 34-feature PS-complete graph -> V116 history-relative transform -> V118 validation-only innovation calibration",
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
            "method": gate.get("method"),
            "threshold": threshold,
            "supported_sequences": supported_sequences,
            "total_sequences": total_sequences,
            "supported_fraction": supported_fraction,
            "median_score": float(np.median(scores)),
            "max_score": float(np.max(scores)),
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
