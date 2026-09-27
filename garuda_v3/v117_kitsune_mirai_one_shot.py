"""V117 frozen one-shot evaluation on the original Kitsune Mirai demo capture.

The external archive/member hashes are frozen before packet decode. This runner uses
only the frozen V116 model, train/validation-fitted relative transform and support
gate. No labels are accessed and no external statistic is fit.
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
PCAP_SHA256 = "da69165a7b47353de854e82b3e8c88741383bf94099db2aeaac35d27c7c921fe"
PCAP_BYTES = 62859800
MIN_SEQUENCES = 32
MIN_SUPPORTED_FRACTION = 0.50
MAX_PACKETS = 2_000_000


class V117ContractError(RuntimeError):
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
    ap.add_argument("--prereg", required=True, type=Path)
    ap.add_argument("--acquisition", required=True, type=Path)
    ap.add_argument("--output", required=True, type=Path)
    args = ap.parse_args()
    if args.output.exists():
        ap.error("V117 one-shot result already exists and is immutable")

    prereg = json.loads(args.prereg.read_text())
    acq = json.loads(args.acquisition.read_text())
    if prereg.get("status") != "HASH_FROZEN_ONE_SHOT_ARMED" or prereg.get("evaluation_permitted") is not True:
        raise V117ContractError("V117 preregistration is not armed")
    if acq.get("status") != "HASH_FROZEN_NO_PACKET_DECODE":
        raise V117ContractError("V117 acquisition was not frozen before packet decode")
    if acq.get("packet_records_decoded") is not False or acq.get("model_inference_performed") is not False:
        raise V117ContractError("V117 acquisition boundary violated")
    if acq.get("labels_accessed") is not False:
        raise V117ContractError("V117 acquisition accessed labels")

    ext = prereg["external_holdout"]
    if args.pcap.stat().st_size != PCAP_BYTES or file_hash(args.pcap) != PCAP_SHA256:
        raise V117ContractError("Frozen Kitsune Mirai PCAP identity mismatch")
    if ext.get("pcap_sha256") != PCAP_SHA256 or int(acq.get("selected_pcap_uncompressed_bytes", -1)) != PCAP_BYTES:
        raise V117ContractError("Preregistered/acquisition PCAP identity mismatch")
    if file_hash(args.model) != MODEL_SHA256:
        raise V117ContractError("Frozen V116 model hash mismatch")
    if file_hash(args.support_gate) != SUPPORT_SHA256:
        raise V117ContractError("Frozen V116 support-gate hash mismatch")
    if file_hash(args.relative_transform) != TRANSFORM_SHA256:
        raise V117ContractError("Frozen V116 relative-transform hash mismatch")

    reg = prereg["registered_candidate"]
    if reg.get("model_sha256") != MODEL_SHA256 or reg.get("support_gate_sha256") != SUPPORT_SHA256:
        raise V117ContractError("Preregistered V116 candidate identity mismatch")
    if reg.get("relative_transform_sha256") != TRANSFORM_SHA256:
        raise V117ContractError("Preregistered V116 transform identity mismatch")

    model, meta = GraphWorldModel.load(args.model)
    if model.schema != RELATIVE_SCHEMA or model.f != len(FEATURES):
        raise V117ContractError("Frozen V116 model schema/feature count mismatch")
    if meta.get("raw_input_schema") != RAW_SCHEMA:
        raise V117ContractError("Frozen V116 raw input schema mismatch")
    if not bool(meta.get("packet_features_trained")) or not bool(meta.get("ps_complete_features_trained")):
        raise V117ContractError("Frozen V116 model is not PS-complete packet trained")
    if list(meta.get("features", [])) != list(FEATURES):
        raise V117ContractError("Frozen V116 feature ordering mismatch")
    if int(meta.get("history", -1)) != HISTORY or int(meta.get("horizon", -1)) != HORIZON:
        raise V117ContractError("Frozen V116 temporal contract mismatch")

    transform = json.loads(args.relative_transform.read_text())
    if transform.get("model_schema") != RELATIVE_SCHEMA or transform.get("raw_schema") != RAW_SCHEMA:
        raise V117ContractError("V116 transform schema mismatch")
    if transform.get("future_information_used_for_transform") is not False:
        raise V117ContractError("V116 transform violates history-only contract")

    times, raw_x, adj, mask, decoded, audit = tolerant_packet_service_graphs(args.pcap, MAX_PACKETS)
    try:
        sx_raw, sa, sm, target_raw, cutoffs = build_sequences(times, raw_x, adj, mask)
    except Exception as exc:
        raise V117ContractError(f"No valid contiguous V117 sequence: {exc}") from exc

    sx_rel, target_rel, centers = apply_transform(sx_raw, target_raw, sm, transform)
    model_rel = infer_state(model, sx_rel, sa, sm)
    persistence_rel = persistence_prediction(sx_rel, sm)
    model_raw = inverse_pooled(model_rel, centers, transform)
    persistence_raw = inverse_pooled(persistence_rel, centers, transform)
    model_mse = float(np.mean((model_raw - target_raw) ** 2, dtype=np.float64))
    persistence_mse = float(np.mean((persistence_raw - target_raw) ** 2, dtype=np.float64))
    improvement = float((persistence_mse - model_mse) / persistence_mse) if persistence_mse else 0.0

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
    beats_persistence = model_mse < persistence_mse
    positive_improvement = improvement > 0.0
    passed = bool(enough_sequences and enough_support and beats_persistence and positive_improvement)

    result = {
        "schema_version": "v117.1",
        "status": "PASS" if passed else "FAIL",
        "gate": {
            "minimum_total_sequences": MIN_SEQUENCES,
            "minimum_supported_fraction": MIN_SUPPORTED_FRACTION,
            "requires_raw_model_mse_strictly_less_than_raw_persistence_mse": True,
            "requires_raw_improvement_strictly_greater_than_zero": True,
            "total_sequences_gate_passed": enough_sequences,
            "support_gate_passed": enough_support,
            "persistence_gate_passed": beats_persistence,
            "positive_improvement_gate_passed": positive_improvement,
            "all_gates_passed": passed,
        },
        "dataset": {
            "name": ext["dataset"],
            "scenario": ext["scenario"],
            "publisher_repository": ext["publisher_repository"],
            "publisher_commit_sha": ext["publisher_commit_sha"],
            "archive_sha256": ext["archive_sha256"],
            "pcap_member": ext["pcap_member"],
            "pcap_sha256": PCAP_SHA256,
            "pcap_bytes": PCAP_BYTES,
            "labels_accessed": False,
        },
        "frozen_runtime": {
            "model_sha256": MODEL_SHA256,
            "support_gate_sha256": SUPPORT_SHA256,
            "relative_transform_sha256": TRANSFORM_SHA256,
            "raw_schema": RAW_SCHEMA,
            "model_schema": RELATIVE_SCHEMA,
            "feature_count": len(FEATURES),
            "history_windows": HISTORY,
            "forecast_windows": HORIZON,
            "window_seconds": WINDOW_SECONDS,
            "max_nodes": MAX_NODES,
            "adapter_mode": "V112 tolerant packet decoder -> 34-feature PS-complete graph -> V116 history-relative transform",
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
            "model_mse": model_mse,
            "persistence_mse": persistence_mse,
            "improvement_vs_persistence": improvement,
            "beats_persistence": beats_persistence,
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
            "retrained_on_external": False,
            "transform_fit_on_external": False,
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
