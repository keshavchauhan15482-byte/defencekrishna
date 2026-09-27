"""V111 frozen one-shot CTU-Malware-Capture-Botnet-327-1 evaluation.

The external capture is selected before acquisition, hash-frozen before packet decode,
and scored once with the unchanged V108 34-feature PS-complete GraphSAGE+LSTM model
and V108 support gate. No labels are read or required.
"""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path

import numpy as np

from .model import GraphWorldModel
from .ps_complete import FEATURES, SCHEMA
from .support_gate import score as support_score
from .v101_packet_graph_recovery import (
    HISTORY, HORIZON, WINDOW_SECONDS, MAX_NODES,
    build_sequences, infer_state, persistence_prediction,
)
from .v108_ps_complete_graph_recovery import packet_service_graphs

MODEL_SHA256 = "f063ae8c890f9e805c913c02c92b8174cc1d58552514484ea2ef723611258fed"
SUPPORT_SHA256 = "7006671148e0dba3be55a2fe27a2fd17d3a7ece030dbcddd599c7aaa7f5368c1"
ADAPTER_SHA256 = "2cc3aff90c525e29fc37e1fe5364913afd2180b747fb6d675a4d0d856a6a2173"
MIN_SEQUENCES = 32
MIN_SUPPORTED_FRACTION = 0.5
MAX_PACKETS = 2_000_000


class V111ContractError(RuntimeError):
    pass


def file_hash(path: Path, algorithm: str = "sha256") -> str:
    h = hashlib.new(algorithm)
    with path.open("rb") as f:
        for block in iter(lambda: f.read(1024 * 1024), b""):
            h.update(block)
    return h.hexdigest()


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--pcap", required=True, type=Path)
    ap.add_argument("--model", required=True, type=Path)
    ap.add_argument("--support-gate", required=True, type=Path)
    ap.add_argument("--prereg", required=True, type=Path)
    ap.add_argument("--acquisition", required=True, type=Path)
    ap.add_argument("--output", required=True, type=Path)
    args = ap.parse_args()

    if args.output.exists():
        ap.error("V111 one-shot result already exists and is immutable")

    prereg = json.loads(args.prereg.read_text())
    acq = json.loads(args.acquisition.read_text())
    if prereg.get("status") != "HASH_FROZEN_ONE_SHOT_ARMED":
        raise V111ContractError("V111 preregistration is not armed")
    if prereg.get("evaluation_permitted") is not True:
        raise V111ContractError("V111 evaluation is not permitted")
    if acq.get("status") != "HASH_FROZEN_NO_DECODE":
        raise V111ContractError("V111 acquisition was not frozen before decode")
    if acq.get("packet_records_decoded") is not False or acq.get("model_inference_performed") is not False:
        raise V111ContractError("Acquisition boundary violated")

    ext = prereg["external_holdout"]
    expected_bytes = int(ext["bytes"])
    capture_sha256 = str(ext["sha256"])
    capture_md5 = str(ext["md5"])
    if args.pcap.stat().st_size != expected_bytes:
        raise V111ContractError("Capture byte-size mismatch")
    if file_hash(args.pcap) != capture_sha256:
        raise V111ContractError("Capture SHA-256 mismatch")
    if file_hash(args.pcap, "md5") != capture_md5:
        raise V111ContractError("Capture MD5 mismatch")
    if file_hash(args.model) != MODEL_SHA256:
        raise V111ContractError("Frozen V108 model hash mismatch")
    if file_hash(args.support_gate) != SUPPORT_SHA256:
        raise V111ContractError("Frozen V108 support-gate hash mismatch")

    reg = prereg["registered_candidate"]
    if reg["model_sha256"] != MODEL_SHA256 or reg["support_gate_sha256"] != SUPPORT_SHA256:
        raise V111ContractError("Preregistered candidate identity mismatch")
    if reg["adapter_contract_sha256"] != ADAPTER_SHA256:
        raise V111ContractError("Preregistered adapter identity mismatch")

    model, meta = GraphWorldModel.load(args.model)
    expected_contract = {
        "architecture": "gnn_lstm", "history": HISTORY, "horizon": HORIZON,
        "decoder": "residual", "mode": "service", "window_seconds": WINDOW_SECONDS,
        "max_nodes": MAX_NODES, "schema": SCHEMA, "feature_count": len(FEATURES),
    }
    contract = {
        "architecture": model.config["architecture"],
        "history": int(meta.get("history", -1)),
        "horizon": int(meta.get("horizon", -1)),
        "decoder": model.config["decoder"],
        "mode": meta.get("mode"),
        "window_seconds": int(meta.get("window_seconds", -1)),
        "max_nodes": int(meta.get("max_nodes", -1)),
        "schema": model.schema,
        "feature_count": int(model.f),
    }
    if contract != expected_contract:
        raise V111ContractError(f"Frozen model contract mismatch: {contract}")
    if not bool(meta.get("packet_features_trained")) or not bool(meta.get("ps_complete_features_trained")):
        raise V111ContractError("Frozen model is not PS-complete packet trained")
    if list(meta.get("features", [])) != list(FEATURES):
        raise V111ContractError("Frozen feature ordering mismatch")

    times, x, adj, mask, decoded = packet_service_graphs(args.pcap, MAX_PACKETS)
    try:
        sx, sa, sm, target, cutoffs = build_sequences(times, x, adj, mask)
    except Exception as exc:
        raise V111ContractError(f"No valid contiguous V111 sequence: {exc}") from exc

    model_pred = infer_state(model, sx, sa, sm)
    persistence_pred = persistence_prediction(sx, sm)
    model_mse = float(np.mean((model_pred - target) ** 2, dtype=np.float64))
    persistence_mse = float(np.mean((persistence_pred - target) ** 2, dtype=np.float64))
    improvement = float((persistence_mse - model_mse) / persistence_mse) if persistence_mse else 0.0

    gate = json.loads(args.support_gate.read_text())
    scores = support_score(gate, sx, sm)
    threshold = float(gate["threshold"])
    supported = scores <= threshold
    total_sequences = int(len(supported))
    supported_sequences = int(supported.sum())
    supported_fraction = float(supported_sequences / total_sequences) if total_sequences else 0.0

    pidx = FEATURES.index("packet_features_present")
    packet_vals = x[:, :, pidx][mask > 0]
    enough_sequences = total_sequences >= MIN_SEQUENCES
    enough_support = supported_fraction >= MIN_SUPPORTED_FRACTION
    beats_persistence = model_mse < persistence_mse
    passed = bool(enough_sequences and enough_support and beats_persistence)

    result = {
        "schema_version": "v111.1",
        "status": "PASS" if passed else "FAIL",
        "gate": {
            "minimum_total_sequences": MIN_SEQUENCES,
            "minimum_supported_fraction": MIN_SUPPORTED_FRACTION,
            "requires_model_mse_strictly_less_than_persistence_mse": True,
            "total_sequences_gate_passed": enough_sequences,
            "support_gate_passed": enough_support,
            "persistence_gate_passed": beats_persistence,
            "all_gates_passed": passed,
        },
        "dataset": {
            "name": ext["dataset"], "capture": ext["capture"],
            "bytes": expected_bytes, "sha256": capture_sha256, "md5": capture_md5,
            "source_url": ext["source_url"], "labels_accessed": False,
        },
        "frozen_runtime": {
            "model_sha256": MODEL_SHA256,
            "support_gate_sha256": SUPPORT_SHA256,
            "adapter_contract_sha256": ADAPTER_SHA256,
            "contract": contract,
            "packet_features_trained": True,
            "ps_complete_features_trained": True,
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
        },
        "state_forecasting": {
            "model_mse": model_mse,
            "persistence_mse": persistence_mse,
            "improvement_vs_persistence": improvement,
            "beats_persistence": beats_persistence,
        },
        "runtime_support": {
            "method": gate.get("method"), "threshold": threshold,
            "supported_sequences": supported_sequences, "total_sequences": total_sequences,
            "supported_fraction": supported_fraction,
            "median_score": float(np.median(scores)), "max_score": float(scores.max()),
            "interpretation": "training-support diagnostic only; outside support is not attack/OOD detection",
        },
        "one_shot_integrity": {
            "runs_allowed_for_claim": 1,
            "retrained_on_external": False,
            "normalization_fit_on_external": False,
            "support_fit_on_external": False,
            "threshold_fit_on_external": False,
            "adapter_changed_after_external_packet_decode": False,
            "labels_accessed": False,
            "rerun_for_claim_improvement": False,
        },
        "claim_boundary": "Fresh external one-shot state-transition forecasting only. No attack recall/FPR, MITRE-stage, or successful-compromise warning claim is made."
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(result, indent=2, allow_nan=False) + "\n")
    print(json.dumps(result, indent=2, allow_nan=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
