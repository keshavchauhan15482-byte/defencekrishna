"""V113 generic frozen external one-shot evaluator.

This evaluator is frozen before the V113 capture is acquired. It uses the unchanged
V108 PS-complete 34-feature GraphSAGE+LSTM model, unchanged V108 support gate, and the
V112 audited tolerant packet adapter. It always writes an immutable PASS/FAIL result,
including pre-inference incompatibility failures; labels are never read.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import traceback
from pathlib import Path

import numpy as np

from .model import GraphWorldModel
from .ps_complete import FEATURES, SCHEMA
from .support_gate import score as support_score
from .v101_packet_graph_recovery import (
    HISTORY, HORIZON, WINDOW_SECONDS, MAX_NODES,
    build_sequences, infer_state, persistence_prediction,
)
from .v112_tolerant_ps_complete_runtime import tolerant_packet_service_graphs

MODEL_SHA256 = "f063ae8c890f9e805c913c02c92b8174cc1d58552514484ea2ef723611258fed"
SUPPORT_SHA256 = "7006671148e0dba3be55a2fe27a2fd17d3a7ece030dbcddd599c7aaa7f5368c1"
ADAPTER_SHA256 = "2c48468ed2e608377c226137bb432ee85efb27cfcb4ba7052f893816976e2e8c"
MAX_PACKETS = 2_000_000


def sha256(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for block in iter(lambda: f.read(1024 * 1024), b""):
            h.update(block)
    return h.hexdigest()


def md5(path: Path) -> str:
    h = hashlib.md5()
    with path.open("rb") as f:
        for block in iter(lambda: f.read(1024 * 1024), b""):
            h.update(block)
    return h.hexdigest()


def write_result(path: Path, value: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, indent=2, allow_nan=False) + "\n")


def main() -> int:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--pcap", required=True, type=Path)
    p.add_argument("--model", required=True, type=Path)
    p.add_argument("--support-gate", required=True, type=Path)
    p.add_argument("--prereg", required=True, type=Path)
    p.add_argument("--acquisition", required=True, type=Path)
    p.add_argument("--output", required=True, type=Path)
    args = p.parse_args()
    if args.output.exists():
        p.error("V113 result already exists; one-shot evidence is immutable")

    base = {
        "schema_version": "v113.1",
        "status": "FAIL",
        "claim_boundary": "Fresh external one-shot state-transition forecasting only. No attack recall/FPR, MITRE-stage, or successful-compromise warning claim is made.",
        "one_shot_integrity": {
            "runs_allowed_for_claim": 1,
            "retrained_on_external": False,
            "normalization_fit_on_external": False,
            "support_fit_on_external": False,
            "threshold_fit_on_external": False,
            "adapter_changed_after_external_acquisition": False,
            "labels_accessed": False,
            "rerun_for_claim_improvement": False,
        },
    }

    try:
        prereg = json.loads(args.prereg.read_text())
        acq = json.loads(args.acquisition.read_text())
        if prereg.get("status") != "HASH_FROZEN_ONE_SHOT_ARMED":
            raise RuntimeError("preregistration is not armed")
        if prereg.get("evaluation_permitted") is not True:
            raise RuntimeError("evaluation_permitted is not true")
        if acq.get("status") != "HASH_FROZEN_NO_DECODE":
            raise RuntimeError("acquisition was not frozen before decode")
        if acq.get("packet_records_decoded") is not False or acq.get("model_inference_performed") is not False:
            raise RuntimeError("acquisition/decode boundary violated")

        ext = prereg["external_holdout"]
        if args.pcap.stat().st_size != int(ext["bytes"]):
            raise RuntimeError("capture byte-size mismatch")
        if sha256(args.pcap) != ext["sha256"] or md5(args.pcap) != ext["md5"]:
            raise RuntimeError("capture hash mismatch")
        if sha256(args.model) != MODEL_SHA256:
            raise RuntimeError("frozen model hash mismatch")
        if sha256(args.support_gate) != SUPPORT_SHA256:
            raise RuntimeError("frozen support-gate hash mismatch")

        reg = prereg["registered_candidate"]
        if reg["model_sha256"] != MODEL_SHA256 or reg["support_gate_sha256"] != SUPPORT_SHA256:
            raise RuntimeError("preregistered model/support identity mismatch")
        if reg["adapter_contract_sha256"] != ADAPTER_SHA256:
            raise RuntimeError("preregistered tolerant adapter identity mismatch")

        model, meta = GraphWorldModel.load(args.model)
        contract = {
            "architecture": model.config["architecture"],
            "decoder": model.config["decoder"],
            "schema": model.schema,
            "feature_count": int(model.f),
            "history": int(meta.get("history", -1)),
            "horizon": int(meta.get("horizon", -1)),
            "mode": meta.get("mode"),
            "window_seconds": int(meta.get("window_seconds", -1)),
            "max_nodes": int(meta.get("max_nodes", -1)),
            "packet_features_trained": bool(meta.get("packet_features_trained")),
            "ps_complete_features_trained": bool(meta.get("ps_complete_features_trained")),
            "feature_order_match": list(meta.get("features", [])) == list(FEATURES),
        }
        expected = {
            "architecture": "gnn_lstm", "decoder": "residual", "schema": SCHEMA,
            "feature_count": 34, "history": HISTORY, "horizon": HORIZON,
            "mode": "service", "window_seconds": WINDOW_SECONDS, "max_nodes": MAX_NODES,
            "packet_features_trained": True, "ps_complete_features_trained": True,
            "feature_order_match": True,
        }
        if contract != expected:
            raise RuntimeError(f"frozen model contract mismatch: {contract}")

        times, x, adj, mask, decoded, parser_audit = tolerant_packet_service_graphs(args.pcap, MAX_PACKETS)
        sx, sa, sm, target, cutoffs = build_sequences(times, x, adj, mask)
        pred = infer_state(model, sx, sa, sm)
        persistence = persistence_prediction(sx, sm)
        model_mse = float(np.mean((pred - target) ** 2, dtype=np.float64))
        persistence_mse = float(np.mean((persistence - target) ** 2, dtype=np.float64))
        improvement = float((persistence_mse - model_mse) / persistence_mse) if persistence_mse else 0.0

        gate = json.loads(args.support_gate.read_text())
        scores = support_score(gate, sx, sm)
        threshold = float(gate["threshold"])
        supported = scores <= threshold
        total = int(len(supported))
        supported_n = int(supported.sum())
        supported_fraction = float(supported_n / total) if total else 0.0
        packet_idx = FEATURES.index("packet_features_present")
        observed = x[:, :, packet_idx][mask > 0]
        packet_presence = float(observed.mean()) if len(observed) else 0.0

        declared = prereg["one_shot_gate"]
        enough_sequences = total >= int(declared["minimum_total_sequences"])
        enough_support = supported_fraction >= float(declared["minimum_supported_fraction"])
        beats_persistence = model_mse < persistence_mse
        passed = bool(enough_sequences and enough_support and beats_persistence and improvement > 0.0)

        result = {
            **base,
            "status": "PASS" if passed else "FAIL",
            "failure_class": None if passed else "METRIC_OR_SUPPORT_GATE_FAIL",
            "dataset": {
                "name": ext["dataset"], "capture": ext["capture"], "bytes": int(ext["bytes"]),
                "sha256": ext["sha256"], "md5": ext["md5"], "source_url": ext["source_url"],
                "labels_accessed": False,
            },
            "frozen_runtime": {
                "model_sha256": MODEL_SHA256, "support_gate_sha256": SUPPORT_SHA256,
                "adapter_contract_sha256": ADAPTER_SHA256, "contract": contract,
            },
            "capture_processing": {
                "decoded_ipv4_packets": int(decoded), "packet_limit": MAX_PACKETS,
                "observed_windows": int(len(times)), "contiguous_sequences": total,
                "first_window_epoch": int(times[0]), "last_window_epoch": int(times[-1]),
                "cutoff_timestamps_sha256": hashlib.sha256(cutoffs.astype(np.int64).tobytes()).hexdigest(),
                "packet_features_present_mean_on_observed_nodes": packet_presence,
                "parser_audit": parser_audit,
            },
            "state_forecasting": {
                "model_mse": model_mse, "persistence_mse": persistence_mse,
                "improvement_vs_persistence": improvement, "beats_persistence": beats_persistence,
            },
            "runtime_support": {
                "method": gate.get("method"), "threshold": threshold,
                "supported_sequences": supported_n, "total_sequences": total,
                "supported_fraction": supported_fraction,
                "median_score": float(np.median(scores)), "max_score": float(scores.max()),
                "interpretation": "training-support diagnostic only; outside support is not attack/OOD detection",
            },
            "gate": {
                "minimum_total_sequences": int(declared["minimum_total_sequences"]),
                "minimum_supported_fraction": float(declared["minimum_supported_fraction"]),
                "total_sequences_gate_passed": enough_sequences,
                "support_gate_passed": enough_support,
                "persistence_gate_passed": beats_persistence,
                "positive_improvement_gate_passed": improvement > 0.0,
                "all_gates_passed": passed,
            },
            "model_inference_performed": True,
            "state_metric_computed": True,
            "support_metric_computed": True,
        }
    except Exception as exc:
        result = {
            **base,
            "status": "FAIL",
            "failure_class": "PREINFERENCE_OR_RUNTIME_INCOMPATIBILITY",
            "failure": {"type": type(exc).__name__, "message": str(exc)},
            "traceback_tail": traceback.format_exc().splitlines()[-8:],
            "model_inference_performed": False,
            "state_metric_computed": False,
            "support_metric_computed": False,
        }

    write_result(args.output, result)
    print(json.dumps(result, indent=2, allow_nan=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
