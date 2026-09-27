"""V106 frozen one-shot USTC-TFC2016 Miuref state-transition evaluation.

The holdout capture was selected and byte-hash frozen before any packet decode.
The unchanged V101 packet-trained GNN+LSTM candidate, V101 support gate and
V105 tolerant packet adapter are evaluated exactly once against persistence.
No labels are read or required.
"""
from __future__ import annotations

import argparse
import hashlib
import json
from collections import defaultdict
from pathlib import Path
from typing import Dict, Iterable, List

import numpy as np

from .data import FEATURES, graph_snapshot
from .model import GraphWorldModel
from .pcap_reader import packets
from .ps_complete import _connection_flow
from .support_gate import score as support_score
from .v101_packet_graph_recovery import (
    HISTORY, HORIZON, WINDOW_SECONDS, MAX_NODES,
    build_sequences, infer_state, persistence_prediction,
)

MODEL_SHA256 = "30694adf0819e6ffd79079512a348059195dcc651d7f0b4d5049e278b4d7cb79"
SUPPORT_SHA256 = "2f281593f163ba3e4bbed592ea41eeaa1c8d5e3dfe49de933473b15fe6c17df3"
ADAPTER_SHA256 = "1f705e4427f65507ae5d71dd353fbe58966e2882bff7acc182f45fad99fb5e7f"
PCAP_READER_SHA256 = "3b5a4d01b9f6881b726787cd990e341aed0af625775b4f823c14d3981c69bfad"
CAPTURE_SHA256 = "ec2476c9fb34a202b11d1138286143ad2cd7055fbc9401baf150b3d513c3d0ae"
CAPTURE_MD5 = "7a21246187cfe0c4b7ff82be798d836d"
EXPECTED_BYTES = 17196739
MIN_SEQUENCES = 32
MIN_SUPPORTED_FRACTION = 0.5
MAX_PACKETS = 2_000_000


class V106ContractError(RuntimeError):
    pass


def file_hash(path: Path, algorithm: str = "sha256") -> str:
    h = hashlib.new(algorithm)
    with path.open("rb") as f:
        for block in iter(lambda: f.read(1024 * 1024), b""):
            h.update(block)
    return h.hexdigest()


def _flow(rows: List[dict]) -> dict:
    flow = _connection_flow(rows)
    flow["retransmission_fraction"] = float(flow.get("retransmission_count", 0.0)) / max(
        float(flow.get("packets", 0.0)), 1.0
    )
    return flow


def packet_service_graphs(path: Path):
    times, xs, adjs, masks = [], [], [], []
    current = None
    conns: Dict[tuple, List[dict]] = defaultdict(list)
    decoded = 0
    audit: dict = {}

    def flush():
        nonlocal conns
        if current is None:
            return
        flows = [_flow(v) for v in conns.values()]
        x, adj, mask, _ = graph_snapshot(flows, mode="service", max_nodes=MAX_NODES)
        times.append(int(current))
        xs.append(x.astype(np.float32, copy=False))
        adjs.append(adj.astype(np.float32, copy=False))
        masks.append(mask.astype(np.float32, copy=False))
        conns = defaultdict(list)

    iterator: Iterable[dict] = packets(
        path, max_packets=MAX_PACKETS, allow_truncated=True, audit=audit
    )
    for pkt in iterator:
        decoded += 1
        bucket = int(pkt["t"] // WINDOW_SECONDS) * WINDOW_SECONDS
        if current is None:
            current = bucket
        elif bucket != current:
            if bucket < current:
                raise V106ContractError("Non-monotone timestamp in Miuref capture")
            flush()
            current = bucket
        endpoints = sorted([(pkt["src"], pkt["sport"]), (pkt["dst"], pkt["dport"])])
        conns[(endpoints[0], endpoints[1], pkt["protocol"])].append(pkt)
    flush()

    if decoded < 1:
        raise V106ContractError("No IPv4 packets decoded from registered capture")
    if len(times) < HISTORY + HORIZON:
        raise V106ContractError(
            f"Too few observed graph windows: windows={len(times)}"
        )
    return (
        np.asarray(times, dtype=np.int64),
        np.asarray(xs, dtype=np.float32),
        np.asarray(adjs, dtype=np.float32),
        np.asarray(masks, dtype=np.float32),
        int(decoded),
        {k: int(v) for k, v in sorted(audit.items())},
    )


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
        ap.error("V106 one-shot result already exists and is immutable")

    prereg = json.loads(args.prereg.read_text())
    acq = json.loads(args.acquisition.read_text())
    if prereg["status"] != "HASH_FROZEN_ONE_SHOT_ARMED":
        raise V106ContractError("V106 is not armed")
    if prereg["evaluation_permitted"] is not True:
        raise V106ContractError("V106 evaluation not permitted")
    if acq["status"] != "HASH_FROZEN_MODEL_NOT_RUN":
        raise V106ContractError("V106 acquisition manifest is not frozen")

    if args.pcap.stat().st_size != EXPECTED_BYTES:
        raise V106ContractError("Capture byte-size mismatch")
    if file_hash(args.pcap) != CAPTURE_SHA256:
        raise V106ContractError("Capture SHA-256 mismatch")
    if file_hash(args.pcap, "md5") != CAPTURE_MD5:
        raise V106ContractError("Capture MD5 mismatch")
    if file_hash(args.model) != MODEL_SHA256:
        raise V106ContractError("Frozen model hash mismatch")
    if file_hash(args.support_gate) != SUPPORT_SHA256:
        raise V106ContractError("Frozen support-gate hash mismatch")
    if file_hash(Path(__file__).with_name("pcap_reader.py")) != PCAP_READER_SHA256:
        raise V106ContractError("Frozen V105 packet-reader hash mismatch")

    reg = prereg["registered_candidate"]
    if reg["model_sha256"] != MODEL_SHA256:
        raise V106ContractError("Preregistered model identity mismatch")
    if reg["support_gate_sha256"] != SUPPORT_SHA256:
        raise V106ContractError("Preregistered support identity mismatch")
    if reg["adapter_contract_sha256"] != ADAPTER_SHA256:
        raise V106ContractError("Preregistered adapter identity mismatch")
    if reg["pcap_reader_sha256"] != PCAP_READER_SHA256:
        raise V106ContractError("Preregistered packet-reader identity mismatch")

    model, meta = GraphWorldModel.load(args.model)
    contract = {
        "architecture": model.config["architecture"],
        "history": int(meta.get("history", -1)),
        "horizon": int(meta.get("horizon", -1)),
        "decoder": model.config["decoder"],
        "mode": meta.get("mode"),
        "window_seconds": int(meta.get("window_seconds", -1)),
        "max_nodes": int(meta.get("max_nodes", -1)),
    }
    expected_contract = {
        "architecture": "gnn_lstm",
        "history": 8,
        "horizon": 4,
        "decoder": "residual",
        "mode": "service",
        "window_seconds": 10,
        "max_nodes": 32,
    }
    if contract != expected_contract:
        raise V106ContractError(f"Frozen model contract mismatch: {contract}")
    if not bool(meta.get("packet_features_trained", False)):
        raise V106ContractError("Frozen model is not packet-feature trained")

    times, x, adj, mask, decoded, parser_audit = packet_service_graphs(args.pcap)
    try:
        sx, sa, sm, target, cutoffs = build_sequences(times, x, adj, mask)
    except Exception as exc:
        raise V106ContractError(f"No valid contiguous V106 sequence: {exc}") from exc

    model_pred = infer_state(model, sx, sa, sm)
    persistence_pred = persistence_prediction(sx, sm)

    model_mse = float(np.mean((model_pred - target) ** 2, dtype=np.float64))
    persistence_mse = float(np.mean((persistence_pred - target) ** 2, dtype=np.float64))
    improvement = (
        float((persistence_mse - model_mse) / persistence_mse)
        if persistence_mse
        else 0.0
    )

    gate = json.loads(args.support_gate.read_text())
    scores = support_score(gate, sx, sm)
    threshold = float(gate["threshold"])
    supported = scores <= threshold
    total_sequences = int(len(supported))
    supported_sequences = int(supported.sum())
    supported_fraction = (
        float(supported_sequences / total_sequences) if total_sequences else 0.0
    )

    pidx = FEATURES.index("packet_features_present")
    packet_vals = x[:, :, pidx][mask > 0]

    enough_sequences = total_sequences >= MIN_SEQUENCES
    enough_support = supported_fraction >= MIN_SUPPORTED_FRACTION
    beats_persistence = model_mse < persistence_mse
    passed = bool(enough_sequences and enough_support and beats_persistence)

    result = {
        "schema_version": "v106.1",
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
            "name": "USTC-TFC2016",
            "capture": "Malware/Miuref.pcap",
            "bytes": EXPECTED_BYTES,
            "sha256": CAPTURE_SHA256,
            "md5": CAPTURE_MD5,
            "publisher_git_blob_sha1": prereg["external_holdout"]["publisher_git_blob_sha1"],
            "labels_accessed": False,
        },
        "frozen_runtime": {
            "model_sha256": MODEL_SHA256,
            "support_gate_sha256": SUPPORT_SHA256,
            "adapter_contract_sha256": ADAPTER_SHA256,
            "pcap_reader_sha256": PCAP_READER_SHA256,
            "contract": contract,
            "packet_features_trained": True,
        },
        "capture_processing": {
            "decoded_ipv4_packets": decoded,
            "parser_audit": parser_audit,
            "observed_windows": int(len(times)),
            "contiguous_sequences": total_sequences,
            "first_window_epoch": int(times[0]),
            "last_window_epoch": int(times[-1]),
            "cutoff_timestamps_sha256": hashlib.sha256(
                cutoffs.astype(np.int64).tobytes()
            ).hexdigest(),
            "packet_features_present_mean_on_observed_nodes": (
                float(packet_vals.mean()) if len(packet_vals) else 0.0
            ),
        },
        "state_forecasting": {
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
            "max_score": float(scores.max()),
            "interpretation": (
                "training-support diagnostic only; outside support is not attack/OOD detection"
            ),
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
        "claim_boundary": (
            "Fresh external one-shot state-transition forecasting only. "
            "No attack recall/FPR, MITRE-stage, or successful-compromise warning claim is made."
        ),
    }

    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(result, indent=2, allow_nan=False) + "\n")
    print(json.dumps(result, indent=2, allow_nan=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
