"""V99 frozen one-shot HIKARI-2021 external state-forecast evaluation.

This runner is intentionally narrow: it tests the already-frozen active Garuda
GraphSAGE+LSTM checkpoint on one preregistered HIKARI-2021 PCAP without fitting,
normalizing, calibrating, thresholding, or retraining on HIKARI.

The PCAP is deterministically adapted into the active v3.1 service-graph contract
using packet-derived flow telemetry.  Attack labels are not read here, so this run
certifies only fresh external *state-transition forecasting* versus persistence.
It does not certify attack recall/FPR, MITRE stages, or pre-compromise warning.
"""
from __future__ import annotations

import argparse
import hashlib
import json
from collections import defaultdict
from pathlib import Path
from typing import Dict, Iterable, List, Tuple

import numpy as np

from .data import FEATURES, SCHEMA, graph_snapshot
from .model import GraphWorldModel
from .pcap_reader import packets
from .ps_complete import _connection_flow
from .support_gate import score as support_score

EXPECTED_CAPTURE = "Monday_2022-04-11_0622_BRUTEFORCE_XML_150s.pcap"
EXPECTED_MD5 = "900deec66e058801a377fd81c5fc805e"
EXPECTED_MODEL_BLOB = "c1e411859042c10818ea46bedda8b483d5c9d717"
HISTORY = 8
HORIZON = 4
WINDOW_SECONDS = 10
MAX_NODES = 32
MAX_PACKETS = 10_000_000


class CompatibilityError(RuntimeError):
    pass


def file_hash(path: Path, algorithm: str) -> str:
    h = hashlib.new(algorithm)
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            h.update(block)
    return h.hexdigest()


def git_blob_sha1(path: Path) -> str:
    raw = path.read_bytes()
    return hashlib.sha1(b"blob " + str(len(raw)).encode("ascii") + b"\0" + raw).hexdigest()


def _flow_from_packets(observed: List[dict]) -> dict:
    flow = _connection_flow(observed)
    flow["retransmission_fraction"] = float(flow.get("retransmission_count", 0.0)) / max(
        float(flow.get("packets", 0.0)), 1.0
    )
    return flow


def packet_service_graphs(path: Path, max_packets: int = MAX_PACKETS):
    """Stream one 10-second bucket at a time into the frozen v3.1 service graph."""
    times: List[int] = []
    xs: List[np.ndarray] = []
    adjs: List[np.ndarray] = []
    masks: List[np.ndarray] = []
    current_bucket = None
    connections: Dict[tuple, List[dict]] = defaultdict(list)
    decoded_ipv4_packets = 0

    def flush() -> None:
        nonlocal connections
        if current_bucket is None:
            return
        flows = [_flow_from_packets(v) for v in connections.values()]
        x, adj, mask, _ = graph_snapshot(flows, mode="service", max_nodes=MAX_NODES)
        times.append(int(current_bucket))
        xs.append(x.astype(np.float32, copy=False))
        adjs.append(adj.astype(np.float32, copy=False))
        masks.append(mask.astype(np.float32, copy=False))
        connections = defaultdict(list)

    try:
        iterator: Iterable[dict] = packets(path, max_packets=max_packets)
        for packet in iterator:
            decoded_ipv4_packets += 1
            bucket = int(packet["t"] // WINDOW_SECONDS) * WINDOW_SECONDS
            if current_bucket is None:
                current_bucket = bucket
            elif bucket != current_bucket:
                if bucket < current_bucket:
                    raise CompatibilityError("non-monotone packet timestamps")
                flush()
                current_bucket = bucket
            endpoints = sorted(
                [(packet["src"], packet["sport"]), (packet["dst"], packet["dport"])]
            )
            key = (endpoints[0], endpoints[1], packet["protocol"])
            connections[key].append(packet)
        flush()
    except ValueError as exc:
        raise CompatibilityError(str(exc)) from exc

    if decoded_ipv4_packets < 1000:
        raise CompatibilityError(f"too few decoded IPv4 packets: {decoded_ipv4_packets}")
    if len(times) < HISTORY + HORIZON:
        raise CompatibilityError(
            f"too few observed 10-second windows: {len(times)}; need at least {HISTORY + HORIZON}"
        )
    return (
        np.asarray(times, dtype=np.int64),
        np.asarray(xs, dtype=np.float32),
        np.asarray(adjs, dtype=np.float32),
        np.asarray(masks, dtype=np.float32),
        decoded_ipv4_packets,
    )


def build_sequences(times, x, adj, mask):
    seq_x, seq_adj, seq_mask, targets, cutoffs = [], [], [], [], []
    total = HISTORY + HORIZON
    for start in range(0, len(times) - total + 1):
        ids = slice(start, start + total)
        if not np.all(np.diff(times[ids]) == WINDOW_SECONDS):
            continue
        hx = x[start : start + HISTORY]
        ha = adj[start : start + HISTORY]
        hm = mask[start : start + HISTORY]
        fx = x[start + HISTORY : start + total]
        fm = mask[start + HISTORY : start + total]
        pooled_future = (fx * fm[:, :, None]).sum(axis=1) / np.maximum(
            fm.sum(axis=1, keepdims=True), 1.0
        )
        seq_x.append(hx)
        seq_adj.append(ha)
        seq_mask.append(hm)
        targets.append(pooled_future)
        cutoffs.append(int(times[start + HISTORY - 1] + WINDOW_SECONDS))
    if not seq_x:
        raise CompatibilityError("no contiguous 8-history/4-future sequence exists")
    return tuple(
        np.asarray(v)
        for v in (seq_x, seq_adj, seq_mask, targets, cutoffs)
    )


def evaluate(pcap: Path, model_path: Path, support_gate_path: Path, prereg_path: Path) -> dict:
    prereg = json.loads(prereg_path.read_text(encoding="utf-8"))
    frozen = prereg["frozen_runtime"]
    primary = prereg["dataset"]["primary_capture"]

    if pcap.name != primary["filename"] or pcap.name != EXPECTED_CAPTURE:
        raise ValueError("PCAP filename does not match frozen preregistration")
    md5 = file_hash(pcap, "md5")
    if md5 != primary["official_md5"] or md5 != EXPECTED_MD5:
        raise ValueError(f"official MD5 mismatch: {md5}")

    model_blob = git_blob_sha1(model_path)
    if model_blob != frozen["model_git_blob_sha1"] or model_blob != EXPECTED_MODEL_BLOB:
        raise ValueError(f"frozen model Git blob mismatch: {model_blob}")

    model, metadata = GraphWorldModel.load(model_path)
    expected_contract = {
        "architecture": "gnn_lstm",
        "history": HISTORY,
        "horizon": HORIZON,
        "decoder": "residual",
        "mode": "service",
        "window_seconds": WINDOW_SECONDS,
        "max_nodes": MAX_NODES,
    }
    observed_contract = {
        "architecture": model.config["architecture"],
        "history": int(metadata.get("history", -1)),
        "horizon": int(metadata.get("horizon", -1)),
        "decoder": model.config["decoder"],
        "mode": metadata.get("mode"),
        "window_seconds": int(metadata.get("window_seconds", -1)),
        "max_nodes": int(metadata.get("max_nodes", -1)),
    }
    if observed_contract != expected_contract:
        raise ValueError(
            f"active model contract changed after preregistration: {observed_contract}"
        )
    if model.config["feature_dim"] != len(FEATURES):
        raise ValueError("active checkpoint feature dimension no longer matches v3.1")

    gate = json.loads(support_gate_path.read_text(encoding="utf-8"))

    try:
        times, x, adj, mask, decoded = packet_service_graphs(pcap)
        sx, sa, sm, target, cutoffs = build_sequences(times, x, adj, mask)
    except CompatibilityError as exc:
        return {
            "schema_version": "v99.1",
            "status": "INCOMPATIBLE",
            "reason": str(exc),
            "dataset": "HIKARI-2021",
            "capture": pcap.name,
            "capture_md5": md5,
            "capture_sha256": file_hash(pcap, "sha256"),
            "model_git_blob_sha1": model_blob,
            "labels_accessed": False,
            "retuned_after_result": False,
            "claim_boundary": "No fresh external performance claim is made because the preregistered capture could not be mapped under the frozen runtime contract.",
        }

    predictions, risks = [], []
    for start in range(0, len(sx), 64):
        mean, _, risk = model.forward(
            sx[start : start + 64],
            sa[start : start + 64],
            sm[start : start + 64],
            HORIZON,
        )
        predictions.append(mean.data)
        risks.append(risk.data)
    pred = np.concatenate(predictions, axis=0)
    unscored_risk = np.concatenate(risks, axis=0)

    pooled_history = (sx * sm[:, :, :, None]).sum(axis=2) / np.maximum(
        sm.sum(axis=2, keepdims=True), 1.0
    )
    persistence = np.repeat(pooled_history[:, -1:, :], HORIZON, axis=1)

    model_mse = float(np.mean((pred - target) ** 2))
    persistence_mse = float(np.mean((persistence - target) ** 2))
    improvement = (
        float((persistence_mse - model_mse) / persistence_mse)
        if persistence_mse > 0
        else 0.0
    )
    per_horizon = []
    for h in range(HORIZON):
        mm = float(np.mean((pred[:, h] - target[:, h]) ** 2))
        pm = float(np.mean((persistence[:, h] - target[:, h]) ** 2))
        per_horizon.append(
            {
                "seconds_ahead": (h + 1) * WINDOW_SECONDS,
                "model_mse": mm,
                "persistence_mse": pm,
                "improvement_vs_persistence": float((pm - mm) / pm) if pm > 0 else 0.0,
            }
        )

    scores = support_score(gate, sx, sm)
    threshold = float(gate["threshold"])
    supported = scores <= threshold
    packet_idx = FEATURES.index("packet_features_present")
    observed_nodes = mask > 0
    packet_feature_values = x[:, :, packet_idx][observed_nodes]

    supported_metrics = None
    if supported.any():
        smse = float(np.mean((pred[supported] - target[supported]) ** 2))
        spmse = float(np.mean((persistence[supported] - target[supported]) ** 2))
        supported_metrics = {
            "sequences": int(supported.sum()),
            "model_mse": smse,
            "persistence_mse": spmse,
            "improvement_vs_persistence": float((spmse - smse) / spmse) if spmse > 0 else 0.0,
        }

    passed = bool(model_mse < persistence_mse)
    return {
        "schema_version": "v99.1",
        "status": "PASS" if passed else "FAIL",
        "gate": "frozen model state MSE must be lower than persistence MSE on the first compatible preregistered external run",
        "dataset": {
            "name": "HIKARI-2021",
            "zenodo_record": "6463389",
            "capture": pcap.name,
            "official_md5": md5,
            "sha256": file_hash(pcap, "sha256"),
        },
        "frozen_runtime": {
            "model": str(model_path),
            "model_git_blob_sha1": model_blob,
            "contract": observed_contract,
            "checkpoint_packet_features_trained": bool(metadata.get("packet_features_trained", False)),
        },
        "adapter": {
            "schema": SCHEMA,
            "features": list(FEATURES),
            "feature_count": len(FEATURES),
            "mode": "service",
            "window_seconds": WINDOW_SECONDS,
            "max_nodes": MAX_NODES,
            "source": "raw PCAP packet telemetry -> per-window bidirectional connections -> frozen v3.1 service graph",
            "fit_on_hikari": False,
            "labels_accessed": False,
            "decoded_ipv4_packets": int(decoded),
            "observed_windows": int(len(times)),
            "contiguous_sequences": int(len(sx)),
            "first_window_epoch": int(times[0]),
            "last_window_epoch": int(times[-1]),
            "packet_features_present_mean_on_observed_nodes": float(packet_feature_values.mean()) if len(packet_feature_values) else 0.0,
        },
        "state_forecasting": {
            "model_mse": model_mse,
            "persistence_mse": persistence_mse,
            "improvement_vs_persistence": improvement,
            "beats_persistence": passed,
            "per_horizon": per_horizon,
        },
        "runtime_support": {
            "method": gate.get("method"),
            "threshold": threshold,
            "supported_sequences": int(supported.sum()),
            "total_sequences": int(len(supported)),
            "supported_fraction": float(supported.mean()),
            "max_support_score": float(scores.max()),
            "median_support_score": float(np.median(scores)),
            "interpretation": "Training-support diagnostic only; outside-support is abstention, not attack/OOD detection.",
            "supported_only_state_metrics": supported_metrics,
        },
        "unscored_outputs": {
            "risk_probabilities_computed": True,
            "risk_labels_accessed": False,
            "risk_metrics_reported": False,
            "mean_max_horizon_risk": float(unscored_risk.max(axis=1).mean()),
            "reason": "V99 deliberately does not inspect HIKARI attack labels before the frozen state-forecast result is recorded.",
        },
        "one_shot_integrity": {
            "retrained_on_hikari": False,
            "normalization_fit_on_hikari": False,
            "threshold_fit_on_hikari": False,
            "support_fit_on_hikari": False,
            "feature_mapping_changed_after_result": False,
            "rerun_for_better_metrics": False,
            "cutoff_timestamps": cutoffs.astype(int).tolist(),
        },
        "claim_boundary": "Fresh external one-shot state-transition forecasting evidence only. This result does not establish HIKARI attack recall/FPR, MITRE-stage accuracy, or verified pre-compromise warning.",
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--pcap", required=True, type=Path)
    parser.add_argument("--model", required=True, type=Path)
    parser.add_argument("--support-gate", required=True, type=Path)
    parser.add_argument("--prereg", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    if args.output.exists():
        parser.error("output already exists; one-shot result is immutable")
    report = evaluate(args.pcap, args.model, args.support_gate, args.prereg)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report, indent=2, allow_nan=False) + "\n", encoding="utf-8")
    print(json.dumps(report, indent=2, allow_nan=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
