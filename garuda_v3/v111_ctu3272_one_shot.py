"""V111 frozen external one-shot on CTU-Malware-Capture-Botnet-327-2.

Primary gate: frozen V108 PS-complete GraphSAGE+LSTM state MSE must be strictly lower
than same-history persistence over the exact registered PCAP. Runtime-support is a
separate operational diagnostic under the V107 protocol. A prediction-only warning
policy, frozen on CICAPT development data before external decode, is also evaluated.

The publisher's "last packet before infection" marker is treated only as a conservative
pre-infection boundary. It is never promoted into an exact successful-compromise
timestamp; V98 remains separate unless objective compromise evidence satisfies V107.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import struct
from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterable

import numpy as np

from .model import GraphWorldModel
from .pcap_reader import packets
from .ps_complete import FEATURES, SCHEMA, _connection_flow, graph_snapshot
from .support_gate import score as support_score
from .v101_packet_graph_recovery import (
    HISTORY,
    HORIZON,
    WINDOW_SECONDS,
    MAX_NODES,
    build_sequences,
    infer_state,
    persistence_prediction,
)
from .v111_freeze_warning_policy import transition_score

MODEL_SHA256 = "f063ae8c890f9e805c913c02c92b8174cc1d58552514484ea2ef723611258fed"
SUPPORT_SHA256 = "7006671148e0dba3be55a2fe27a2fd17d3a7ece030dbcddd599c7aaa7f5368c1"
PCAP_SHA256 = "ce9d45d2b5c0be8be56481cbd4d98a094a96e453328e9d88f88e882d94a79884"
PCAP_MD5 = "8bf6f9ec33d1c521ee4129671d31ee61"
PCAP_BYTES = 69890363
MIN_SEQUENCES = 32
MAX_PACKET_RECORDS = 5_000_000


class V111ContractError(RuntimeError):
    pass


def file_hash(path: Path, algorithm: str = "sha256") -> str:
    h = hashlib.new(algorithm)
    with path.open("rb") as f:
        for block in iter(lambda: f.read(1024 * 1024), b""):
            h.update(block)
    return h.hexdigest()


def _flow(rows: list[dict]) -> dict:
    return _connection_flow(rows)


def packet_service_graphs(path: Path):
    times, xs, adjs, masks = [], [], [], []
    current = None
    conns: dict[tuple, list[dict]] = defaultdict(list)
    decoded = 0
    audit: dict[str, int] = {}

    def flush() -> None:
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
        path,
        max_packets=MAX_PACKET_RECORDS,
        allow_truncated=True,
        audit=audit,
    )
    for pkt in iterator:
        decoded += 1
        bucket = int(pkt["t"] // WINDOW_SECONDS) * WINDOW_SECONDS
        if current is None:
            current = bucket
        elif bucket != current:
            if bucket < current:
                raise V111ContractError("non-monotone decoded packet timestamp")
            flush()
            current = bucket
        endpoints = sorted([(pkt["src"], pkt["sport"]), (pkt["dst"], pkt["dport"])])
        conns[(endpoints[0], endpoints[1], pkt["protocol"])].append(pkt)
    flush()

    if decoded < 1000:
        raise V111ContractError(f"too few decoded IPv4 packets: {decoded}")
    if len(times) < HISTORY + HORIZON + 20:
        raise V111ContractError(f"too few observed graph windows: {len(times)}")
    return (
        np.asarray(times, dtype=np.int64),
        np.asarray(xs, dtype=np.float32),
        np.asarray(adjs, dtype=np.float32),
        np.asarray(masks, dtype=np.float32),
        int(decoded),
        {k: int(v) for k, v in sorted(audit.items())},
    )


def raw_classic_timestamp_audit(path: Path, expected_epoch: float | None = None) -> dict:
    classic = {
        b"\xd4\xc3\xb2\xa1": ("<", 1e6),
        b"\xa1\xb2\xc3\xd4": (">", 1e6),
        b"\x4d\x3c\xb2\xa1": ("<", 1e9),
        b"\xa1\xb2\x3c\x4d": (">", 1e9),
    }
    with path.open("rb") as f:
        magic = f.read(4)
        if magic not in classic:
            raise V111ContractError("registered V111 object is not classic PCAP")
        endian, unit = classic[magic]
        tail = f.read(20)
        if len(tail) != 20:
            raise V111ContractError("truncated PCAP global header")
        major, minor, _, _, snaplen, linktype = struct.unpack(endian + "HHIIII", tail)
        if (major, minor) != (2, 4):
            raise V111ContractError(f"unexpected PCAP version {(major, minor)}")
        first = last = None
        nearest = None
        nearest_delta = None
        count = 0
        while True:
            rec = f.read(16)
            if not rec:
                break
            if len(rec) != 16:
                raise V111ContractError("truncated raw PCAP record header")
            sec, sub, captured, original = struct.unpack(endian + "IIII", rec)
            if captured > snaplen or captured > original:
                raise V111ContractError("invalid raw PCAP capture length")
            timestamp = float(sec + sub / unit)
            if first is None:
                first = timestamp
            last = timestamp
            if expected_epoch is not None:
                delta = abs(timestamp - float(expected_epoch))
                if nearest_delta is None or delta < nearest_delta:
                    nearest_delta = delta
                    nearest = timestamp
            f.seek(captured, 1)
            count += 1
            if count > MAX_PACKET_RECORDS:
                raise V111ContractError("raw PCAP record count exceeds frozen safety bound")
    if not count:
        raise V111ContractError("PCAP has no packet records")
    return {
        "record_count": int(count),
        "first_timestamp": float(first),
        "last_timestamp": float(last),
        "linktype": int(linktype),
        "snaplen": int(snaplen),
        "nearest_expected_marker_timestamp": float(nearest) if nearest is not None else None,
        "nearest_expected_marker_delta_seconds": float(nearest_delta) if nearest_delta is not None else None,
    }


def iso_from_epoch(value: float) -> str:
    return datetime.fromtimestamp(float(value), tz=timezone.utc).isoformat()


def main() -> int:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--pcap", required=True, type=Path)
    p.add_argument("--model", required=True, type=Path)
    p.add_argument("--support-gate", required=True, type=Path)
    p.add_argument("--warning-policy", required=True, type=Path)
    p.add_argument("--prereg", required=True, type=Path)
    p.add_argument("--acquisition", required=True, type=Path)
    p.add_argument("--output", required=True, type=Path)
    args = p.parse_args()
    if args.output.exists():
        p.error("V111 one-shot result already exists and is immutable")

    prereg = json.loads(args.prereg.read_text())
    acq = json.loads(args.acquisition.read_text())
    policy = json.loads(args.warning_policy.read_text())
    if prereg.get("status") != "HASH_AND_POLICY_FROZEN_ONE_SHOT_ARMED":
        raise V111ContractError("V111 one-shot is not armed")
    if prereg.get("acquisition", {}).get("evaluation_permitted") is not True:
        raise V111ContractError("V111 evaluation not permitted by preregistration")
    if acq.get("status") != "HASH_FROZEN_MODEL_NOT_RUN":
        raise V111ContractError("V111 acquisition evidence is not pre-inference frozen")
    if policy.get("status") != "DEV_ONLY_WARNING_POLICY_FROZEN":
        raise V111ContractError("V111 warning policy is not development-frozen")

    if args.pcap.stat().st_size != PCAP_BYTES:
        raise V111ContractError("registered PCAP byte-size mismatch")
    if file_hash(args.pcap) != PCAP_SHA256 or file_hash(args.pcap, "md5") != PCAP_MD5:
        raise V111ContractError("registered PCAP hash mismatch")
    if file_hash(args.model) != MODEL_SHA256:
        raise V111ContractError("frozen V108 model hash mismatch")
    if file_hash(args.support_gate) != SUPPORT_SHA256:
        raise V111ContractError("frozen V108 support-gate hash mismatch")
    expected_policy_sha = prereg["prediction_warning_policy"].get("artifact_sha256")
    if not expected_policy_sha or file_hash(args.warning_policy) != expected_policy_sha:
        raise V111ContractError("warning-policy artifact hash mismatch")

    model, meta = GraphWorldModel.load(args.model)
    if model.schema != SCHEMA or model.f != len(FEATURES) or len(FEATURES) != 34:
        raise V111ContractError("frozen model PS-complete schema mismatch")
    if meta.get("ps_complete_features_trained") is not True:
        raise V111ContractError("frozen model is not PS-complete trained")

    marker_policy = prereg["external_holdout"]["publisher_metadata"].get(
        "packet_clock_alignment_policy", {}
    )
    expected_marker = marker_policy.get("expected_raw_epoch_seconds")
    raw_audit = raw_classic_timestamp_audit(args.pcap, expected_marker)

    times, x, adj, mask, decoded, parser_audit = packet_service_graphs(args.pcap)
    sx, sa, sm, target, cutoffs = build_sequences(times, x, adj, mask)
    if len(sx) < MIN_SEQUENCES:
        raise V111ContractError(f"insufficient contiguous sequences: {len(sx)} < {MIN_SEQUENCES}")

    pred = infer_state(model, sx, sa, sm, batch_size=64)
    persistence = persistence_prediction(sx, sm)
    model_mse = float(np.mean((pred - target) ** 2, dtype=np.float64))
    persistence_mse = float(np.mean((persistence - target) ** 2, dtype=np.float64))
    improvement = (
        float((persistence_mse - model_mse) / persistence_mse)
        if persistence_mse > 0
        else 0.0
    )
    forecast_pass = bool(model_mse < persistence_mse)

    gate = json.loads(args.support_gate.read_text())
    support_scores = support_score(gate, sx, sm)
    support_threshold = float(gate["threshold"])
    supported = support_scores <= support_threshold

    warning_scores = transition_score(pred, persistence)
    warning_threshold = float(policy["threshold"]["value"])
    alerts = warning_scores > warning_threshold
    alert_times = np.asarray(cutoffs, dtype=np.float64)[alerts]

    marker_tolerance = float(marker_policy.get("match_tolerance_seconds", 0.0) or 0.0)
    marker_aligned = bool(
        expected_marker is not None
        and raw_audit["nearest_expected_marker_delta_seconds"] is not None
        and raw_audit["nearest_expected_marker_delta_seconds"] <= marker_tolerance
    )
    lookback = float(marker_policy.get("warning_lookback_seconds", 600.0))
    preinfection = {
        "publisher_marker_interpretation_predeclared": bool(expected_marker is not None),
        "marker_alignment_passed": marker_aligned,
        "expected_raw_epoch_seconds": float(expected_marker) if expected_marker is not None else None,
        "nearest_raw_packet_epoch_seconds": raw_audit["nearest_expected_marker_timestamp"],
        "alignment_delta_seconds": raw_audit["nearest_expected_marker_delta_seconds"],
        "match_tolerance_seconds": marker_tolerance,
        "warning_lookback_seconds": lookback,
        "qualifying_warning_count": 0,
        "first_warning_epoch_seconds": None,
        "conservative_lead_to_last_preinfection_packet_seconds": None,
        "warning_before_publisher_last_preinfection_packet": False,
        "successful_compromise_timestamp_certified": False,
        "v98_exact_successful_compromise_gate_passed": False,
    }
    if marker_aligned:
        marker = float(expected_marker)
        eligible = np.sort(alert_times[(alert_times >= marker - lookback) & (alert_times < marker)])
        if len(eligible):
            first = float(eligible[0])
            preinfection.update({
                "qualifying_warning_count": int(len(eligible)),
                "first_warning_epoch_seconds": first,
                "first_warning_timestamp_utc_reference": iso_from_epoch(first),
                "publisher_last_preinfection_packet_timestamp_utc_reference": iso_from_epoch(marker),
                "conservative_lead_to_last_preinfection_packet_seconds": float(marker - first),
                "warning_before_publisher_last_preinfection_packet": True,
            })

    pidx = FEATURES.index("packet_features_present")
    observed_packet_presence = x[:, :, pidx][mask > 0]
    result = {
        "schema_version": "v111.1",
        "status": "PASS" if forecast_pass else "FAIL",
        "primary_gate": {
            "protocol": "v107.1 future external forecast gate",
            "minimum_contiguous_sequences": MIN_SEQUENCES,
            "metric": "state_transition_mse",
            "baseline": "same-history persistence",
            "pass_rule": "frozen_model_mse < persistence_mse",
            "support_required_for_forecast_pass": False,
        },
        "dataset": {
            "name": prereg["external_holdout"]["dataset"],
            "capture": prereg["external_holdout"]["capture"],
            "pcap_bytes": PCAP_BYTES,
            "pcap_sha256": PCAP_SHA256,
            "pcap_md5": PCAP_MD5,
            "external_labels_accessed": False,
        },
        "frozen_runtime": {
            "model_sha256": MODEL_SHA256,
            "support_gate_sha256": SUPPORT_SHA256,
            "warning_policy_sha256": expected_policy_sha,
            "schema": SCHEMA,
            "feature_count": len(FEATURES),
            "packet_features_trained": True,
            "ps_complete_features_trained": True,
        },
        "capture_audit": {
            "raw_record_timestamps": raw_audit,
            "decoded_ipv4_packets": decoded,
            "parser_audit": parser_audit,
            "observed_graph_windows": int(len(times)),
            "contiguous_sequences": int(len(sx)),
            "first_graph_window_epoch": int(times[0]),
            "last_graph_window_epoch": int(times[-1]),
            "packet_features_present_mean_on_observed_nodes": float(observed_packet_presence.mean()) if len(observed_packet_presence) else 0.0,
        },
        "state_forecasting": {
            "model_mse": model_mse,
            "persistence_mse": persistence_mse,
            "improvement_vs_persistence": improvement,
            "beats_persistence": forecast_pass,
        },
        "operational_support": {
            "method": gate.get("method"),
            "threshold": support_threshold,
            "supported_sequences": int(supported.sum()),
            "total_sequences": int(len(supported)),
            "supported_fraction": float(supported.mean()),
            "median_score": float(np.median(support_scores)),
            "max_score": float(np.max(support_scores)),
            "interpretation": "operational eligibility diagnostic only; not attack/OOD detection and not part of the external forecast PASS rule",
        },
        "prediction_warning": {
            "score_definition": policy["score"]["definition"],
            "threshold": warning_threshold,
            "threshold_source": "CICAPT development Phase-2 only, frozen before V111 packet decode",
            "external_threshold_fitting": False,
            "alert_sequences": int(alerts.sum()),
            "total_sequences": int(len(alerts)),
            "alert_fraction": float(alerts.mean()),
            "first_alert_epoch_seconds": float(alert_times[0]) if len(alert_times) else None,
            "last_alert_epoch_seconds": float(alert_times[-1]) if len(alert_times) else None,
        },
        "preinfection_boundary_audit": preinfection,
        "one_shot_integrity": {
            "runs_allowed": 1,
            "retrained_on_external": False,
            "normalization_fit_on_external": False,
            "support_fit_on_external": False,
            "warning_threshold_fit_on_external": False,
            "adapter_changed_after_external_decode": False,
            "external_labels_accessed": False,
            "publisher_infection_metadata_used_for_model_or_threshold_fitting": False,
            "rerun_for_claim_improvement": False,
        },
        "claim_boundary": (
            "PASS/FAIL certifies only fresh external state-transition forecasting versus persistence for this exact capture. "
            "The preinfection boundary audit can show a conservative warning before the publisher's last packet before infection, "
            "but it does not create an exact successful-compromise timestamp and therefore does not by itself close V98."
        ),
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(result, indent=2, sort_keys=True, allow_nan=False) + "\n")
    print(json.dumps(result, indent=2, allow_nan=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
