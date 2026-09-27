"""V102 fresh external MAWI one-shot state-transition evaluation.

This evaluator is frozen before any MAWI packet-record decode or model inference.
It evaluates the already-frozen V101 packet-compatible GraphSAGE+LSTM candidate on
one preregistered MAWI samplepoint-B capture exactly once.

Scientific boundary:
- MAWI is never used for training, normalization, support fitting, adapter selection,
  seed selection, checkpoint selection, or threshold fitting.
- The capture is hash-pinned before packet decoding.
- The V101 checkpoint/support-gate hashes are verified before inference.
- The primary gate is state-forecast MSE < persistence MSE on the full registered
  capture. Support is a training-support diagnostic only.
- No attack labels are accessed, so this script makes no recall/FPR, MITRE-stage,
  or successful-compromise warning claim.

MAWI samplepoint-B uses a 96-byte classic-PCAP snaplen. The precommitted adapter
therefore supports truncated packet payload bytes without changing feature meaning:
IPv4/TCP/UDP header fields are read only when captured, while total payload length
is derived from the IPv4 total-length/header-length fields. Wire bytes use the PCAP
original-length field. This policy is generic and was frozen before MAWI inference.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import socket
import struct
from collections import defaultdict
from pathlib import Path
from typing import Dict, Iterable, Iterator, List

import numpy as np

from .data import FEATURES, SCHEMA, graph_snapshot
from .model import GraphWorldModel
from .ps_complete import _connection_flow
from .support_gate import score as support_score

HISTORY = 8
HORIZON = 4
WINDOW_SECONDS = 10
MAX_NODES = 32
EXPECTED_CAPTURE = "200601011400.dump"
EXPECTED_RECORDS = 6_587_564
EXPECTED_SNAPLEN = 96
EXPECTED_MODEL_SHA256 = "30694adf0819e6ffd79079512a348059195dcc651d7f0b4d5049e278b4d7cb79"
EXPECTED_SUPPORT_SHA256 = "2f281593f163ba3e4bbed592ea41eeaa1c8d5e3dfe49de933473b15fe6c17df3"
EXPECTED_ADAPTER_SHA256 = "870e7894378e687c542f286eabccf367c10d4d41dbebe7551b4ce95df2c65ac8"

_CLASSIC = {
    b"\xd4\xc3\xb2\xa1": ("<", 1e6),
    b"\xa1\xb2\xc3\xd4": (">", 1e6),
    b"\x4d\x3c\xb2\xa1": ("<", 1e9),
    b"\xa1\xb2\x3c\x4d": (">", 1e9),
}


class V102ContractError(RuntimeError):
    pass


def sha256_path(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for block in iter(lambda: f.read(1024 * 1024), b""):
            h.update(block)
    return h.hexdigest()


def _decode_truncated_ipv4(data: bytes, *, original: int, timestamp: float, linktype: int):
    """Decode header-complete IPv4 packets even when payload bytes are snaplen-truncated."""
    offset = 0
    if linktype == 1:
        if len(data) < 14:
            return None
        kind = struct.unpack("!H", data[12:14])[0]
        offset = 14
        for _ in range(2):
            if kind in (0x8100, 0x88A8):
                if len(data) < offset + 4:
                    return None
                kind = struct.unpack("!H", data[offset + 2 : offset + 4])[0]
                offset += 4
        if kind != 0x0800:
            return None
    elif linktype != 101:
        raise V102ContractError(f"Unsupported MAWI linktype {linktype}")

    ip = data[offset:]
    if len(ip) < 20 or ip[0] >> 4 != 4:
        return None
    ihl = (ip[0] & 15) * 4
    if ihl < 20 or len(ip) < ihl:
        return None
    total_len = struct.unpack("!H", ip[2:4])[0]
    if total_len < ihl:
        return None
    frag = struct.unpack("!H", ip[6:8])[0]
    proto = int(ip[9])
    item = {
        "t": float(timestamp),
        "src": socket.inet_ntoa(ip[12:16]),
        "dst": socket.inet_ntoa(ip[16:20]),
        "bytes": int(original),
        "ttl": int(ip[8]),
        "frag": bool(frag & 0x3FFF),
        "protocol": "other",
        "sport": 0,
        "dport": 0,
        "flags": 0,
        "win": 0,
        "seq": None,
        "payload_len": 0,
        "capture_truncated": bool(len(ip) < total_len),
    }
    # Non-initial fragments do not carry a reliable transport header.
    if frag & 0x1FFF:
        return item

    transport = ip[ihl:]
    if proto == 6:
        if len(transport) < 20:
            return item
        tcp_len = (transport[12] >> 4) * 4
        if tcp_len < 20 or len(transport) < tcp_len or total_len < ihl + tcp_len:
            return item
        sport, dport, seq = struct.unpack("!HHI", transport[:8])
        item.update(
            protocol="tcp",
            sport=int(sport),
            dport=int(dport),
            seq=int(seq),
            flags=int(transport[13]),
            win=int(struct.unpack("!H", transport[14:16])[0]),
            payload_len=int(max(0, total_len - ihl - tcp_len)),
        )
    elif proto == 17:
        if len(transport) < 8 or total_len < ihl + 8:
            return item
        sport, dport = struct.unpack("!HH", transport[:4])
        item.update(
            protocol="udp",
            sport=int(sport),
            dport=int(dport),
            payload_len=int(max(0, total_len - ihl - 8)),
        )
    return item


def classic_packets(path: Path, *, expected_records: int, expected_snaplen: int, stats: dict) -> Iterator[dict]:
    with path.open("rb") as f:
        header = f.read(24)
        if len(header) != 24 or header[:4] not in _CLASSIC:
            raise V102ContractError("V102 requires a classic PCAP capture")
        endian, unit = _CLASSIC[header[:4]]
        major, minor, _, _, snaplen, linktype = struct.unpack(endian + "HHIIII", header[4:])
        if (major, minor) != (2, 4):
            raise V102ContractError(f"Unexpected PCAP version {major}.{minor}")
        if int(snaplen) != int(expected_snaplen):
            raise V102ContractError(f"Snaplen mismatch: {snaplen} != {expected_snaplen}")
        if int(linktype) not in (1, 101):
            raise V102ContractError(f"Unsupported linktype {linktype}")
        stats.update(records=0, ipv4=0, truncated_ipv4=0, linktype=int(linktype), snaplen=int(snaplen))
        while True:
            record = f.read(16)
            if not record:
                break
            if len(record) != 16:
                raise V102ContractError("Truncated PCAP packet record header")
            sec, sub, captured, original = struct.unpack(endian + "IIII", record)
            if captured > snaplen or captured > original:
                raise V102ContractError("Invalid PCAP capture/original length")
            payload = f.read(captured)
            if len(payload) != captured:
                raise V102ContractError("Truncated PCAP packet bytes")
            stats["records"] += 1
            if stats["records"] > expected_records:
                raise V102ContractError("Capture has more packet records than preregistered")
            item = _decode_truncated_ipv4(
                payload,
                original=int(original),
                timestamp=float(sec + sub / unit),
                linktype=int(linktype),
            )
            if item is not None:
                stats["ipv4"] += 1
                stats["truncated_ipv4"] += int(bool(item.get("capture_truncated")))
                yield item
        if stats["records"] != expected_records:
            raise V102ContractError(
                f"Publisher packet-count mismatch: {stats['records']} != {expected_records}"
            )


def _flow_from_packets(observed: List[dict]) -> dict:
    flow = _connection_flow(observed)
    flow["retransmission_fraction"] = float(flow.get("retransmission_count", 0.0)) / max(
        float(flow.get("packets", 0.0)), 1.0
    )
    return flow


def packet_service_graphs(path: Path, expected_records: int, expected_snaplen: int):
    times: List[int] = []
    xs: List[np.ndarray] = []
    adjs: List[np.ndarray] = []
    masks: List[np.ndarray] = []
    current_bucket = None
    connections: Dict[tuple, List[dict]] = defaultdict(list)
    stats: dict = {}

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

    for packet in classic_packets(
        path,
        expected_records=expected_records,
        expected_snaplen=expected_snaplen,
        stats=stats,
    ):
        bucket = int(packet["t"] // WINDOW_SECONDS) * WINDOW_SECONDS
        if current_bucket is None:
            current_bucket = bucket
        elif bucket != current_bucket:
            if bucket < current_bucket:
                raise V102ContractError("Non-monotone packet timestamps")
            flush()
            current_bucket = bucket
        endpoints = sorted(
            [(packet["src"], packet["sport"]), (packet["dst"], packet["dport"])]
        )
        key = (endpoints[0], endpoints[1], packet["protocol"])
        connections[key].append(packet)
    flush()

    if stats.get("ipv4", 0) < 1000:
        raise V102ContractError(f"Too few decoded IPv4 packets: {stats.get('ipv4', 0)}")
    if len(times) < HISTORY + HORIZON:
        raise V102ContractError(f"Too few 10-second windows: {len(times)}")
    return (
        np.asarray(times, dtype=np.int64),
        np.asarray(xs, dtype=np.float32),
        np.asarray(adjs, dtype=np.float32),
        np.asarray(masks, dtype=np.float32),
        stats,
    )


def build_sequences(times, x, adj, mask):
    sx, sa, sm, future, cutoffs = [], [], [], [], []
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
        sx.append(hx)
        sa.append(ha)
        sm.append(hm)
        future.append(pooled_future)
        cutoffs.append(int(times[start + HISTORY - 1] + WINDOW_SECONDS))
    if not sx:
        raise V102ContractError("No contiguous 8-history/4-future sequence exists")
    return tuple(np.asarray(v) for v in (sx, sa, sm, future, cutoffs))


def infer_state(model: GraphWorldModel, x, adj, mask, batch_size: int = 64) -> np.ndarray:
    rows = []
    for start in range(0, len(x), batch_size):
        mean, _, _ = model.forward(
            x[start : start + batch_size],
            adj[start : start + batch_size],
            mask[start : start + batch_size],
            HORIZON,
        )
        rows.append(mean.data)
    return np.concatenate(rows, axis=0)


def pooled_history(x: np.ndarray, mask: np.ndarray) -> np.ndarray:
    return (x * mask[:, :, :, None]).sum(axis=2) / np.maximum(
        mask.sum(axis=2, keepdims=True), 1.0
    )


def evaluate(
    pcap: Path,
    model_path: Path,
    support_path: Path,
    prereg_path: Path,
    acquisition_path: Path,
    lock_path: Path,
) -> dict:
    prereg = json.loads(prereg_path.read_text(encoding="utf-8"))
    acquisition = json.loads(acquisition_path.read_text(encoding="utf-8"))
    lock = json.loads(lock_path.read_text(encoding="utf-8"))

    if prereg.get("status") != "HASH_PINNED_EVALUATION_PERMITTED" or prereg.get("evaluation_permitted") is not True:
        raise V102ContractError("V102 evaluation requires a committed hash-pinned preregistration")
    if acquisition.get("status") != "HASH_ACQUIRED_MODEL_NOT_RUN" or acquisition.get("evaluation_performed") is not False:
        raise V102ContractError("Invalid acquisition manifest state")
    if lock.get("status") != "ONE_SHOT_CONSUMED_BEFORE_INFERENCE":
        raise V102ContractError("Missing immutable pre-inference one-shot lock")
    if pcap.name != EXPECTED_CAPTURE:
        raise V102ContractError(f"Capture filename mismatch: {pcap.name}")

    observed_capture_sha = sha256_path(pcap)
    expected_capture_sha = acquisition["decompressed_sha256"]
    if observed_capture_sha != expected_capture_sha or observed_capture_sha != prereg["external_holdout"]["decompressed_sha256"]:
        raise V102ContractError("MAWI decompressed SHA-256 mismatch")
    if sha256_path(model_path) != EXPECTED_MODEL_SHA256 or EXPECTED_MODEL_SHA256 != prereg["registered_candidate"]["model_sha256"]:
        raise V102ContractError("Frozen V101 model SHA-256 mismatch")
    if sha256_path(support_path) != EXPECTED_SUPPORT_SHA256 or EXPECTED_SUPPORT_SHA256 != prereg["registered_candidate"]["support_gate_sha256"]:
        raise V102ContractError("Frozen V101 support-gate SHA-256 mismatch")
    if prereg["registered_candidate"]["adapter_contract_sha256"] != EXPECTED_ADAPTER_SHA256:
        raise V102ContractError("Frozen V101 adapter contract mismatch")

    model, metadata = GraphWorldModel.load(model_path)
    observed_contract = {
        "architecture": model.config["architecture"],
        "history_windows": int(metadata.get("history", -1)),
        "forecast_windows": int(metadata.get("horizon", -1)),
        "decoder": model.config["decoder"],
        "mode": metadata.get("mode"),
        "window_seconds": int(metadata.get("window_seconds", -1)),
        "max_nodes": int(metadata.get("max_nodes", -1)),
        "feature_dim": int(model.config["feature_dim"]),
        "packet_features_trained": bool(metadata.get("packet_features_trained", False)),
        "risk_head_trained": bool(metadata.get("risk_head_trained", False)),
        "hikari_used_for_fitting": bool(metadata.get("hikari_used_for_fitting", False)),
    }
    expected_contract = {
        "architecture": "gnn_lstm",
        "history_windows": HISTORY,
        "forecast_windows": HORIZON,
        "decoder": "residual",
        "mode": "service",
        "window_seconds": WINDOW_SECONDS,
        "max_nodes": MAX_NODES,
        "feature_dim": len(FEATURES),
        "packet_features_trained": True,
        "risk_head_trained": False,
        "hikari_used_for_fitting": False,
    }
    if observed_contract != expected_contract:
        raise V102ContractError(f"Frozen candidate contract mismatch: {observed_contract}")

    times, x, adj, mask, decode_stats = packet_service_graphs(
        pcap,
        expected_records=int(prereg["external_holdout"]["publisher_packet_count"]),
        expected_snaplen=int(prereg["external_holdout"]["publisher_caplen_bytes"]),
    )
    sx, sa, sm, target, cutoffs = build_sequences(times, x, adj, mask)
    pred = infer_state(model, sx, sa, sm)
    pooled = pooled_history(sx, sm)
    persistence = np.repeat(pooled[:, -1:, :], HORIZON, axis=1)

    model_mse = float(np.mean((pred - target) ** 2))
    persistence_mse = float(np.mean((persistence - target) ** 2))
    improvement = float((persistence_mse - model_mse) / persistence_mse) if persistence_mse > 0 else 0.0
    passed = bool(model_mse < persistence_mse)

    per_horizon = []
    for h in range(HORIZON):
        mm = float(np.mean((pred[:, h] - target[:, h]) ** 2))
        pm = float(np.mean((persistence[:, h] - target[:, h]) ** 2))
        per_horizon.append({
            "seconds_ahead": int((h + 1) * WINDOW_SECONDS),
            "model_mse": mm,
            "persistence_mse": pm,
            "improvement_vs_persistence": float((pm - mm) / pm) if pm > 0 else 0.0,
            "beats_persistence": bool(mm < pm),
        })

    gate = json.loads(support_path.read_text(encoding="utf-8"))
    scores = support_score(gate, sx, sm)
    threshold = float(gate["threshold"])
    supported = scores <= threshold
    supported_metrics = None
    if supported.any():
        smse = float(np.mean((pred[supported] - target[supported]) ** 2))
        spmse = float(np.mean((persistence[supported] - target[supported]) ** 2))
        supported_metrics = {
            "sequences": int(supported.sum()),
            "model_mse": smse,
            "persistence_mse": spmse,
            "improvement_vs_persistence": float((spmse - smse) / spmse) if spmse > 0 else 0.0,
            "beats_persistence": bool(smse < spmse),
        }

    packet_idx = FEATURES.index("packet_features_present")
    observed_nodes = mask > 0
    packet_values = x[:, :, packet_idx][observed_nodes]

    return {
        "schema_version": "v102.1",
        "status": "PASS" if passed else "FAIL",
        "gate": "frozen V101 packet-compatible model state MSE must be lower than persistence MSE on the exact preregistered MAWI capture",
        "dataset": {
            "name": "MAWI Working Group Traffic Archive",
            "samplepoint": "B",
            "capture": pcap.name,
            "sha256": observed_capture_sha,
            "publisher_packet_count": int(prereg["external_holdout"]["publisher_packet_count"]),
            "publisher_caplen_bytes": int(prereg["external_holdout"]["publisher_caplen_bytes"]),
        },
        "frozen_runtime": {
            "model_sha256": EXPECTED_MODEL_SHA256,
            "support_gate_sha256": EXPECTED_SUPPORT_SHA256,
            "adapter_contract_sha256": EXPECTED_ADAPTER_SHA256,
            "contract": observed_contract,
        },
        "adapter": {
            "schema": SCHEMA,
            "features": list(FEATURES),
            "feature_count": len(FEATURES),
            "mode": "service",
            "window_seconds": WINDOW_SECONDS,
            "max_nodes": MAX_NODES,
            "policy": "classic-PCAP snaplen-safe header decode; IPv4 total length supplies uncaptured payload length; PCAP original length supplies wire bytes",
            "policy_frozen_before_inference": True,
            "fit_on_mawi": False,
            "labels_accessed": False,
            "packet_records": int(decode_stats["records"]),
            "decoded_ipv4_packets": int(decode_stats["ipv4"]),
            "truncated_ipv4_packets": int(decode_stats["truncated_ipv4"]),
            "observed_windows": int(len(times)),
            "contiguous_sequences": int(len(sx)),
            "first_window_epoch": int(times[0]),
            "last_window_epoch": int(times[-1]),
            "packet_features_present_mean_on_observed_nodes": float(packet_values.mean()) if len(packet_values) else 0.0,
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
            "median_support_score": float(np.median(scores)),
            "max_support_score": float(scores.max()),
            "supported_only_state_metrics": supported_metrics,
            "interpretation": "Training-support diagnostic only; outside-support is abstention/context shift, not attack detection.",
        },
        "one_shot_integrity": {
            "pre_inference_lock_present": True,
            "retrained_on_mawi": False,
            "normalization_fit_on_mawi": False,
            "support_fit_on_mawi": False,
            "threshold_fit_on_mawi": False,
            "adapter_selected_on_mawi": False,
            "seed_or_checkpoint_selected_on_mawi": False,
            "rerun_for_claim_improvement": False,
            "cutoff_timestamps": cutoffs.astype(int).tolist(),
        },
        "claim_boundary": "Fresh external one-shot state-transition forecasting evidence only. No MAWI attack-label, recall/FPR, MITRE-stage, or successful-compromise claim is made.",
    }


def main() -> int:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--pcap", required=True, type=Path)
    p.add_argument("--model", required=True, type=Path)
    p.add_argument("--support-gate", required=True, type=Path)
    p.add_argument("--prereg", required=True, type=Path)
    p.add_argument("--acquisition", required=True, type=Path)
    p.add_argument("--lock", required=True, type=Path)
    p.add_argument("--output", required=True, type=Path)
    args = p.parse_args()
    if args.output.exists():
        p.error("V102 one-shot result already exists and is immutable")
    report = evaluate(
        args.pcap,
        args.model,
        args.support_gate,
        args.prereg,
        args.acquisition,
        args.lock,
    )
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report, indent=2, allow_nan=False) + "\n", encoding="utf-8")
    print(json.dumps(report, indent=2, allow_nan=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
