"""SIH problem-statement-complete packet/flow feature extraction.

This is an additive V46 schema.  It does not change or reinterpret the historical
Garuda v3.1 checkpoints.  Raw packet captures carry *unknown* attack truth until
an explicit reviewed annotation is attached.  The optional IDS2018 schedule
helper is development-only weak supervision and is never release evidence.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import math
from collections import Counter, defaultdict
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Iterable

import numpy as np

from .annotations import annotate
from .data import PORTS, SERVICE_NODES
from .pcap_reader import packets as read_packets

SCHEMA = "garuda-observed-graph-v46-ps-complete"
FEATURES = [
    "flow_count_log", "bytes_log", "packets_log", "duration_ms_log",
    "syn_fraction", "ack_fraction", "rst_fraction", "fin_fraction",
    "psh_fraction", "urg_fraction",
    "backward_packet_fraction", "tcp_fraction", "udp_fraction", "active",
    "iat_ms_log", "iat_variance_log", "iat_max_log",
    "tcp_window_log", "ttl_mean_scaled", "ttl_variance_scaled",
    "fragment_fraction",
    "payload_mean_log", "payload_variance_log", "payload_max_log",
    "unique_destination_ports_log",
    "sequential_port_transition_fraction", "random_port_transition_fraction",
    "retransmission_fraction", "retransmission_count_log",
    "packet_features_present", "iat_present", "tcp_window_present",
    "payload_present", "scan_sequence_present",
]

IDS2018_WEAK_SCHEDULE = {
    "Thursday-22-02-2018": ("2018-02-22", "18.218.115.60", "web", [("10:17", "11:24"), ("13:50", "14:29"), ("16:15", "16:29")]),
    "Friday-23-02-2018": ("2018-02-23", "18.218.115.60", "web", [("10:03", "11:03"), ("13:00", "14:10"), ("15:05", "15:18")]),
    "Thursday-01-03-2018": ("2018-03-01", "13.58.225.34", "infiltration", [("09:57", "10:55"), ("14:00", "15:37")]),
    "Friday-02-03-2018": ("2018-03-02", "18.219.211.138", "botnet", [("10:11", "11:34"), ("14:24", "15:55")]),
}


def _sha256(path: str | Path) -> str:
    h = hashlib.sha256()
    with Path(path).open("rb") as handle:
        while block := handle.read(1024 * 1024):
            h.update(block)
    return h.hexdigest()


def _logscale(value: float, scale: float) -> float:
    value = max(0.0, float(value))
    return min(1.0, math.log1p(value) / math.log1p(scale))


def _weighted_mean(flows: list[dict], key: str, weight_key: str = "packets") -> float:
    pairs = [(float(f.get(key, 0.0)), max(float(f.get(weight_key, 0.0)), 0.0)) for f in flows if f.get(key) is not None]
    total = sum(w for _, w in pairs)
    if not pairs:
        return 0.0
    if total <= 0:
        return sum(v for v, _ in pairs) / len(pairs)
    return sum(v * w for v, w in pairs) / total


def _scan_statistics(flows: list[dict]) -> tuple[int, float, float, bool]:
    events = sorted((event for flow in flows for event in flow.get("scan_events", [])), key=lambda e: e[0])
    ports = {int(port) for _, _, port in events if int(port) > 0}
    transitions = []
    previous = None
    for event in events:
        _, destination, port = event
        port = int(port)
        if port <= 0:
            continue
        if previous is not None and previous[0] == destination and previous[1] != port:
            transitions.append(abs(port - previous[1]))
        previous = (destination, port)
    if not transitions:
        return len(ports), 0.0, 0.0, False
    sequential = sum(delta == 1 for delta in transitions) / len(transitions)
    randomized = sum(delta > 1 for delta in transitions) / len(transitions)
    return len(ports), float(sequential), float(randomized), True


def summarize(flows: list[dict]) -> np.ndarray:
    """Summarize node-local observations using only telemetry available by cutoff."""
    if not flows:
        return np.zeros(len(FEATURES), dtype=np.float32)
    n = len(flows)
    packet_count = sum(float(f["packets"]) for f in flows)
    flag_totals = [sum(float(f["flags"][i]) for f in flows) for i in range(6)]
    unique_ports, sequential, randomized, scan_present = _scan_statistics(flows)
    payload_present = any(bool(f.get("payload_present")) for f in flows)
    iat_present = any(f.get("iat_ms") is not None for f in flows)
    tcp_window_present = any(bool(f.get("window_present")) for f in flows)
    retrans_count = sum(float(f.get("retransmission_count", 0.0)) for f in flows)
    values = [
        _logscale(n, 10000),
        _logscale(sum(float(f["bytes"]) for f in flows), 1e9),
        _logscale(packet_count, 1e7),
        _logscale(sum(float(f["duration"]) for f in flows) * 1000 / n, 1e7),
        *[min(1.0, total / max(packet_count, 1.0)) for total in flag_totals],
        min(1.0, sum(float(f["bwd"]) for f in flows) / max(packet_count, 1.0)),
        sum(f["protocol"] == "tcp" for f in flows) / n,
        sum(f["protocol"] == "udp" for f in flows) / n,
        1.0,
        _logscale(_weighted_mean(flows, "iat_ms"), 1e6),
        _logscale(_weighted_mean(flows, "iat_variance"), 1e12),
        _logscale(max((float(f.get("iat_max") or 0.0) for f in flows), default=0.0), 1e6),
        _logscale(_weighted_mean(flows, "tcp_window"), 65535),
        min(1.0, _weighted_mean(flows, "ttl_mean") / 255.0),
        min(1.0, _weighted_mean(flows, "ttl_var") / 1000.0),
        min(1.0, _weighted_mean(flows, "fragment_fraction")),
        _logscale(_weighted_mean(flows, "payload_mean"), 65535),
        _logscale(_weighted_mean(flows, "payload_variance"), 1e9),
        _logscale(max((float(f.get("payload_max") or 0.0) for f in flows), default=0.0), 65535),
        _logscale(unique_ports, 65535),
        sequential,
        randomized,
        min(1.0, retrans_count / max(packet_count, 1.0)),
        _logscale(retrans_count, 100000),
        sum(bool(f.get("packet_present")) for f in flows) / n,
        float(iat_present),
        float(tcp_window_present),
        float(payload_present),
        float(scan_present),
    ]
    result = np.asarray(values, dtype=np.float32)
    if result.shape != (len(FEATURES),) or not np.isfinite(result).all() or np.any((result < 0) | (result > 1)):
        raise ValueError("Invalid PS-complete feature vector")
    return result


def graph_snapshot(flows: list[dict], mode: str = "host", max_nodes: int = 128):
    if mode not in {"host", "service"}:
        raise ValueError("mode must be host or service")
    if mode == "service":
        names = list(SERVICE_NODES)
    else:
        if any(not f.get("src") or not f.get("dst") for f in flows):
            raise ValueError("Host graph requires source/destination endpoints")
        names = sorted({f[k] for f in flows for k in ("src", "dst")})
    if len(names) > max_nodes:
        raise ValueError(f"Graph exceeds {max_nodes} nodes; partition by sensor/subnet instead of dropping hosts")
    mapping = {name: i for i, name in enumerate(names)}
    node_flows: dict[int, list[dict]] = defaultdict(list)
    adjacency = np.zeros((max_nodes, max_nodes), dtype=np.float32)
    for flow in flows:
        if mode == "service":
            a = mapping[f"protocol:{flow['protocol']}"]
            service = f"service:{flow['port']}" if flow["port"] in PORTS else "service:other"
            b = mapping[service]
        else:
            a, b = mapping[flow["src"]], mapping[flow["dst"]]
        node_flows[a].append(flow)
        if a != b:
            node_flows[b].append(flow)
        adjacency[b, a] += 1.0
    features = np.zeros((max_nodes, len(FEATURES)), dtype=np.float32)
    mask = np.zeros(max_nodes, dtype=np.float32)
    for node, observed in node_flows.items():
        features[node] = summarize(observed)
        mask[node] = 1.0
    return features, adjacency, mask, names


def _connection_flow(observed: list[dict]) -> dict:
    observed.sort(key=lambda p: p["t"])
    first = observed[0]
    forward = (first["src"], first["sport"])
    seen = set()
    retrans = 0
    for packet in observed:
        segment = (packet["src"], packet["sport"], packet["seq"], packet["payload_len"])
        if packet["protocol"] == "tcp" and packet["payload_len"] > 0:
            if segment in seen:
                retrans += 1
            seen.add(segment)
    times = np.asarray([p["t"] for p in observed], dtype=np.float64)
    iats = np.diff(times) * 1000.0
    ttls = np.asarray([p["ttl"] for p in observed], dtype=np.float64)
    payloads = np.asarray([p["payload_len"] for p in observed], dtype=np.float64)
    windows = [p["win"] for p in observed if p["protocol"] == "tcp"]
    scan_events = [(float(p["t"]), p["dst"], int(p["dport"])) for p in observed if p["protocol"] in {"tcp", "udp"} and p["dport"]]
    return {
        "src": first["src"], "dst": first["dst"], "port": int(first["dport"]), "protocol": first["protocol"],
        "start": float(times[0]), "end": float(times[-1]), "duration": float(times[-1] - times[0]),
        "packets": len(observed), "bytes": sum(int(p["bytes"]) for p in observed),
        "bwd": sum((p["src"], p["sport"]) != forward for p in observed),
        "flags": [sum(bool(p["flags"] & bit) for p in observed) for bit in (0x02, 0x10, 0x04, 0x01, 0x08, 0x20)],
        "iat_ms": float(iats.mean()) if len(iats) else None,
        "iat_variance": float(iats.var()) if len(iats) else None,
        "iat_max": float(iats.max()) if len(iats) else None,
        "tcp_window": float(np.mean(windows)) if windows else 0.0,
        "ttl_mean": float(ttls.mean()), "ttl_var": float(ttls.var()),
        "fragment_fraction": sum(bool(p["frag"]) for p in observed) / len(observed),
        "payload_mean": float(payloads.mean()), "payload_variance": float(payloads.var()), "payload_max": float(payloads.max()),
        "payload_present": bool(np.any(payloads > 0)),
        "retransmission_count": retrans,
        "packet_present": True, "window_present": bool(windows), "scan_events": scan_events,
        "label": None,
    }


def convert_pcap(path: str | Path, *, campaign: str, family: str = "unknown", mode: str = "host",
                 window_seconds: int = 10, max_packets: int = 2_000_000, max_nodes: int = 128,
                 drop_last: bool = True) -> dict:
    if window_seconds != 10:
        raise ValueError("V46 SIH evidence contract is frozen at 10-second windows")
    if max_packets < 1 or max_packets > 10_000_000:
        raise ValueError("max_packets must be 1..10,000,000")
    if mode == "service" and max_nodes < len(SERVICE_NODES):
        raise ValueError("max_nodes too small for service vocabulary")
    groups: dict[int, dict[tuple, list[dict]]] = defaultdict(lambda: defaultdict(list))
    record_count = 0
    for packet in read_packets(path, max_packets=max_packets):
        record_count += 1
        endpoints = sorted([(packet["src"], packet["sport"]), (packet["dst"], packet["dport"])])
        key = (endpoints[0], endpoints[1], packet["protocol"])
        bucket = int(packet["t"] // window_seconds) * window_seconds
        groups[bucket][key].append(packet)
    if len(groups) < 2:
        raise ValueError("Need at least two observed packet windows")
    xs, adjs, masks, times, names = [], [], [], [], []
    for bucket, connections in sorted(groups.items()):
        flows = [_connection_flow(observed) for observed in connections.values()]
        x, adjacency, mask, node_names = graph_snapshot(flows, mode=mode, max_nodes=max_nodes)
        xs.append(x); adjs.append(adjacency); masks.append(mask); times.append(bucket); names.append(node_names)
    stop = -1 if drop_last else None
    used_times = times[:stop]
    metadata = {
        "schema": SCHEMA, "features": FEATURES, "mode": mode, "window_seconds": window_seconds,
        "max_nodes": max_nodes, "source_sha256": _sha256(path), "source_filename": Path(path).name,
        "campaign_id": campaign, "attack_family": family, "dataset_id": "CIC-IDS-2018",
        "packet_features": True, "flow_features": True, "raw_packet_records": record_count,
        "node_names": names[:stop], "windows": len(used_times), "synthetic": False,
        "label_provenance": "raw PCAP establishes network state only; attack labels remain unknown until explicit annotation",
        "runtime_evidence": "network-only", "risk_labels_attached": False,
        "feature_contract": "SIH flow+packet requested attributes including PSH/URG, IAT mean/variance/max, payload distribution, scan transitions and retransmission count",
        "scan_feature_semantics": "sequential/random port-transition fractions are descriptive telemetry features, not attack labels",
        "limitations": ["retransmission is duplicate positive-payload TCP segment indicator, not full stream reassembly", "classic PCAP Ethernet/raw IPv4 only"],
    }
    count = len(used_times)
    return {
        "x": np.asarray(xs[:stop], dtype=np.float32), "adj": np.asarray(adjs[:stop], dtype=np.float32),
        "mask": np.asarray(masks[:stop], dtype=np.float32), "y": np.full(count, -1, dtype=np.int8),
        "times": np.asarray(used_times, dtype=np.int64), "metadata": metadata,
    }


def attach_ids2018_weak_schedule(data: dict, pcap_path: str | Path, campaign: str, *, max_packets: int = 2_000_000) -> dict:
    """Attach historical schedule-assisted development labels; never compromise/stage truth."""
    if campaign not in IDS2018_WEAK_SCHEDULE:
        raise ValueError("No frozen weak IDS2018 schedule for campaign")
    day, attacker, family, intervals = IDS2018_WEAK_SCHEDULE[campaign]
    step = int(data["metadata"]["window_seconds"])
    observed = Counter()
    for packet in read_packets(pcap_path, max_packets=max_packets):
        if attacker in (packet["src"], packet["dst"]):
            observed[int(packet["t"] // step) * step] += 1
    ranges = []
    for start, end in intervals:
        a, b = [int((datetime.fromisoformat(day + "T" + value).replace(tzinfo=timezone.utc) + timedelta(hours=4)).timestamp()) for value in (start, end)]
        ranges.append((a, b))
    labels = []
    for t in data["times"]:
        t = int(t)
        full = any(a + step <= t and t + step <= b - step for a, b in ranges)
        overlap = any(t < b + step and t + step > a - step for a, b in ranges)
        has_attacker = observed[t] > 0
        labels.append(1 if full and has_attacker else (-1 if overlap or has_attacker else 0))
    result = {**data, "metadata": dict(data["metadata"])}
    result["y"] = np.asarray(labels, dtype=np.int8)
    result["metadata"].update({
        "attack_family": family, "risk_labels_attached": True,
        "annotation_status": "schedule-assisted weak labels; development diagnostic only",
        "label_method": "1=published interval interior plus observed attacker endpoint; boundary/conflict=unknown; outside schedule without attacker=benchmark benign assumption",
        "schedule_source": "https://www.unb.ca/cic/datasets/ids-2018.html",
        "schedule_utc_ranges": ranges,
        "timezone_assumption": "published wall time interpreted UTC-04:00; convention remains unverified",
        "verified_incident_records": 0, "stage_supervised": False,
        "release_evidence_eligible": False,
    })
    return result


def save_dataset(data: dict, output: str | Path) -> None:
    output = Path(output)
    output.parent.mkdir(parents=True, exist_ok=True)
    payload = {k: v for k, v in data.items() if k != "metadata"}
    np.savez_compressed(output, **payload, metadata=json.dumps(data["metadata"], sort_keys=True))


def load_dataset(path: str | Path) -> dict:
    with np.load(path, allow_pickle=False) as z:
        data = {k: z[k] for k in ("x", "adj", "mask", "y", "times")}
        if "stage_y" in z:
            data["stage_y"] = z["stage_y"]
        data["metadata"] = json.loads(str(z["metadata"]))
    meta = data["metadata"]
    if meta.get("schema") != SCHEMA or list(meta.get("features", [])) != FEATURES:
        raise ValueError("V46 feature schema mismatch")
    if data["x"].shape[-1] != len(FEATURES):
        raise ValueError("V46 feature dimension mismatch")
    if not np.isin(data["y"], [-1, 0, 1]).all():
        raise ValueError("labels must be -1/0/1")
    return data


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("pcap")
    parser.add_argument("--output", required=True)
    parser.add_argument("--campaign", required=True)
    parser.add_argument("--family", default="unknown")
    parser.add_argument("--mode", choices=["host", "service"], default="host")
    parser.add_argument("--max-nodes", type=int, default=128)
    parser.add_argument("--max-packets", type=int, default=2_000_000)
    parser.add_argument("--weak-ids2018-schedule", action="store_true")
    parser.add_argument("--annotations", help="Reviewed interval/stage JSON; mutually exclusive with weak schedule")
    args = parser.parse_args()
    if args.weak_ids2018_schedule and args.annotations:
        parser.error("Choose reviewed annotations or weak development schedule, not both")
    output = Path(args.output)
    if output.exists():
        parser.error("Output already exists; evidence files are immutable")
    data = convert_pcap(args.pcap, campaign=args.campaign, family=args.family, mode=args.mode,
                        max_nodes=args.max_nodes, max_packets=args.max_packets)
    if args.weak_ids2018_schedule:
        data = attach_ids2018_weak_schedule(data, args.pcap, args.campaign, max_packets=args.max_packets)
    elif args.annotations:
        document = json.loads(Path(args.annotations).read_text())
        data = annotate(data, document)
        data["metadata"]["risk_labels_attached"] = True
        data["metadata"]["release_evidence_eligible"] = False
        data["metadata"]["release_evidence_note"] = "annotation references still require independent verification before release claims"
    save_dataset(data, output)
    print(json.dumps({
        "schema": SCHEMA, "features": len(FEATURES), "windows": len(data["times"]),
        "labels": {str(v): int((data["y"] == v).sum()) for v in (-1, 0, 1)},
        "campaign": args.campaign, "family": data["metadata"].get("attack_family"),
        "release_evidence_eligible": bool(data["metadata"].get("release_evidence_eligible", False)),
    }, indent=2))


if __name__ == "__main__":
    main()
