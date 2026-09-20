"""V68 real-CICAPT flow + packet telemetry contract audit.

This is a feature-evidence audit, not an attack-detection accuracy benchmark. It parses
a bounded prefix of each hash-pinned CICAPT capture using the production reader and
measures what was actually observed. A feature supported by code but absent in the
sample remains reported as zero rather than being fabricated as present.
"""
from __future__ import annotations

import argparse
import json
from collections import defaultdict
from itertools import islice
from pathlib import Path

import numpy as np

from .pcap_reader import packets
from .ps_complete import FEATURES, _connection_flow, summarize

REQUIRED_FLOW = {
    "flow_count_log", "bytes_log", "packets_log", "duration_ms_log",
    "syn_fraction", "ack_fraction", "fin_fraction", "rst_fraction",
    "psh_fraction", "urg_fraction", "backward_packet_fraction",
    "tcp_fraction", "udp_fraction", "iat_ms_log", "iat_variance_log", "iat_max_log",
}
REQUIRED_PACKET = {
    "ttl_mean_scaled", "ttl_variance_scaled", "tcp_window_log", "fragment_fraction",
    "payload_mean_log", "payload_variance_log", "payload_max_log",
    "unique_destination_ports_log", "sequential_port_transition_fraction",
    "random_port_transition_fraction", "retransmission_fraction", "retransmission_count_log",
}


def capture_format(path: Path):
    magic = path.read_bytes()[:4]
    if magic == b"\x0a\x0d\x0d\x0a":
        return "pcapng"
    if magic in {b"\xd4\xc3\xb2\xa1", b"\xa1\xb2\xc3\xd4", b"\x4d\x3c\xb2\xa1", b"\xa1\xb2\x3c\x4d"}:
        return "classic_pcap"
    return "unknown"


def audit_capture(path: Path, packet_limit: int, window_seconds: int = 10):
    grouped = defaultdict(lambda: defaultdict(list))
    decoded = []
    # The parser is lazy: islice stops after exactly packet_limit decoded IPv4 records,
    # so the safety ceiling can be above the sample without scanning the whole capture.
    for p in islice(packets(path, max_packets=max(packet_limit * 20, packet_limit + 1)), packet_limit):
        decoded.append(p)
        endpoints = sorted([(p["src"], p["sport"]), (p["dst"], p["dport"])])
        key = (endpoints[0], endpoints[1], p["protocol"])
        bucket = int(p["t"] // window_seconds) * window_seconds
        grouped[bucket][key].append(p)

    if len(decoded) < 1000:
        raise RuntimeError(f"Too few decoded IPv4 packets in {path}: {len(decoded)}")
    if len(grouped) < 2:
        raise RuntimeError(f"Too few timestamp windows in {path}: {len(grouped)}")

    vectors = []
    total_flows = 0
    retrans_total = 0
    scan_events = 0
    for _, connections in sorted(grouped.items()):
        flows = [_connection_flow(v) for v in connections.values()]
        total_flows += len(flows)
        retrans_total += int(sum(f.get("retransmission_count", 0) for f in flows))
        scan_events += int(sum(len(f.get("scan_events", [])) for f in flows))
        vectors.append(summarize(flows))
    matrix = np.asarray(vectors, dtype=np.float32)

    tcp = [p for p in decoded if p["protocol"] == "tcp"]
    udp = [p for p in decoded if p["protocol"] == "udp"]
    payload = [p for p in decoded if p["payload_len"] > 0]
    fragmented = [p for p in decoded if p["frag"]]
    ttls = np.asarray([p["ttl"] for p in decoded], dtype=float)
    wins = np.asarray([p["win"] for p in tcp], dtype=float) if tcp else np.asarray([], dtype=float)
    payloads = np.asarray([p["payload_len"] for p in decoded], dtype=float)

    observed = {}
    for name in sorted(REQUIRED_FLOW | REQUIRED_PACKET | {
        "packet_features_present", "iat_present", "tcp_window_present", "payload_present", "scan_sequence_present"
    }):
        idx = FEATURES.index(name)
        observed[name] = {
            "nonzero_windows": int((matrix[:, idx] > 0).sum()),
            "window_fraction": float((matrix[:, idx] > 0).mean()),
            "max_normalized_value": float(matrix[:, idx].max()),
        }

    return {
        "path": str(path),
        "format_detected_from_magic": capture_format(path),
        "sample_contract": "first N decoded IPv4 packets; exact for this bounded prefix only",
        "decoded_ipv4_packets": len(decoded),
        "windows_10s": len(grouped),
        "bidirectional_connection_flows": total_flows,
        "tcp_packets": len(tcp),
        "udp_packets": len(udp),
        "payload_packets": len(payload),
        "fragmented_packets": len(fragmented),
        "duplicate_positive_payload_segments": retrans_total,
        "scan_events": scan_events,
        "ttl": {"min": float(ttls.min()), "mean": float(ttls.mean()), "max": float(ttls.max()), "variance": float(ttls.var())},
        "tcp_window": {
            "samples": int(len(wins)),
            "mean": float(wins.mean()) if len(wins) else None,
            "variance": float(wins.var()) if len(wins) else None,
        },
        "payload_size": {"mean": float(payloads.mean()), "variance": float(payloads.var()), "max": float(payloads.max())},
        "feature_observation": observed,
    }


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--captures", nargs="+", required=True)
    p.add_argument("--output", required=True)
    p.add_argument("--packet-limit", type=int, default=200000)
    args = p.parse_args()
    if args.packet_limit < 1000:
        p.error("packet-limit must be >=1000")

    missing = (REQUIRED_FLOW | REQUIRED_PACKET) - set(FEATURES)
    if missing:
        raise RuntimeError(f"PS feature schema missing required attributes: {sorted(missing)}")

    result = {
        "protocol": "V68 hash-pinned CICAPT real-PCAP flow+packet feature audit",
        "claim_boundary": (
            "Feature extraction evidence from bounded prefixes of real public CICAPT network captures. "
            "This audit proves ingestion/feature availability, not attack recall, forecasting lead time, or production performance."
        ),
        "required_flow_features": sorted(REQUIRED_FLOW),
        "required_packet_features": sorted(REQUIRED_PACKET),
        "all_required_features_in_schema": True,
        "packet_limit_per_capture": int(args.packet_limit),
        "captures": [audit_capture(Path(x), args.packet_limit) for x in args.captures],
    }
    out = Path(args.output)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(result, indent=2, allow_nan=False) + "\n")
    print(json.dumps(result, indent=2), flush=True)


if __name__ == "__main__":
    main()
