"""V69 CICAPT publisher-stage ↔ network-time alignment audit.

This audit answers a prerequisite question before any supervised MITRE-stage score is
reported: do the real Phase-2 packet timestamps actually cover the publisher-labelled
stage events with enough *unique network windows* per required stage?

No classifier is trained here.  The script intentionally fails closed on evidence:
provenance rows marked ``network_stage_validated=false`` remain publisher labels, and
multiple provenance rows at the same timestamp count as one network supervision event.
"""
from __future__ import annotations

import argparse
import json
from collections import Counter
from pathlib import Path

from .pcap_reader import packets

WINDOW_SECONDS = 10
PS_STAGE_MAP = {
    "discovery": "Reconnaissance/Discovery",
    "initialAccess": "Initial Access",
    "lateralMovement": "Lateral Movement",
    "CandC": "Command & Control",
    "exfiltration": "Exfiltration",
}


def bucket(t: float) -> int:
    return int(float(t) // WINDOW_SECONDS) * WINDOW_SECONDS


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--capture", required=True)
    p.add_argument("--timeline", required=True)
    p.add_argument("--output", required=True)
    p.add_argument("--packet-limit", type=int, default=12_000_000)
    args = p.parse_args()

    timeline = json.loads(Path(args.timeline).read_text())
    events = timeline.get("events", [])
    required = []
    for e in events:
        src = str(e.get("publisher_stage", ""))
        if src not in PS_STAGE_MAP:
            continue
        if e.get("epoch") is None:
            continue
        required.append({
            "epoch": float(e["epoch"]),
            "bucket": bucket(float(e["epoch"])),
            "publisher_stage": src,
            "ps_stage": PS_STAGE_MAP[src],
            "network_stage_validated": bool(e.get("network_stage_validated", False)),
        })

    # Collapse duplicate provenance entities at identical stage/time into one potential
    # network supervision point. This avoids inflating stage support.
    unique_events = {}
    for e in required:
        unique_events[(e["bucket"], e["ps_stage"])] = e
    required = sorted(unique_events.values(), key=lambda x: (x["bucket"], x["ps_stage"]))
    event_buckets = {e["bucket"] for e in required}

    capture = Path(args.capture)
    seen_buckets = set()
    decoded = 0
    first_t = None
    last_t = None
    for pkt in packets(capture, max_packets=args.packet_limit):
        decoded += 1
        t = float(pkt["t"])
        if first_t is None:
            first_t = t
        last_t = t
        b = bucket(t)
        if b in event_buckets:
            seen_buckets.add(b)
        if decoded >= args.packet_limit:
            break

    if decoded == 0:
        raise RuntimeError("No decoded IPv4 packets")

    all_counts = Counter(e["ps_stage"] for e in required)
    aligned = [e for e in required if e["bucket"] in seen_buckets]
    aligned_counts = Counter(e["ps_stage"] for e in aligned)
    unvalidated_aligned = sum(not e["network_stage_validated"] for e in aligned)

    # A defensible 5-class network-stage metric needs more than one/few unique windows.
    # 20 is a predeclared minimum for a basic held-out per-class estimate; it is not a
    # guarantee of production-quality evidence.
    min_unique_for_metric = 20
    stage_support = {}
    for stage in PS_STAGE_MAP.values():
        n = int(aligned_counts.get(stage, 0))
        stage_support[stage] = {
            "publisher_unique_event_windows_total": int(all_counts.get(stage, 0)),
            "aligned_network_windows_in_scanned_capture": n,
            "minimum_for_basic_per_class_metric": min_unique_for_metric,
            "basic_metric_support_sufficient": bool(n >= min_unique_for_metric),
        }

    report = {
        "protocol": "V69 CICAPT publisher-stage/network-time alignment prerequisite audit",
        "claim_boundary": (
            "Publisher tactic labels are aligned to exact 10-second packet windows by timestamp only. "
            "The source timeline explicitly marks these labels network_stage_validated=false, so this audit "
            "does not claim supervised network-stage accuracy. It determines whether such a metric is supportable."
        ),
        "capture": str(capture),
        "timeline": str(args.timeline),
        "timeline_source_sha256": timeline.get("source_sha256"),
        "packet_limit": int(args.packet_limit),
        "decoded_ipv4_packets": int(decoded),
        "capture_time": {"first_epoch": first_t, "last_epoch": last_t, "span_seconds": float(last_t-first_t)},
        "stage_mapping": PS_STAGE_MAP,
        "duplicate_provenance_rows_collapsed_by_stage_and_10s_bucket": True,
        "unique_required_publisher_event_windows": len(required),
        "aligned_required_event_windows": len(aligned),
        "aligned_events_marked_network_stage_validated_false": int(unvalidated_aligned),
        "stage_support": stage_support,
        "all_five_stages_support_basic_metric": all(x["basic_metric_support_sufficient"] for x in stage_support.values()),
        "supervised_network_stage_f1_release_claim_allowed": False,
        "reason": (
            "Alignment alone does not validate that a provenance tactic label applies to the network window; "
            "a release F1 also requires sufficient independent per-stage windows and a frozen train/test protocol."
        ),
    }
    out = Path(args.output)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(report, indent=2, allow_nan=False) + "\n")
    print(json.dumps(report, indent=2), flush=True)


if __name__ == "__main__":
    main()
