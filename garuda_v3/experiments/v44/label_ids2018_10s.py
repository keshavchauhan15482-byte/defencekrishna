"""Apply conservative schedule-assisted weak labels to V44 10-second graphs.

Labels are for development/runtime-regression evidence only. They are not packet-level,
compromise, MITRE-stage, or zero-day ground truth.
"""
from __future__ import annotations

import argparse
import json
from collections import defaultdict
from datetime import datetime, timedelta, timezone
from pathlib import Path
import numpy as np

from garuda_v3.data import load_dataset, save_dataset
from garuda_v3.ids2018_label import SCHEDULE
from garuda_v3.pcap_reader import packets
from garuda_v3.experiments.v44.runtime_contract import (
    EVIDENCE_SCOPE, WINDOW_SECONDS, assert_runtime_dataset,
)

BOUNDARY_GUARD_SECONDS = 60
DEFAULT_SPLIT = {
    "train": ["Thursday-22-02-2018"],
    "validation": ["Friday-23-02-2018"],
    "test": ["Thursday-01-03-2018", "Friday-02-03-2018"],
}


def schedule_ranges(day: str, intervals: list[tuple[str, str]]) -> list[tuple[int, int]]:
    ranges = []
    for start, end in intervals:
        values = []
        for value in (start, end):
            dt = datetime.fromisoformat(day + "T" + value).replace(tzinfo=timezone.utc)
            values.append(int((dt + timedelta(hours=4)).timestamp()))
        ranges.append(tuple(values))
    return ranges


def label_one(name: str, output_root: Path) -> Path:
    if name not in SCHEDULE:
        raise ValueError(f"No frozen schedule for {name}")
    day, attacker, family, intervals = SCHEDULE[name]
    graph_path = output_root / "graphs" / f"{name}.npz"
    clean_path = output_root / "clean" / f"{name}.pcap"
    d = load_dataset(graph_path)
    assert_runtime_dataset(d)

    peer = defaultdict(int)
    for packet in packets(clean_path, max_packets=1_000_000):
        if attacker in (packet["src"], packet["dst"]):
            peer[int(packet["t"] // WINDOW_SECONDS) * WINDOW_SECONDS] += 1

    ranges = schedule_ranges(day, intervals)
    y = []
    for raw_t in d["times"]:
        t = int(raw_t)
        full = any(
            a + BOUNDARY_GUARD_SECONDS <= t
            and t + WINDOW_SECONDS <= b - BOUNDARY_GUARD_SECONDS
            for a, b in ranges
        )
        overlap = any(
            t < b + BOUNDARY_GUARD_SECONDS
            and t + WINDOW_SECONDS > a - BOUNDARY_GUARD_SECONDS
            for a, b in ranges
        )
        matched = bool(peer[t])
        y.append(1 if full and matched else (-1 if overlap or matched else 0))

    d["y"] = np.asarray(y, dtype=np.int8)
    d["metadata"].update(
        attack_family=family,
        annotation_status="schedule-assisted weak labels; not independently verified packet truth",
        label_method=(
            "1: published interval interior with 60-second guard AND observed attacker endpoint; "
            "-1: guarded boundaries, interval without matched endpoint, or attacker outside schedule; "
            "0: no matched attacker and outside guarded schedule (benchmark benign assumption)"
        ),
        schedule_source="https://www.unb.ca/cic/datasets/ids-2018.html",
        schedule_utc_ranges=ranges,
        timezone_assumption=(
            "Published wall time interpreted UTC-04:00; consistent with prior web alignment, "
            "not a publisher-confirmed timezone declaration"
        ),
        annotation_intervals=[],
        incidents=[],
        stage_supervised=False,
        evidence_scope=EVIDENCE_SCOPE,
    )
    dest = output_root / "labelled" / f"{name}.npz"
    save_dataset(d, dest)
    return dest


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output-root", default="datasets/v44_runtime")
    args = parser.parse_args()
    root = Path(args.output_root)
    root.mkdir(parents=True, exist_ok=True)
    (root / "split.json").write_text(json.dumps(DEFAULT_SPLIT, indent=2))

    paths = []
    for name in sum(DEFAULT_SPLIT.values(), []):
        dest = label_one(name, root)
        d = load_dataset(dest)
        values, counts = np.unique(d["y"], return_counts=True)
        print("V44_LABEL", name, dict(zip(values.tolist(), counts.tolist())), flush=True)
        paths.append(str(dest))
    (root / "label_manifest.json").write_text(json.dumps({
        "split": DEFAULT_SPLIT,
        "labelled_graphs": paths,
        "window_seconds": WINDOW_SECONDS,
        "evidence_scope": EVIDENCE_SCOPE,
        "weak_supervision": True,
        "fresh_final_holdout": False,
    }, indent=2))


if __name__ == "__main__":
    main()
