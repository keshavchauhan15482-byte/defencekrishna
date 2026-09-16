"""Build exact 10-second V44 packet graphs from checked-in IDS2018 PCAPs.

This is runtime-compatibility/development evidence only. It does not create a fresh
untouched final holdout and does not alter the archived V15 experiment.
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path
import numpy as np

from garuda_v3.data import MAX_NODES, save_dataset
from garuda_v3.ids2018_prepare import clean
from garuda_v3.pcap import convert_pcap
from garuda_v3.experiments.v44.runtime_contract import (
    EVIDENCE_SCOPE, WINDOW_SECONDS, assert_runtime_dataset,
)


def build_one(raw_path: Path, output_root: Path, mode: str) -> Path:
    output_root.mkdir(parents=True, exist_ok=True)
    cleaned, audit = clean(raw_path, output_root, step=WINDOW_SECONDS)
    data = convert_pcap(
        cleaned,
        mode=mode,
        window_seconds=WINDOW_SECONDS,
        max_packets=1_000_000,
        max_nodes=MAX_NODES,
    )
    keep = ~np.isin(data["times"], audit["excluded_windows"])
    for key in ("x", "adj", "mask", "y", "times"):
        data[key] = data[key][keep]
    data["metadata"]["node_names"] = [
        names for names, ok in zip(data["metadata"]["node_names"], keep) if ok
    ]
    data["metadata"].update(
        windows=len(data["times"]),
        campaign_id=raw_path.stem,
        original_sha256=audit["original_sha256"],
        preprocessing_audit=audit,
        evidence_scope=EVIDENCE_SCOPE,
        v44_runtime_contract=True,
    )
    assert_runtime_dataset(data)
    dest = output_root / "graphs" / f"{raw_path.stem}.npz"
    save_dataset(data, dest)
    return dest


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source-root", default="datasets/ids2018")
    parser.add_argument("--output-root", default="datasets/v44_runtime")
    parser.add_argument("--mode", choices=("service", "host"), default="service")
    args = parser.parse_args()

    source_root = Path(args.source_root)
    output_root = Path(args.output_root)
    raw = sorted((source_root / "raw").glob("*.pcap"))
    if not raw:
        raise SystemExit("No IDS2018 PCAPs found; V44 refuses synthetic fallback")

    results = []
    for path in raw:
        dest = build_one(path, output_root, args.mode)
        results.append(str(dest))
        print("V44_GRAPH", dest, flush=True)
    (output_root / "prepare_manifest.json").write_text(json.dumps({
        "window_seconds": WINDOW_SECONDS,
        "max_nodes": MAX_NODES,
        "mode": args.mode,
        "evidence_scope": EVIDENCE_SCOPE,
        "graphs": results,
        "fresh_final_holdout": False,
    }, indent=2))


if __name__ == "__main__":
    main()
