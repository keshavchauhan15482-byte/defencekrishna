"""Build exact 10-second V44 packet graphs from checked-in IDS2018 PCAPs.

This is runtime-compatibility/development evidence only. It does not create a fresh
untouched final holdout and does not alter the archived V15 experiment.
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path
import numpy as np

from garuda_v3.data import MAX_NODES, SERVICE_NODES, save_dataset
from garuda_v3.ids2018_prepare import clean
from garuda_v3.pcap import convert_pcap
from garuda_v3.experiments.v44.runtime_contract import (
    EVIDENCE_SCOPE, WINDOW_SECONDS, assert_runtime_dataset,
)


def densify_service_windows(data: dict, excluded_windows=()) -> dict:
    """Represent real closed no-packet buckets as explicit zero-state service graphs.

    Missing buckets between the first and last complete observed bucket mean the sensor saw
    no IP packet in that closed 10-second interval. They are valid zero-traffic observations,
    not synthetic traffic. Windows known to contain corrupt/truncated records stay absent.
    """
    if data["metadata"].get("mode") != "service":
        raise ValueError("V44 empty-window densification is defined only for service graphs")
    times = np.asarray(data["times"], dtype=np.int64)
    if len(times) < 2:
        raise ValueError("Need at least two complete packet buckets for V44 densification")
    step = int(data["metadata"]["window_seconds"])
    if step != WINDOW_SECONDS:
        raise ValueError("V44 densification requires exact 10-second windows")

    excluded = {int(t) for t in excluded_windows}
    full = np.arange(int(times[0]), int(times[-1]) + step, step, dtype=np.int64)
    full = np.asarray([t for t in full if int(t) not in excluded], dtype=np.int64)
    index = {int(t): i for i, t in enumerate(times)}

    xs, adjs, masks, ys, names = [], [], [], [], []
    empty = 0
    for raw_t in full:
        t = int(raw_t)
        if t in index:
            i = index[t]
            xs.append(data["x"][i]); adjs.append(data["adj"][i]); masks.append(data["mask"][i])
            ys.append(data["y"][i]); names.append(data["metadata"]["node_names"][i])
        else:
            empty += 1
            xs.append(np.zeros_like(data["x"][0]))
            adjs.append(np.zeros_like(data["adj"][0]))
            masks.append(np.zeros_like(data["mask"][0]))
            ys.append(-1)
            names.append(list(SERVICE_NODES))

    data["x"] = np.asarray(xs, dtype=data["x"].dtype)
    data["adj"] = np.asarray(adjs, dtype=data["adj"].dtype)
    data["mask"] = np.asarray(masks, dtype=data["mask"].dtype)
    data["y"] = np.asarray(ys, dtype=np.int8)
    data["times"] = full
    data["metadata"]["node_names"] = names
    data["metadata"]["explicit_empty_windows"] = empty
    data["metadata"]["empty_window_semantics"] = (
        "Closed 10-second service-graph buckets between first and last complete packet bucket; "
        "zero state means no captured IP packet; corrupt/truncated audit windows remain absent"
    )
    return data


def build_one(raw_path: Path, output_root: Path, mode: str) -> Path:
    if mode != "service":
        raise ValueError("V44 runtime regression currently requires service mode for closed empty-window semantics")
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
    data = densify_service_windows(data, audit["excluded_windows"])
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
    parser.add_argument("--mode", choices=("service",), default="service")
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
        "empty_windows": "explicit closed zero-traffic service graphs; audited corrupt windows excluded",
    }, indent=2))


if __name__ == "__main__":
    main()
