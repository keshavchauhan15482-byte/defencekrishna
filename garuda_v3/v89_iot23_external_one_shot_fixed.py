"""Parser-only compatibility wrapper for V89 IoT-23 one-shot evaluation.

The first V89 run failed before IoT-23 inference because IoT-23 v2's labeled Zeek
files append `label` and `detailed-label` with whitespace rather than a literal tab in
the #fields line. This wrapper changes only deterministic file parsing; model training,
feature construction, candidate selection, UNSW-only threshold selection, frozen test
captures, and metric definitions remain exactly V89.
"""
from __future__ import annotations

from pathlib import Path

import pandas as pd

from . import v89_iot23_external_one_shot as base


def read_zeek_labeled_whitespace(path: Path, host_ip: str):
    fields = None
    with Path(path).open("r", encoding="utf-8", errors="replace") as f:
        for line in f:
            if line.startswith("#fields"):
                # IoT-23 v2 uses ordinary Zeek tabs for the base schema but some
                # labeled exports append the two label fields using spaces. All
                # field names are whitespace-free, so split() is deterministic.
                fields = line.rstrip("\n").split()[1:]
                break
    if not fields:
        raise RuntimeError(f"Zeek #fields header missing in {path}")

    # Data records follow the same whitespace-delimited convention in these frozen
    # exports. The fields used by V89 contain no embedded whitespace.
    raw = pd.read_csv(
        path,
        sep=r"\s+",
        engine="python",
        comment="#",
        names=fields,
        dtype=str,
    )
    required = [
        "ts", "id.orig_h", "id.resp_h", "id.resp_p", "proto", "duration",
        "orig_bytes", "resp_bytes", "orig_pkts", "resp_pkts", "label",
    ]
    missing = [c for c in required if c not in raw.columns]
    if missing:
        raise RuntimeError(f"IoT-23 Zeek fields missing after whitespace parse: {missing}; got={fields}")
    if raw.shape[1] != len(fields):
        raise RuntimeError(f"IoT-23 parsed column-count drift: {raw.shape[1]} != {len(fields)}")

    raw = raw[raw["id.orig_h"].astype(str) == str(host_ip)].copy()
    if not len(raw):
        raise RuntimeError(f"No device-origin flows for {host_ip}")

    label = raw["label"].astype(str).str.lower().str.strip()
    y = label.str.contains("malicious", regex=False).astype(int)
    detailed_col = "detailed-label" if "detailed-label" in raw.columns else None
    detailed = (
        raw[detailed_col].astype(str).str.strip()
        if detailed_col
        else pd.Series("unknown", index=raw.index)
    )
    return pd.DataFrame({
        "ts": pd.to_numeric(raw["ts"], errors="coerce"),
        "src": raw["id.orig_h"].astype(str),
        "dst": raw["id.resp_h"].astype(str),
        "dport": raw["id.resp_p"],
        "proto": raw["proto"],
        "duration": raw["duration"],
        "orig_bytes": raw["orig_bytes"],
        "resp_bytes": raw["resp_bytes"],
        "orig_pkts": raw["orig_pkts"],
        "resp_pkts": raw["resp_pkts"],
        "y": y,
        "detail": detailed,
    })


def main():
    base.read_zeek_labeled = read_zeek_labeled_whitespace
    base.main()


if __name__ == "__main__":
    main()
