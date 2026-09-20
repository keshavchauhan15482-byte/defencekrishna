"""V59 independent-dataset replication on UNSW-NB15.

The V55 fusion recipe and benign-tail policy budget are frozen from X-IIoTID and
are not selected on UNSW outcomes.  Dataset-specific state and nonlinear transfer
models are fitted only on UNSW development traffic with the requested UNSW reserve
families excluded from fit/calibration/policy data, then the frozen fusion is evaluated.

This is a cross-dataset protocol replication, not direct zero-shot weight transfer: the
raw feature schemas differ, so UNSW flows are mapped into a deterministic common
network-only feature schema before state construction.
"""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path

import numpy as np
import pandas as pd

from .v47_unseen_family import build_minute_state, make_sequences, temporal_masks
from .v48_strict_runner import canonical_family_name
from .v55_nonlinear_joint_generalization import evaluate_joint

COMMON_FEATURES = (
    "Scr_port",
    "Des_port",
    "Duration",
    "Scr_bytes",
    "Des_bytes",
    "Scr_pkts",
    "Des_pkts",
    "total_bytes",
    "total_packet",
    "paket_rate",
    "byte_rate",
    "Des_pkts_ratio",
    "Scr_bytes_ratio",
    "Des_bytes_ratio",
)


def norm(value):
    return "".join(ch.lower() for ch in str(value) if ch.isalnum())


def sha256(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for block in iter(lambda: f.read(1024 * 1024), b""):
            h.update(block)
    return h.hexdigest()


def _pick(mapping, *names):
    for name in names:
        key = norm(name)
        if key in mapping:
            return mapping[key]
    return None


def read_feature_names(path: Path, expected_cols: int) -> list[str]:
    raw = pd.read_csv(path, header=None, dtype=str, encoding_errors="ignore")
    candidates = []
    for col in raw.columns:
        vals = raw[col].dropna().astype(str).str.strip().tolist()
        # Remove a possible header cell such as Name/Feature.
        vals = [v for v in vals if norm(v) not in {"name", "feature", "featurename"}]
        if len(vals) >= expected_cols:
            candidates.append(vals[:expected_cols])
    for vals in candidates:
        keys = {norm(v) for v in vals}
        if {"srcip", "sport", "dstip", "dsport", "stime", "attackcat", "label"}.issubset(keys):
            return vals
    raise RuntimeError(f"Could not infer {expected_cols} UNSW feature names from {path}")


def load_unsw_raw(root: Path) -> tuple[pd.DataFrame, list[dict]]:
    shards = sorted(root.rglob("UNSW-NB15_[1-4].csv"))
    if len(shards) != 4:
        raise RuntimeError(f"Expected four UNSW raw shards, got {shards}")
    probe = pd.read_csv(shards[0], header=None, nrows=1, low_memory=False)
    expected_cols = int(probe.shape[1])
    feature_files = sorted(root.rglob("*features*.csv")) + sorted(root.rglob("*Features*.csv"))
    if not feature_files:
        raise RuntimeError("UNSW feature-definition CSV not found")
    names = read_feature_names(feature_files[0], expected_cols)
    mapping = {norm(c): c for c in names}
    wanted_keys = {
        "srcip", "sport", "dsport", "dur", "sbytes", "dbytes", "spkts", "dpkts",
        "rate", "stime", "attackcat", "label",
    }
    wanted = [c for c in names if norm(c) in wanted_keys]
    missing = wanted_keys - {norm(c) for c in wanted}
    if missing:
        raise RuntimeError(f"UNSW common-schema source columns missing: {sorted(missing)}")
    frames = []
    audit = []
    for shard in shards:
        frame = pd.read_csv(shard, header=None, names=names, usecols=wanted, low_memory=False)
        frames.append(frame)
        audit.append({"path": shard.name, "rows": int(len(frame)), "sha256": sha256(shard)})
    return pd.concat(frames, ignore_index=True), audit


def adapt_unsw(df: pd.DataFrame) -> tuple[pd.DataFrame, pd.Series, pd.Series]:
    m = {norm(c): c for c in df.columns}
    col = lambda *names: _pick(m, *names)

    src = col("srcip")
    sport = col("sport")
    dport = col("dsport")
    dur = col("dur")
    sbytes = col("sbytes")
    dbytes = col("dbytes")
    spkts = col("spkts")
    dpkts = col("dpkts")
    rate = col("rate")
    stime = col("stime")
    attack_cat = col("attack_cat", "attackcat")
    label = col("label")
    required = [src, sport, dport, dur, sbytes, dbytes, spkts, dpkts, rate, stime, attack_cat, label]
    if any(x is None for x in required):
        raise RuntimeError(f"UNSW adapter columns unresolved: {m}")

    out = pd.DataFrame(index=df.index)
    out["Timestamp"] = pd.to_numeric(df[stime], errors="coerce")
    out["Scr_IP"] = df[src].astype(str).str.strip()
    out["Scr_port"] = pd.to_numeric(df[sport], errors="coerce")
    out["Des_port"] = pd.to_numeric(df[dport], errors="coerce")
    out["Duration"] = pd.to_numeric(df[dur], errors="coerce")
    out["Scr_bytes"] = pd.to_numeric(df[sbytes], errors="coerce")
    out["Des_bytes"] = pd.to_numeric(df[dbytes], errors="coerce")
    out["Scr_pkts"] = pd.to_numeric(df[spkts], errors="coerce")
    out["Des_pkts"] = pd.to_numeric(df[dpkts], errors="coerce")
    out["total_bytes"] = out["Scr_bytes"] + out["Des_bytes"]
    out["total_packet"] = out["Scr_pkts"] + out["Des_pkts"]
    raw_rate = pd.to_numeric(df[rate], errors="coerce")
    safe_dur = out["Duration"].abs().clip(lower=1e-6)
    out["paket_rate"] = raw_rate.where(np.isfinite(raw_rate), out["total_packet"] / safe_dur)
    out["byte_rate"] = out["total_bytes"] / safe_dur
    safe_pkts = out["total_packet"].replace(0, np.nan)
    safe_bytes = out["total_bytes"].replace(0, np.nan)
    out["Des_pkts_ratio"] = out["Des_pkts"] / safe_pkts
    out["Scr_bytes_ratio"] = out["Scr_bytes"] / safe_bytes
    out["Des_bytes_ratio"] = out["Des_bytes"] / safe_bytes

    y = pd.to_numeric(df[label], errors="coerce").astype("float64")
    family = df[attack_cat].astype(str).str.strip().map(canonical_family_name)
    family = family.where(y != 0, "normal")
    family = family.replace({"nan": "normal", "": "normal"})
    return out, y, family


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--dataset-root", required=True)
    p.add_argument("--frozen-config", required=True)
    p.add_argument("--output", required=True)
    p.add_argument("--epochs", type=int, default=12)
    p.add_argument("--seeds", nargs="+", type=int, default=[42, 43, 44])
    p.add_argument("--reserve-families", nargs="+", default=["exploits", "dos"])
    args = p.parse_args()
    if len(set(args.seeds)) < 3:
        p.error("At least three distinct seeds required")

    out_dir = Path(args.output)
    if out_dir.exists():
        p.error("Output exists; V59 evidence is immutable")
    out_dir.mkdir(parents=True)

    root = Path(args.dataset_root)
    raw, shard_audit = load_unsw_raw(root)
    adapted, y, family = adapt_unsw(raw)
    dt = pd.to_datetime(adapted["Timestamp"], unit="s", errors="coerce", utc=True)
    state, names, src_col = build_minute_state(adapted, dt, y, family, list(COMMON_FEATURES))
    seq = make_sequences(state, names)
    masks, boundaries = temporal_masks(seq["cutoff"])
    available = sorted({x for steps in seq["step_families"] for fams in steps for x in fams})
    reserve = [canonical_family_name(x) for x in args.reserve_families]
    missing = [x for x in reserve if x not in available]
    if missing:
        raise RuntimeError(f"Reserve families missing after temporal construction: {missing}; available={available}")

    frozen_path = Path(args.frozen_config)
    frozen = json.loads(frozen_path.read_text())
    required_weights = {
        "future_state_novelty", "transition_energy", "nonlinear_temporal_transfer"
    }
    if not required_weights.issubset(frozen.get("weights", {})):
        raise RuntimeError("Frozen V55 fusion is incompatible")

    joint = evaluate_joint(seq, masks, reserve, tuple(args.seeds), args.epochs, frozen)
    report = {
        "protocol": "V59 UNSW-NB15 independent-dataset replication with frozen V55 fusion recipe",
        "claim_boundary": (
            "Independent dataset/cyber-range replication. Dataset-specific state/transfer models are retrained "
            "because raw feature schemas differ; V55 fusion weights and policy budget are not reselected on UNSW."
        ),
        "dataset": "UNSW-NB15 raw four-shard flow corpus",
        "dataset_shards": shard_audit,
        "frozen_config_sha256": sha256(frozen_path),
        "fusion_reused_without_selection": True,
        "unsw_metrics_used_for_fusion_selection": False,
        "reserve_blocked_from_fit_calibration_policy": True,
        "common_network_features": list(COMMON_FEATURES),
        "reserve_families": reserve,
        "seeds": list(args.seeds),
        "boundaries": boundaries,
        "source_group_column": src_col,
        "available_families": available,
        "joint_reserve": joint,
    }
    (out_dir / "summary.json").write_text(json.dumps(report, indent=2, allow_nan=False) + "\n")
    print(json.dumps({
        "reserve_families": reserve,
        "support": joint["support"],
        "summary": {k: v["summary"] for k, v in joint["families"].items()},
    }, indent=2), flush=True)


if __name__ == "__main__":
    main()
