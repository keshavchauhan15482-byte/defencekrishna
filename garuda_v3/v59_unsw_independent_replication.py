"""V59 independent-dataset replication on UNSW-NB15.

The V55 fusion recipe and benign-tail policy budget are frozen from X-IIoTID and
are not selected on UNSW outcomes. Dataset-specific state and nonlinear transfer
models are fitted only on UNSW development traffic with reserve families excluded
from fit/calibration/policy data, then the frozen fusion is evaluated.

If a requested reserve pair destroys temporal development support, V59 first searches
other two-family reserves and then, if necessary, a single-family reserve. The fallback
is chosen only from pre-metric support counts. No model score, recall, FPR or threshold
outcome is used in this support-only choice.
"""
from __future__ import annotations

import argparse
import hashlib
import itertools
import json
from pathlib import Path

import numpy as np
import pandas as pd

from .v47_unseen_family import build_minute_state, make_sequences, temporal_masks
from .v48_strict_runner import canonical_family_name
from .v54_joint_family_generalization import _future_presence, _joint_reserve_split
from .v55_nonlinear_joint_generalization import evaluate_joint

COMMON_FEATURES = (
    "Scr_port", "Des_port", "Duration", "Scr_bytes", "Des_bytes",
    "Scr_pkts", "Des_pkts", "total_bytes", "total_packet", "paket_rate",
    "byte_rate", "Des_pkts_ratio", "Scr_bytes_ratio", "Des_bytes_ratio",
)

MIN_TRAIN = 500
MIN_CAL = 100
MIN_POLICY = 100
MIN_NEGATIVE = 100
MIN_POSITIVE_PER_FAMILY = 20


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
    required_keys = {
        "srcip", "sport", "dsport", "dur", "sbytes", "dbytes", "spkts", "dpkts",
        "stime", "attackcat", "label",
    }
    optional_keys = {"rate"}
    wanted = [c for c in names if norm(c) in (required_keys | optional_keys)]
    missing = required_keys - {norm(c) for c in wanted}
    if missing:
        raise RuntimeError(f"UNSW common-schema source columns missing: {sorted(missing)}")
    frames = []
    audit = []
    for shard in shards:
        frame = pd.read_csv(shard, header=None, names=names, usecols=wanted, low_memory=False)
        frames.append(frame)
        audit.append({
            "path": shard.name,
            "rows": int(len(frame)),
            "sha256": sha256(shard),
            "rate_column_present": "rate" in {norm(c) for c in frame.columns},
        })
    return pd.concat(frames, ignore_index=True), audit


def adapt_unsw(df: pd.DataFrame) -> tuple[pd.DataFrame, pd.Series, pd.Series]:
    m = {norm(c): c for c in df.columns}
    col = lambda *names: _pick(m, *names)
    src = col("srcip"); sport = col("sport"); dport = col("dsport"); dur = col("dur")
    sbytes = col("sbytes"); dbytes = col("dbytes"); spkts = col("spkts"); dpkts = col("dpkts")
    rate = col("rate"); stime = col("stime"); attack_cat = col("attack_cat", "attackcat"); label = col("label")
    required = [src, sport, dport, dur, sbytes, dbytes, spkts, dpkts, stime, attack_cat, label]
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
    safe_dur = out["Duration"].abs().clip(lower=1e-6)
    derived_packet_rate = out["total_packet"] / safe_dur
    if rate is not None:
        raw_rate = pd.to_numeric(df[rate], errors="coerce")
        out["paket_rate"] = raw_rate.where(np.isfinite(raw_rate), derived_packet_rate)
    else:
        out["paket_rate"] = derived_packet_rate
    out["byte_rate"] = out["total_bytes"] / safe_dur
    safe_pkts = out["total_packet"].replace(0, np.nan)
    safe_bytes = out["total_bytes"].replace(0, np.nan)
    out["Des_pkts_ratio"] = out["Des_pkts"] / safe_pkts
    out["Scr_bytes_ratio"] = out["Scr_bytes"] / safe_bytes
    out["Des_bytes_ratio"] = out["Des_bytes"] / safe_bytes

    y = pd.to_numeric(df[label], errors="coerce").astype("float64")
    family = df[attack_cat].astype(str).str.strip().map(canonical_family_name)
    family = family.where(y != 0, "normal").replace({"nan": "normal", "": "normal"})
    return out, y, family


def reserve_support(seq, masks, reserve):
    reserve = tuple(reserve)
    split = _joint_reserve_split(seq, masks, reserve)
    pos = {fam: int(_future_presence(seq, fam).sum()) for fam in reserve}
    return {
        "reserve": list(reserve),
        "train": int(split["train"].sum()),
        "calibration": int(split["calibration"].sum()),
        "policy": int(split["policy"].sum()),
        "negative": int(split["test_negative"].sum()),
        "positive": pos,
    }


def support_ok(s):
    return (
        s["train"] >= MIN_TRAIN
        and s["calibration"] >= MIN_CAL
        and s["policy"] >= MIN_POLICY
        and s["negative"] >= MIN_NEGATIVE
        and all(v >= MIN_POSITIVE_PER_FAMILY for v in s["positive"].values())
    )


def _support_objective(s):
    positive = list(s["positive"].values())
    return (
        min(positive) if positive else 0,
        sum(positive),
        s["calibration"],
        s["policy"],
        s["train"],
    )


def choose_reserve_support_only(seq, masks, available, requested):
    """Choose reserve solely from support counts, never from model outcomes.

    Priority is the requested pair, then another valid pair, then a valid single
    family. Falling back to one family is preferable to weakening the temporal
    calibration/policy support contract.
    """
    requested = tuple(requested)
    requested_support = reserve_support(seq, masks, requested)
    if support_ok(requested_support):
        return list(requested), requested_support, "requested_pair_supported", []

    pair_candidates = []
    for pair in itertools.combinations(available, 2):
        s = reserve_support(seq, masks, pair)
        if support_ok(s):
            pair_candidates.append((_support_objective(s), pair, s))
    if pair_candidates:
        pair_candidates.sort(key=lambda row: row[0], reverse=True)
        _, pair, support = pair_candidates[0]
        audit = [row[2] for row in pair_candidates[:20]]
        return list(pair), support, "support_only_pair_fallback", audit

    single_candidates = []
    for family in available:
        reserve = (family,)
        s = reserve_support(seq, masks, reserve)
        if support_ok(s):
            single_candidates.append((_support_objective(s), reserve, s))
    if single_candidates:
        single_candidates.sort(key=lambda row: row[0], reverse=True)
        _, reserve, support = single_candidates[0]
        audit = [row[2] for row in single_candidates[:20]]
        return list(reserve), support, "support_only_single_family_fallback", audit

    all_single_support = [reserve_support(seq, masks, (family,)) for family in available]
    raise RuntimeError(
        "No leakage-safe UNSW reserve satisfies the fixed temporal support contract; "
        f"requested={requested_support}; single_family_support={all_single_support}"
    )


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
    requested = [canonical_family_name(x) for x in args.reserve_families]
    missing = [x for x in requested if x not in available]
    if missing:
        raise RuntimeError(f"Requested reserve families missing after temporal construction: {missing}; available={available}")

    reserve, selected_support, selection_mode, support_candidates = choose_reserve_support_only(
        seq, masks, available, requested
    )
    print(json.dumps({
        "requested_reserve": requested,
        "selected_reserve": reserve,
        "selection_mode": selection_mode,
        "selected_support": selected_support,
    }, indent=2), flush=True)

    frozen_path = Path(args.frozen_config)
    frozen = json.loads(frozen_path.read_text())
    required_weights = {"future_state_novelty", "transition_energy", "nonlinear_temporal_transfer"}
    if not required_weights.issubset(frozen.get("weights", {})):
        raise RuntimeError("Frozen V55 fusion is incompatible")

    joint = evaluate_joint(seq, masks, reserve, tuple(args.seeds), args.epochs, frozen)
    report = {
        "protocol": "V59 UNSW-NB15 independent-dataset replication with frozen V55 fusion recipe",
        "claim_boundary": (
            "Independent dataset/cyber-range replication. Dataset-specific state/transfer models are retrained "
            "because raw feature schemas differ; V55 fusion weights and policy budget are not reselected on UNSW. "
            "Reserve fallback, if needed, is selected from support counts only before model metrics are computed."
        ),
        "dataset": "UNSW-NB15 raw four-shard flow corpus",
        "dataset_shards": shard_audit,
        "frozen_config_sha256": sha256(frozen_path),
        "fusion_reused_without_selection": True,
        "unsw_metrics_used_for_fusion_selection": False,
        "reserve_blocked_from_fit_calibration_policy": True,
        "reserve_selection_uses_model_metrics": False,
        "common_network_features": list(COMMON_FEATURES),
        "requested_reserve_families": requested,
        "reserve_families": reserve,
        "reserve_selection_mode": selection_mode,
        "reserve_selected_support": selected_support,
        "reserve_support_candidate_audit": support_candidates,
        "support_contract": {
            "min_train": MIN_TRAIN,
            "min_calibration": MIN_CAL,
            "min_policy": MIN_POLICY,
            "min_negative": MIN_NEGATIVE,
            "min_positive_per_family": MIN_POSITIVE_PER_FAMILY,
        },
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
