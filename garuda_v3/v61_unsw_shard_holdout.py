"""V61 independent UNSW-NB15 shard-holdout replication.

V59 showed that a global time-quantile split can lose all reserve-free calibration
and policy support because some UNSW attack families occupy long contiguous spans.
V61 therefore uses the four published raw shards as a predeclared chronology-aware
partition: shard 1=train, shard 2=calibration, shard 3=policy, shard 4=test.

The V55 fusion weights and benign-tail policy budget are frozen from X-IIoTID.
UNSW reserve families are excluded from train/calibration/policy. Reserve selection,
if the requested pair lacks support, uses support counts only before any model metric
is computed. Dataset-specific state/transfer models are fitted on UNSW development
traffic because the raw schemas differ. This is cross-dataset protocol replication,
not direct zero-shot weight transfer and not proof of a production zero-day.
"""
from __future__ import annotations

import argparse
import itertools
import json
from pathlib import Path

import numpy as np
import pandas as pd

from .v47_unseen_family import binary_metrics, build_minute_state, fpr_threshold, make_sequences
from .v48_strict_runner import canonical_family_name, reserve_exposure_mask
from .v54_joint_family_generalization import _future_presence
from .v55_nonlinear_joint_generalization import extended_evidence, fused_extended
from .v59_unsw_independent_replication import (
    COMMON_FEATURES,
    adapt_unsw,
    norm,
    read_feature_names,
    sha256,
)
from .v60_residual_state_forecasting import train_residual_world_model
from .v48_unseen_fusion import raw_components

MIN_TRAIN = 500
MIN_CALIBRATION = 100
MIN_POLICY = 100
MIN_NEGATIVE = 100
MIN_POSITIVE = 20


def _read_shard(path: Path, names: list[str]) -> pd.DataFrame:
    required_keys = {
        "srcip", "sport", "dsport", "dur", "sbytes", "dbytes", "spkts", "dpkts",
        "stime", "attackcat", "label",
    }
    optional_keys = {"rate"}
    wanted = [c for c in names if norm(c) in (required_keys | optional_keys)]
    missing = required_keys - {norm(c) for c in wanted}
    if missing:
        raise RuntimeError(f"UNSW shard schema missing: {sorted(missing)}")
    return pd.read_csv(path, header=None, names=names, usecols=wanted, low_memory=False)


def load_shard_sequences(root: Path):
    shards = sorted(root.rglob("UNSW-NB15_[1-4].csv"))
    if len(shards) != 4:
        raise RuntimeError(f"Expected four UNSW raw shards, got {shards}")
    probe = pd.read_csv(shards[0], header=None, nrows=1, low_memory=False)
    expected_cols = int(probe.shape[1])
    feature_files = sorted(root.rglob("*features*.csv")) + sorted(root.rglob("*Features*.csv"))
    if not feature_files:
        raise RuntimeError("UNSW feature-definition CSV not found")
    names = read_feature_names(feature_files[0], expected_cols)

    seq_parts = []
    audit = []
    available = set()
    for shard_id, path in enumerate(shards, start=1):
        raw = _read_shard(path, names)
        adapted, y, family = adapt_unsw(raw)
        dt = pd.to_datetime(adapted["Timestamp"], unit="s", errors="coerce", utc=True)
        state, fcols, src_col = build_minute_state(adapted, dt, y, family, list(COMMON_FEATURES))
        # Make source identity shard-local so sequences can never cross a shard boundary.
        state["src"] = f"S{shard_id}:" + state["src"].astype(str)
        seq = make_sequences(state, fcols)
        seq["shard"] = np.full(len(seq["y"]), shard_id, dtype=np.int8)
        seq_parts.append(seq)
        for steps in seq["step_families"]:
            for fams in steps:
                available.update(fams)
        audit.append({
            "shard": shard_id,
            "path": path.name,
            "rows": int(len(raw)),
            "sequences": int(len(seq["y"])),
            "sha256": sha256(path),
            "source_group_column": src_col,
        })

    keys = ["X", "future", "y", "cutoff", "clean", "history_families", "step_families", "shard"]
    combined = {k: np.concatenate([part[k] for part in seq_parts], axis=0) for k in keys}
    return combined, audit, sorted(available)


def shard_masks(seq):
    shard = seq["shard"]
    return {
        "train": shard == 1,
        "calibration": shard == 2,
        "policy": shard == 3,
        "test": shard == 4,
    }


def split_for_reserve(seq, masks, reserve):
    blocked = reserve_exposure_mask(seq, reserve)
    hist_block = np.asarray(
        [any(fam in h for fam in reserve) for h in seq["history_families"]], dtype=bool
    )
    return {
        "train": masks["train"] & ~blocked,
        "calibration": masks["calibration"] & ~blocked,
        "policy": masks["policy"] & ~blocked,
        "test_negative": masks["test"] & seq["clean"] & (seq["y"] == 0),
        "test_no_reserve_history": masks["test"] & ~hist_block,
        "blocked": blocked,
    }


def support_for(seq, masks, reserve):
    split = split_for_reserve(seq, masks, reserve)
    positive = {
        fam: int((_future_presence(seq, fam) & split["test_no_reserve_history"]).sum())
        for fam in reserve
    }
    clean_positive = {
        fam: int((_future_presence(seq, fam) & split["test_no_reserve_history"] & seq["clean"]).sum())
        for fam in reserve
    }
    return {
        "reserve": list(reserve),
        "train": int(split["train"].sum()),
        "calibration": int(split["calibration"].sum()),
        "policy": int(split["policy"].sum()),
        "negative": int(split["test_negative"].sum()),
        "positive": positive,
        "clean_history_positive": clean_positive,
    }


def support_ok(s):
    return (
        s["train"] >= MIN_TRAIN
        and s["calibration"] >= MIN_CALIBRATION
        and s["policy"] >= MIN_POLICY
        and s["negative"] >= MIN_NEGATIVE
        and all(v >= MIN_POSITIVE for v in s["positive"].values())
    )


def _support_objective(s):
    p = list(s["positive"].values())
    clean = list(s["clean_history_positive"].values())
    return (
        min(clean) if clean else 0,
        min(p) if p else 0,
        sum(p),
        s["calibration"],
        s["policy"],
    )


def choose_reserve_support_only(seq, masks, available, requested):
    requested = tuple(requested)
    req = support_for(seq, masks, requested)
    if support_ok(req):
        return list(requested), req, "requested_pair_supported", []

    pair_rows = []
    for pair in itertools.combinations(available, 2):
        s = support_for(seq, masks, pair)
        if support_ok(s):
            pair_rows.append((_support_objective(s), pair, s))
    if pair_rows:
        pair_rows.sort(key=lambda r: r[0], reverse=True)
        _, pair, support = pair_rows[0]
        return list(pair), support, "support_only_pair_fallback", [r[2] for r in pair_rows[:20]]

    single_rows = []
    for fam in available:
        s = support_for(seq, masks, (fam,))
        if support_ok(s):
            single_rows.append((_support_objective(s), (fam,), s))
    if single_rows:
        single_rows.sort(key=lambda r: r[0], reverse=True)
        _, reserve, support = single_rows[0]
        return list(reserve), support, "support_only_single_fallback", [r[2] for r in single_rows[:20]]

    all_single = [support_for(seq, masks, (fam,)) for fam in available]
    raise RuntimeError(
        "No shard-holdout reserve satisfies fixed support contract; "
        f"requested={req}; singles={all_single}"
    )


def _metrics(positive, negative, score, threshold):
    ids = np.where(positive | negative)[0]
    if positive.sum() == 0 or negative.sum() == 0:
        return {"status": "insufficient_support", "positives": int(positive.sum()), "negatives": int(negative.sum())}
    return binary_metrics(positive[ids].astype(int), score[ids], threshold)


def _mse(pred, target, mask):
    ids = np.where(mask)[0]
    if len(ids) == 0:
        return None
    return float(np.mean((pred[ids] - target[ids]) ** 2))


def evaluate(seq, masks, reserve, seeds, epochs, frozen):
    split = split_for_reserve(seq, masks, reserve)
    positives = {
        fam: _future_presence(seq, fam) & split["test_no_reserve_history"] for fam in reserve
    }
    clean_positives = {fam: positives[fam] & seq["clean"] for fam in reserve}
    rows = {fam: {} for fam in reserve}

    for seed in seeds:
        print(f"V61 seed={seed}", flush=True)
        world = train_residual_world_model(
            seq["X"], seq["future"], split["train"], split["calibration"], seed, epochs=epochs
        )
        base = raw_components(world, seq, split, seed)
        if base is None:
            raise RuntimeError(f"Seed {seed}: insufficient benign calibration/policy support")
        evidence = extended_evidence(base, seq, split, seed)
        score = fused_extended(evidence, frozen["weights"])
        threshold = fpr_threshold(score[base["policy_benign"]], frozen["policy_budget"])

        for fam in reserve:
            all_metric = _metrics(positives[fam], split["test_negative"], score, threshold)
            clean_metric = _metrics(clean_positives[fam], split["test_negative"], score, threshold)
            state_mask = positives[fam] | split["test_negative"]
            pmse = _mse(world["persistence"], world["future_scaled"], state_mask)
            rmse = _mse(world["pred"], world["future_scaled"], state_mask)
            ppmse = _mse(world["persistence"], world["future_scaled"], positives[fam])
            prmse = _mse(world["pred"], world["future_scaled"], positives[fam])
            rows[fam][str(seed)] = {
                "threshold": float(threshold),
                "selected_state_blend": {"alpha": world["blend_alpha"], "trend_beta": world["trend_beta"]},
                "validation_state_gate_passed": bool(world["state_gate_passed"]),
                "all_future_test": all_metric,
                "clean_history_future_test": clean_metric,
                "test_state_mse": rmse,
                "test_persistence_mse": pmse,
                "test_state_gate_passed": bool(rmse is not None and pmse is not None and rmse < pmse),
                "positive_state_mse": prmse,
                "positive_persistence_mse": ppmse,
                "positive_state_gate_passed": bool(prmse is not None and ppmse is not None and prmse < ppmse),
            }

    def stat(vals):
        vals = [float(v) for v in vals if v is not None]
        return {"mean": float(np.mean(vals)) if vals else None, "sd": float(np.std(vals, ddof=1)) if len(vals) > 1 else None}

    families = {}
    for fam in reserve:
        fam_rows = rows[fam]
        all_tests = [r["all_future_test"] for r in fam_rows.values()]
        clean_tests = [r["clean_history_future_test"] for r in fam_rows.values() if r["clean_history_future_test"].get("status") != "insufficient_support"]
        families[fam] = {
            "seeds": fam_rows,
            "summary": {
                "all_future_recall": stat([m.get("recall") for m in all_tests]),
                "all_future_fpr": stat([m.get("fpr") for m in all_tests]),
                "all_future_precision": stat([m.get("precision") for m in all_tests]),
                "all_future_f1": stat([m.get("f1") for m in all_tests]),
                "clean_history_recall": stat([m.get("recall") for m in clean_tests]),
                "clean_history_fpr": stat([m.get("fpr") for m in clean_tests]),
                "validation_state_gate_passed_all_seeds": all(r["validation_state_gate_passed"] for r in fam_rows.values()),
                "test_state_gate_passed_all_seeds": all(r["test_state_gate_passed"] for r in fam_rows.values()),
                "positive_state_gate_passed_all_seeds": all(r["positive_state_gate_passed"] for r in fam_rows.values()),
                "alert_gate_passed_all_seeds": all(
                    r["all_future_test"].get("recall") is not None
                    and r["all_future_test"].get("fpr") is not None
                    and r["all_future_test"]["recall"] >= 0.80
                    and r["all_future_test"]["fpr"] <= 0.01
                    for r in fam_rows.values()
                ),
            },
        }
    return {
        "support": support_for(seq, masks, reserve),
        "families": families,
    }


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--dataset-root", required=True)
    p.add_argument("--frozen-config", required=True)
    p.add_argument("--output", required=True)
    p.add_argument("--reserve-families", nargs="+", default=["exploits", "dos"])
    p.add_argument("--seeds", nargs="+", type=int, default=[42, 43, 44])
    p.add_argument("--epochs", type=int, default=18)
    args = p.parse_args()
    if len(set(args.seeds)) < 3:
        p.error("At least three distinct seeds required")

    out = Path(args.output)
    if out.exists():
        p.error("Output exists; V61 evidence is immutable")
    out.mkdir(parents=True)

    seq, shard_audit, available = load_shard_sequences(Path(args.dataset_root))
    masks = shard_masks(seq)
    requested = [canonical_family_name(x) for x in args.reserve_families]
    missing = [x for x in requested if x not in available]
    if missing:
        raise RuntimeError(f"Requested reserve missing: {missing}; available={available}")

    reserve, selected_support, mode, candidate_audit = choose_reserve_support_only(
        seq, masks, available, requested
    )
    frozen_path = Path(args.frozen_config)
    frozen = json.loads(frozen_path.read_text())
    result = evaluate(seq, masks, reserve, tuple(args.seeds), args.epochs, frozen)

    report = {
        "protocol": "V61 UNSW-NB15 shard4 independent holdout with V55 frozen fusion and V60 residual state model",
        "claim_boundary": (
            "Cross-dataset protocol replication on a predeclared raw-shard split. Models are fitted on UNSW shards 1-3 "
            "with reserve families excluded; shard 4 is evaluation only. V55 fusion weights and policy budget are frozen "
            "from X-IIoTID. This is not direct zero-shot weight transfer or production zero-day proof."
        ),
        "dataset": "UNSW-NB15 raw four-shard flow corpus",
        "partition": {"train": 1, "calibration": 2, "policy": 3, "test": 4},
        "dataset_shards": shard_audit,
        "frozen_config_sha256": sha256(frozen_path),
        "fusion_reused_without_selection": True,
        "unsw_model_metrics_used_for_fusion_selection": False,
        "reserve_selection_uses_model_metrics": False,
        "reserve_blocked_from_dev": True,
        "requested_reserve_families": requested,
        "reserve_families": reserve,
        "reserve_selection_mode": mode,
        "reserve_selected_support": selected_support,
        "reserve_support_candidate_audit": candidate_audit,
        "support_contract": {
            "min_train": MIN_TRAIN,
            "min_calibration": MIN_CALIBRATION,
            "min_policy": MIN_POLICY,
            "min_negative": MIN_NEGATIVE,
            "min_positive": MIN_POSITIVE,
        },
        "available_families": available,
        "common_network_features": list(COMMON_FEATURES),
        "seeds": list(args.seeds),
        "evaluation": result,
    }
    (out / "summary.json").write_text(json.dumps(report, indent=2, allow_nan=False) + "\n")
    print(json.dumps({
        "reserve": reserve,
        "mode": mode,
        "support": result["support"],
        "summary": {f: v["summary"] for f, v in result["families"].items()},
    }, indent=2), flush=True)


if __name__ == "__main__":
    main()
