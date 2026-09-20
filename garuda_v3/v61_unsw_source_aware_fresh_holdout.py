"""V61 source-aware fresh-family UNSW-NB15 evaluation.

V59 exposed two issues: the frozen X-IIoTID fusion did not transfer robustly to UNSW,
and a global time embargo removed unrelated hosts whenever a reserve attack occurred.
V61 fixes both without reusing the already-inspected Backdoors outcome as a holdout.

Protocol
--------
1. Build per-source temporal sequences from UNSW raw cyber-range flows.
2. Reserve-family embargo is source-aware: only overlapping sequences for the same
   source are blocked from fit/calibration/policy.
3. Backdoors is permanently marked contaminated because V59 metrics were inspected.
4. A new reserve family is frozen using support counts only, before model metrics.
5. Fusion weights/policy are selected only on other UNSW development families.
6. The V60 persistence-anchored residual world model is used for state forecasting.
7. The fresh reserve is evaluated only after the fusion configuration is frozen.

This is controlled public-dataset evidence, not a live Internet zero-day claim.
"""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path

import numpy as np
import pandas as pd

from .v47_unseen_family import (
    HISTORY, HORIZON, EMBARGO_MINUTES, FPR_BUDGET, binary_metrics,
    build_minute_state, fpr_threshold, temporal_masks,
)
from .v48_unseen_fusion import raw_components
from .v55_nonlinear_joint_generalization import (
    COMPONENTS, POLICY_BUDGETS, candidate_weights, extended_evidence, fused_extended,
)
from .v59_unsw_independent_replication import COMMON_FEATURES, adapt_unsw, load_unsw_raw
from .v60_residual_state_forecasting import train_residual_world_model

CONTAMINATED_FAMILIES = {"backdoors"}
MIN_TRAIN = 500
MIN_CAL = 100
MIN_POLICY = 100
MIN_NEGATIVE = 100
MIN_RESERVE_POSITIVE = 20
MIN_DEV_POSITIVE = 10
DEV_FPR_MARGIN = 0.01


def canonical(value):
    return " ".join(str(value).replace("_", " ").strip().casefold().split())


def canonical_hash(payload):
    raw = json.dumps(payload, sort_keys=True, separators=(",", ":"), allow_nan=False).encode()
    return hashlib.sha256(raw).hexdigest()


def make_sequences_with_source(state, feature_cols):
    X, future, y, cutoffs, clean = [], [], [], [], []
    hist_families, step_families, sources = [], [], []
    for src, group in state.groupby("src", sort=False):
        g = group.sort_values("minute").reset_index(drop=True)
        t = g["minute"].astype("int64").to_numpy() // 10**9
        attack = g["attack_now"].to_numpy(dtype=int)
        z = g[feature_cols].to_numpy(dtype=np.float32)
        fam = g["families"].tolist()
        for i in range(HISTORY - 1, len(g) - HORIZON):
            lo = i - HISTORY + 1
            stop = i + HORIZON + 1
            span = t[lo:stop]
            if len(span) != HISTORY + HORIZON or not np.all(np.diff(span) == 60):
                continue
            X.append(z[lo:i + 1])
            future.append(z[i + 1:stop])
            y.append(int(attack[i + 1:stop].max()))
            cutoffs.append(int(t[i]))
            clean.append(bool(attack[lo:i + 1].max() == 0))
            hset = set()
            for item in fam[lo:i + 1]:
                hset.update(canonical(x) for x in item)
            hist_families.append(frozenset(hset))
            steps = []
            for item in fam[i + 1:stop]:
                steps.append(frozenset(canonical(x) for x in item))
            step_families.append(tuple(steps))
            sources.append(str(src))
    if not X:
        raise ValueError("No contiguous temporal sequences")
    return {
        "X": np.stack(X), "future": np.stack(future), "y": np.asarray(y, dtype=np.int8),
        "cutoff": np.asarray(cutoffs, dtype=np.int64), "clean": np.asarray(clean, dtype=bool),
        "history_families": np.asarray(hist_families, dtype=object),
        "step_families": np.asarray(step_families, dtype=object),
        "source": np.asarray(sources, dtype=object),
    }


def future_presence(seq, family):
    family = canonical(family)
    return np.asarray(
        [any(family in step for step in steps) for steps in seq["step_families"]],
        dtype=bool,
    )


def history_presence(seq, family):
    family = canonical(family)
    return np.asarray([family in fams for fams in seq["history_families"]], dtype=bool)


def source_aware_exposure_mask(seq, families):
    reserve = {canonical(x) for x in families}
    touched = np.zeros(len(seq["X"]), dtype=bool)
    for i, (history, steps) in enumerate(zip(seq["history_families"], seq["step_families"])):
        if reserve.intersection(history) or any(reserve.intersection(step) for step in steps):
            touched[i] = True
    blocked = touched.copy()
    radius = EMBARGO_MINUTES * 60
    src = seq["source"]
    cutoff = seq["cutoff"]
    for source in np.unique(src[touched]):
        ids = np.where(src == source)[0]
        touched_times = cutoff[ids[touched[ids]]]
        if len(touched_times) == 0:
            continue
        # Per-source embargo prevents one attacked host from deleting unrelated hosts.
        for t in touched_times.tolist():
            blocked[ids[np.abs(cutoff[ids] - int(t)) <= radius]] = True
    return blocked


def source_split(seq, masks, blocked_families):
    blocked = source_aware_exposure_mask(seq, blocked_families)
    return {
        "train": masks["train"] & ~blocked,
        "calibration": masks["calibration"] & ~blocked,
        "policy": masks["policy"] & ~blocked,
        "test_negative": masks["test"] & seq["clean"] & (seq["y"] == 0) & ~blocked,
        "blocked": blocked,
    }


def clean_test_positive(seq, masks, family):
    # Strict pre-attack history: no attack of any family in the observed history.
    return masks["test"] & seq["clean"] & future_presence(seq, family) & ~history_presence(seq, family)


def support_for(seq, masks, reserve):
    split = source_split(seq, masks, reserve)
    pos = {fam: int(clean_test_positive(seq, masks, fam).sum()) for fam in reserve}
    return {
        "reserve": list(reserve),
        "train": int(split["train"].sum()),
        "calibration": int(split["calibration"].sum()),
        "policy": int(split["policy"].sum()),
        "negative": int(split["test_negative"].sum()),
        "positive": pos,
    }


def reserve_support_ok(s):
    return (
        s["train"] >= MIN_TRAIN and s["calibration"] >= MIN_CAL
        and s["policy"] >= MIN_POLICY and s["negative"] >= MIN_NEGATIVE
        and all(v >= MIN_RESERVE_POSITIVE for v in s["positive"].values())
    )


def choose_fresh_reserve(seq, masks, available):
    candidates = []
    for fam in available:
        if fam in CONTAMINATED_FAMILIES:
            continue
        s = support_for(seq, masks, [fam])
        if not reserve_support_ok(s):
            continue
        p = s["positive"][fam]
        objective = (p, s["negative"], s["calibration"], s["policy"], s["train"])
        candidates.append((objective, fam, s))
    if not candidates:
        raise RuntimeError("No fresh UNSW family satisfies source-aware support contract")
    candidates.sort(key=lambda row: row[0], reverse=True)
    _, fam, support = candidates[0]
    return fam, support, [row[2] for row in candidates]


def metric(positive, negative, score, threshold):
    ids = np.where(positive | negative)[0]
    if int(positive.sum()) == 0 or int(negative.sum()) == 0:
        return None
    return binary_metrics(positive[ids].astype(int), score[ids], threshold)


def prepare_dev_fold(seq, masks, reserve, family, seed, epochs):
    blocked_families = [reserve, family]
    split = source_split(seq, masks, blocked_families)
    positive = clean_test_positive(seq, masks, family)
    negative = split["test_negative"]
    support = {
        "train": int(split["train"].sum()), "calibration": int(split["calibration"].sum()),
        "policy": int(split["policy"].sum()), "positive": int(positive.sum()),
        "negative": int(negative.sum()),
    }
    if (
        support["train"] < MIN_TRAIN or support["calibration"] < MIN_CAL
        or support["policy"] < MIN_POLICY or support["negative"] < MIN_NEGATIVE
        or support["positive"] < MIN_DEV_POSITIVE
    ):
        return None, support
    world = train_residual_world_model(
        seq["X"], seq["future"], split["train"], split["calibration"], seed, epochs=epochs
    )
    base = raw_components(world, seq, split, seed)
    if base is None:
        return None, support
    evidence = extended_evidence(base, seq, split, seed)
    return {
        "family": family, "seed": int(seed), "split": split,
        "positive": positive, "negative": negative, "world": world,
        "base": base, "evidence": evidence, "support": support,
    }, support


def robust_objective(rows):
    safe = [r for r in rows if r["fpr"] is not None and r["fpr"] <= DEV_FPR_MARGIN]
    gate = [r for r in safe if r["recall"] is not None and r["recall"] >= 0.80]
    recalls = np.asarray([float(r["recall"]) for r in safe if r["recall"] is not None], dtype=float)
    q10 = float(np.quantile(recalls, 0.10)) if len(recalls) else 0.0
    worst = float(np.min(recalls)) if len(recalls) else 0.0
    mean = float(np.mean(recalls)) if len(recalls) else 0.0
    max_fpr = max((float(r["fpr"]) for r in rows if r["fpr"] is not None), default=1.0)
    return (len(gate), len(safe), q10, worst, mean, -max_fpr)


def select_fusion(dev_folds):
    candidates = []
    for cand in candidate_weights():
        for budget in tuple(POLICY_BUDGETS) + (0.01,):
            rows = []
            for fold in dev_folds:
                score = fused_extended(fold["evidence"], cand["weights"])
                policy = fold["base"]["policy_benign"]
                threshold = fpr_threshold(score[policy], budget)
                m = metric(fold["positive"], fold["negative"], score, threshold)
                if m is None:
                    continue
                rows.append({
                    "family": fold["family"], "seed": fold["seed"],
                    "recall": m.get("recall"), "fpr": m.get("fpr"),
                    "precision": m.get("precision"), "f1": m.get("f1"),
                    "threshold": float(threshold),
                })
            obj = robust_objective(rows)
            candidates.append({
                "name": cand["name"], "weights": cand["weights"],
                "policy_budget": float(budget), "objective": list(obj), "folds": rows,
            })
    candidates.sort(key=lambda c: tuple(c["objective"]) + (-c["policy_budget"],), reverse=True)
    return candidates[0], candidates


def evaluate_reserve(seq, masks, reserve, seeds, epochs, frozen):
    split = source_split(seq, masks, [reserve])
    positive = clean_test_positive(seq, masks, reserve)
    negative = split["test_negative"]
    rows = {}
    for seed in seeds:
        print(f"V61 RESERVE seed={seed} family={reserve}", flush=True)
        world = train_residual_world_model(
            seq["X"], seq["future"], split["train"], split["calibration"], seed, epochs=epochs
        )
        base = raw_components(world, seq, split, seed)
        if base is None:
            raise RuntimeError(f"Seed {seed}: insufficient benign calibration/policy support")
        evidence = extended_evidence(base, seq, split, seed)
        score = fused_extended(evidence, frozen["weights"])
        policy = base["policy_benign"]
        threshold = fpr_threshold(score[policy], frozen["policy_budget"])
        m = metric(positive, negative, score, threshold)
        ids = positive | negative
        mse = float(np.mean((world["pred"][ids] - world["future_scaled"][ids]) ** 2))
        pmse = float(np.mean((world["persistence"][ids] - world["future_scaled"][ids]) ** 2))
        rows[str(seed)] = {
            "threshold": float(threshold), "test": m,
            "validation_state_gate_passed": bool(world["state_gate_passed"]),
            "test_state_mse": mse, "test_persistence_mse": pmse,
            "test_state_gate_passed": bool(mse < pmse),
            "blend_alpha": float(world["blend_alpha"]), "trend_beta": float(world["trend_beta"]),
        }

    vals = list(rows.values())
    def st(key):
        x = [r["test"].get(key) for r in vals if r["test"] and r["test"].get(key) is not None]
        return {"mean": float(np.mean(x)) if x else None,
                "sd": float(np.std(x, ddof=1)) if len(x) > 1 else None}
    summary = {
        "evaluated_seeds": len(vals), "recall": st("recall"), "fpr": st("fpr"),
        "precision": st("precision"), "f1": st("f1"),
        "alert_gate_passed_all_seeds": all(
            r["test"] is not None and r["test"]["recall"] >= 0.80 and r["test"]["fpr"] <= FPR_BUDGET
            for r in vals
        ),
        "validation_state_gate_passed_all_seeds": all(r["validation_state_gate_passed"] for r in vals),
        "test_state_gate_passed_all_seeds": all(r["test_state_gate_passed"] for r in vals),
    }
    return {
        "support": {
            "train": int(split["train"].sum()), "calibration": int(split["calibration"].sum()),
            "policy": int(split["policy"].sum()), "positive": int(positive.sum()),
            "negative": int(negative.sum()),
        },
        "seeds": rows, "summary": summary,
    }


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--dataset-root", required=True)
    p.add_argument("--output", required=True)
    p.add_argument("--epochs", type=int, default=18)
    p.add_argument("--seeds", nargs="+", type=int, default=[42, 43, 44])
    args = p.parse_args()
    if len(set(args.seeds)) < 3:
        p.error("At least three distinct seeds required")
    out = Path(args.output)
    if out.exists():
        p.error("Output exists; V61 evidence is immutable")
    out.mkdir(parents=True)

    raw, shard_audit = load_unsw_raw(Path(args.dataset_root))
    adapted, y, family = adapt_unsw(raw)
    family = family.map(canonical)
    dt = pd.to_datetime(adapted["Timestamp"], unit="s", errors="coerce", utc=True)
    state, names, src_col = build_minute_state(adapted, dt, y, family, list(COMMON_FEATURES))
    seq = make_sequences_with_source(state, names)
    masks, boundaries = temporal_masks(seq["cutoff"])
    available = sorted({canonical(x) for steps in seq["step_families"] for fams in steps for x in fams})

    reserve, reserve_support, reserve_candidates = choose_fresh_reserve(seq, masks, available)
    print(json.dumps({
        "fresh_reserve_frozen_from_support_only": reserve,
        "reserve_support": reserve_support,
        "contaminated_excluded": sorted(CONTAMINATED_FAMILIES),
    }, indent=2), flush=True)

    dev_families = [f for f in available if f != reserve and f not in CONTAMINATED_FAMILIES]
    dev_folds = []
    dev_support = {}
    for fam in dev_families:
        fam_support = []
        for seed in args.seeds:
            fold, support = prepare_dev_fold(seq, masks, reserve, fam, seed, args.epochs)
            fam_support.append({"seed": int(seed), **support})
            if fold is not None:
                dev_folds.append(fold)
        dev_support[fam] = fam_support
    selected_dev = sorted({f["family"] for f in dev_folds})
    if len(selected_dev) < 2:
        raise RuntimeError(f"Need >=2 support-qualified development families, got {selected_dev}")

    winner, candidates = select_fusion(dev_folds)
    frozen = {
        "protocol": "V61 UNSW source-aware development-selected fusion",
        "weights": winner["weights"], "policy_budget": winner["policy_budget"],
        "selection_candidate": winner["name"], "selection_objective": winner["objective"],
        "development_families": selected_dev, "fresh_reserve_family": reserve,
        "contaminated_excluded": sorted(CONTAMINATED_FAMILIES),
        "reserve_metrics_used_for_selection": False,
        "reserve_selected_by_support_only": True,
        "source_aware_embargo": True,
    }
    frozen["config_sha256"] = canonical_hash(frozen)
    (out / "frozen_config.json").write_text(json.dumps(frozen, indent=2) + "\n")

    reserve_result = evaluate_reserve(seq, masks, reserve, tuple(args.seeds), args.epochs, frozen)
    report = {
        "protocol": frozen["protocol"],
        "claim_boundary": (
            "Fresh unseen-family evaluation within independent UNSW-NB15 cyber-range data. "
            "Backdoors is excluded because V59 outcomes were already inspected. This is not a live Internet zero-day claim."
        ),
        "dataset": "UNSW-NB15 raw four-shard flow corpus",
        "dataset_shards": shard_audit,
        "seeds": list(args.seeds), "boundaries": boundaries,
        "source_group_column": src_col, "available_families": available,
        "reserve_support_candidates": reserve_candidates,
        "development_support": dev_support,
        "frozen_config": frozen,
        "candidate_count": len(candidates),
        "top_candidates": [
            {k: c[k] for k in ("name", "weights", "policy_budget", "objective")}
            for c in candidates[:20]
        ],
        "fresh_reserve": reserve_result,
    }
    (out / "summary.json").write_text(json.dumps(report, indent=2, allow_nan=False) + "\n")
    print(json.dumps({
        "frozen_config": frozen,
        "fresh_reserve_support": reserve_result["support"],
        "fresh_reserve_summary": reserve_result["summary"],
    }, indent=2), flush=True)


if __name__ == "__main__":
    main()
