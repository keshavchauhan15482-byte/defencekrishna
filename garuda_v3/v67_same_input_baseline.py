"""V67 same-input Logistic Regression baseline vs Garuda world model.

Purpose
-------
Close the SIH baseline requirement without contaminating the independent UNSW holdout.
Both systems receive the same observed network-state history. Logistic Regression is
fit only on the chronological training split, its feature scaling is fit on training
only, and its operating threshold is chosen only from clean policy-period traffic at
the *same* false-positive budget as the already frozen Garuda fusion.

Family/episode selection uses only timestamps and support counts. No test model score
is available during selection. Garuda configuration remains frozen from V57.

This is an independent public cyber-range benchmark, not production zero-day proof.
"""
from __future__ import annotations

import argparse
import json
import math
from pathlib import Path

import numpy as np
import pandas as pd
from sklearn.linear_model import LogisticRegression
from sklearn.preprocessing import StandardScaler

from .v47_unseen_family import binary_metrics, build_minute_state, fpr_threshold, make_sequences
from .v59_unsw_independent_replication import COMMON_FEATURES, adapt_unsw, load_unsw_raw, sha256
from .v62_unsw_episode_holdout import _build_split, _episodes_for_family, evaluate_one

MIN_TRAIN = 500
MIN_TRAIN_BENIGN = 100
MIN_TRAIN_ATTACK = 20
MIN_CALIBRATION = 100
MIN_POLICY = 100
MIN_CALIBRATION_BENIGN = 30
MIN_POLICY_BENIGN = 30
MIN_POSITIVE = 20
MIN_NEGATIVE = 200


def wilson(successes: int, total: int, z: float = 1.959963984540054):
    if total <= 0:
        return {"lower": None, "upper": None}
    p = successes / total
    z2 = z * z
    den = 1.0 + z2 / total
    center = (p + z2 / (2.0 * total)) / den
    margin = z * math.sqrt(p * (1.0 - p) / total + z2 / (4.0 * total * total)) / den
    return {"lower": float(max(0.0, center - margin)), "upper": float(min(1.0, center + margin))}


def support_row(seq, split):
    y = np.asarray(seq["y"], dtype=int)
    benign = np.asarray(seq["clean"], dtype=bool) & (y == 0)
    return {
        "train": int(split["train"].sum()),
        "train_benign": int((split["train"] & (y == 0)).sum()),
        "train_attack": int((split["train"] & (y == 1)).sum()),
        "calibration": int(split["calibration"].sum()),
        "calibration_benign": int((split["calibration"] & benign).sum()),
        "policy": int(split["policy"].sum()),
        "policy_benign": int((split["policy"] & benign).sum()),
        "positive": int(split["test_positive"].sum()),
        "negative": int(split["test_negative"].sum()),
    }


def support_ok(s):
    return (
        s["train"] >= MIN_TRAIN
        and s["train_benign"] >= MIN_TRAIN_BENIGN
        and s["train_attack"] >= MIN_TRAIN_ATTACK
        and s["calibration"] >= MIN_CALIBRATION
        and s["policy"] >= MIN_POLICY
        and s["calibration_benign"] >= MIN_CALIBRATION_BENIGN
        and s["policy_benign"] >= MIN_POLICY_BENIGN
        and s["positive"] >= MIN_POSITIVE
        and s["negative"] >= MIN_NEGATIVE
    )


def discover_support_only(seq, available, max_audits=2):
    rows = []
    for family in available:
        for episode in _episodes_for_family(seq, family):
            split = _build_split(seq, family, episode)
            if split is None:
                continue
            s = support_row(seq, split)
            if support_ok(s):
                rows.append({
                    "family": family,
                    "episode": [int(episode[0]), int(episode[1])],
                    "support": s,
                    "split": split,
                })
    if not rows:
        raise RuntimeError("No support-qualified UNSW unseen-family episodes")

    # Prospective selection rule copied from the conservative audit: earliest eligible
    # episode per family, then largest positive/negative support. No model score.
    first = {}
    for row in sorted(rows, key=lambda r: (r["family"], r["episode"][0], r["episode"][1])):
        first.setdefault(row["family"], row)
    candidates = list(first.values())
    candidates.sort(
        key=lambda r: (
            r["support"]["positive"],
            r["support"]["negative"],
            r["support"]["policy_benign"],
            r["support"]["calibration_benign"],
            r["family"],
        ),
        reverse=True,
    )
    return candidates[:max_audits], [
        {"family": r["family"], "episode": r["episode"], "support": r["support"]}
        for r in candidates
    ]


def exact_metrics(positive, negative, score, threshold):
    idx = np.where(positive | negative)[0]
    m = binary_metrics(positive[idx].astype(int), score[idx], threshold)
    pred = score[idx] >= threshold
    truth = positive[idx]
    tp = int((pred & truth).sum())
    fp = int((pred & ~truth).sum())
    fn = int((~pred & truth).sum())
    tn = int((~pred & ~truth).sum())
    m.update({"tp": tp, "fp": fp, "fn": fn, "tn": tn})
    m["recall_wilson95"] = wilson(tp, tp + fn)
    m["fpr_wilson95"] = wilson(fp, fp + tn)
    return m


def logistic_same_input(seq, audit, policy_budget):
    split = audit["split"]
    y = np.asarray(seq["y"], dtype=int)
    # Same observed state history consumed by the world model; no future state, family
    # identity, test label, or post-cutoff information enters the LR feature matrix.
    X = np.asarray(seq["X"], dtype=np.float64).reshape(len(seq["X"]), -1)
    tr = np.where(split["train"])[0]
    if len(np.unique(y[tr])) < 2:
        raise RuntimeError(f"{audit['family']}: LR training split is not two-class")

    # Replace nonfinite values from training statistics only.
    X[~np.isfinite(X)] = np.nan
    med = np.nanmedian(X[tr], axis=0)
    med[~np.isfinite(med)] = 0.0
    bad = ~np.isfinite(X)
    if bad.any():
        X[bad] = med[np.where(bad)[1]]

    scaler = StandardScaler()
    Xtr = scaler.fit_transform(X[tr])
    model = LogisticRegression(
        max_iter=2000,
        class_weight="balanced",
        solver="liblinear",
        random_state=20260920,
    )
    model.fit(Xtr, y[tr])
    score = model.predict_proba(scaler.transform(X))[:, 1]

    clean_policy = split["policy"] & np.asarray(seq["clean"], dtype=bool) & (y == 0)
    if int(clean_policy.sum()) < MIN_POLICY_BENIGN:
        raise RuntimeError(f"{audit['family']}: insufficient benign policy support")
    threshold = fpr_threshold(score[clean_policy], float(policy_budget))
    metric = exact_metrics(split["test_positive"], split["test_negative"], score, threshold)
    return {
        "model": "LogisticRegression",
        "input_contract": "flattened observed state history only; identical network-state history source as world model",
        "scaler_fit_on": "train only",
        "threshold_fit_on": "clean policy negatives only",
        "policy_budget": float(policy_budget),
        "threshold": float(threshold),
        "metric": metric,
    }


def garuda_macro(result):
    rows = [r["all_future_test"] for r in result["seeds"].values()]
    keys = ("recall", "fpr", "precision", "f1")
    return {
        k: {
            "mean": float(np.mean([float(r[k]) for r in rows])),
            "sd": float(np.std([float(r[k]) for r in rows], ddof=1)),
        }
        for k in keys
    }


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--dataset-root", required=True)
    p.add_argument("--frozen-config", required=True)
    p.add_argument("--output", required=True)
    p.add_argument("--seeds", nargs="+", type=int, default=[42, 43, 44])
    p.add_argument("--epochs", type=int, default=18)
    p.add_argument("--max-audits", type=int, default=2)
    args = p.parse_args()
    if len(set(args.seeds)) < 3:
        p.error("At least three distinct Garuda outer seeds required")

    out = Path(args.output)
    if out.exists():
        p.error("Output exists; V67 evidence is immutable")
    out.mkdir(parents=True)

    raw, shard_audit = load_unsw_raw(Path(args.dataset_root))
    adapted, y, family = adapt_unsw(raw)
    dt = pd.to_datetime(adapted["Timestamp"], unit="s", errors="coerce", utc=True)
    state, fcols, src_col = build_minute_state(adapted, dt, y, family, list(COMMON_FEATURES))
    seq = make_sequences(state, fcols)
    available = sorted({x for steps in seq["step_families"] for fams in steps for x in fams})
    selected, support_audit = discover_support_only(seq, available, args.max_audits)

    frozen_path = Path(args.frozen_config)
    frozen = json.loads(frozen_path.read_text())
    rows = []
    for audit in selected:
        print(f"V67 family={audit['family']} logistic baseline", flush=True)
        lr = logistic_same_input(seq, audit, frozen["policy_budget"])
        print(f"V67 family={audit['family']} Garuda 3-seed", flush=True)
        garuda = evaluate_one(seq, audit, tuple(args.seeds), args.epochs, frozen)
        gm = garuda_macro(garuda)
        lm = lr["metric"]
        rows.append({
            "family": audit["family"],
            "episode": audit["episode"],
            "support": audit["support"],
            "logistic_regression": lr,
            "garuda": garuda,
            "garuda_macro": gm,
            "delta_garuda_minus_lr": {
                "recall_pp": 100.0 * (gm["recall"]["mean"] - lm["recall"]),
                "fpr_pp": 100.0 * (gm["fpr"]["mean"] - lm["fpr"]),
                "precision_pp": 100.0 * (gm["precision"]["mean"] - lm["precision"]),
                "f1_pp": 100.0 * (gm["f1"]["mean"] - lm["f1"]),
            },
        })

    report = {
        "protocol": "V67 same-observed-input LR baseline vs frozen Garuda on independent UNSW unseen-family episodes",
        "claim_boundary": (
            "Public UNSW-NB15 cyber-range benchmark. Episode selection is timestamp/support-only. "
            "LR preprocessing uses train only and its threshold uses clean policy negatives only. "
            "Garuda fusion/policy budget remain frozen before UNSW test metrics. Not production zero-day proof."
        ),
        "fairness_contract": {
            "same_observed_history_source": True,
            "future_or_test_features_in_lr": False,
            "family_identity_in_lr": False,
            "lr_threshold_uses_test": False,
            "garuda_fusion_uses_unsw_test": False,
            "episode_selection_uses_model_metrics": False,
            "same_policy_fpr_budget": float(frozen["policy_budget"]),
        },
        "dataset": "UNSW-NB15 raw four-shard flow corpus",
        "dataset_shards": shard_audit,
        "frozen_config_sha256": sha256(frozen_path),
        "common_network_features": list(COMMON_FEATURES),
        "source_group_column": src_col,
        "seeds": list(args.seeds),
        "qualified_family_audit": support_audit,
        "results": rows,
    }

    # Macro family view. LR is deterministic; Garuda averages outer seeds per family.
    lr_metrics = [r["logistic_regression"]["metric"] for r in rows]
    g_metrics = [r["garuda_macro"] for r in rows]
    report["summary"] = {
        "families": len(rows),
        "garuda_seed_evaluations": len(rows) * len(args.seeds),
        "lr_macro_recall": float(np.mean([m["recall"] for m in lr_metrics])),
        "lr_macro_fpr": float(np.mean([m["fpr"] for m in lr_metrics])),
        "lr_macro_precision": float(np.mean([m["precision"] for m in lr_metrics])),
        "lr_macro_f1": float(np.mean([m["f1"] for m in lr_metrics])),
        "garuda_macro_recall": float(np.mean([m["recall"]["mean"] for m in g_metrics])),
        "garuda_macro_fpr": float(np.mean([m["fpr"]["mean"] for m in g_metrics])),
        "garuda_macro_precision": float(np.mean([m["precision"]["mean"] for m in g_metrics])),
        "garuda_macro_f1": float(np.mean([m["f1"]["mean"] for m in g_metrics])),
    }
    report["summary"]["garuda_minus_lr"] = {
        "recall_pp": 100.0 * (report["summary"]["garuda_macro_recall"] - report["summary"]["lr_macro_recall"]),
        "fpr_pp": 100.0 * (report["summary"]["garuda_macro_fpr"] - report["summary"]["lr_macro_fpr"]),
        "precision_pp": 100.0 * (report["summary"]["garuda_macro_precision"] - report["summary"]["lr_macro_precision"]),
        "f1_pp": 100.0 * (report["summary"]["garuda_macro_f1"] - report["summary"]["lr_macro_f1"]),
    }
    (out / "summary.json").write_text(json.dumps(report, indent=2, allow_nan=False) + "\n")
    print(json.dumps(report["summary"], indent=2), flush=True)


if __name__ == "__main__":
    main()
