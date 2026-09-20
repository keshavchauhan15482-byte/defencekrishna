"""V63 conservative independent UNSW-NB15 unseen-episode audit.

V63 is intentionally designed to make perfect-looking point estimates hard to
misinterpret. It does not cap or alter measured recall/FPR. Instead it:

* requires explicit benign calibration and benign policy support before an audit is
  eligible (fixing the V62 support-contract bug);
* chooses family/episode audits from timestamp/support counts only, never model metrics;
* reports exact TP/FP/FN/TN for every outer seed;
* attaches Wilson 95% intervals to recall and FPR;
* uses recall lower confidence bound and FPR upper confidence bound as the conservative
  audit view, so a small 100% point estimate is never presented as certainty;
* evaluates multiple support-qualified unseen family episodes with the fusion frozen
  from X-IIoTID.

This remains an independent public-dataset simulation, not proof of an undisclosed
production zero-day.
"""
from __future__ import annotations

import argparse
import json
import math
from pathlib import Path

import numpy as np
import pandas as pd

from .v47_unseen_family import build_minute_state, make_sequences
from .v59_unsw_independent_replication import COMMON_FEATURES, adapt_unsw, load_unsw_raw, sha256
from .v62_unsw_episode_holdout import _episodes_for_family, _build_split, evaluate_one

MIN_TRAIN = 500
MIN_TRAIN_BENIGN = 100
MIN_TRAIN_ATTACK = 20
MIN_CALIBRATION = 100
MIN_POLICY = 100
MIN_CALIBRATION_BENIGN = 30
MIN_POLICY_BENIGN = 30
MIN_POSITIVE = 20
MIN_NEGATIVE = 200


def wilson_interval(successes: int, total: int, z: float = 1.959963984540054):
    if total <= 0:
        return {"lower": None, "upper": None}
    p = successes / total
    z2 = z * z
    den = 1.0 + z2 / total
    center = (p + z2 / (2.0 * total)) / den
    margin = z * math.sqrt((p * (1.0 - p) / total) + z2 / (4.0 * total * total)) / den
    return {"lower": float(max(0.0, center - margin)), "upper": float(min(1.0, center + margin))}


def support_for(seq, split):
    clean_benign = seq["clean"] & (seq["y"] == 0)
    train_attack = split["train"] & (seq["y"] == 1)
    train_benign = split["train"] & (seq["y"] == 0)
    return {
        "train": int(split["train"].sum()),
        "train_benign": int(train_benign.sum()),
        "train_attack": int(train_attack.sum()),
        "calibration": int(split["calibration"].sum()),
        "calibration_benign": int((split["calibration"] & clean_benign).sum()),
        "policy": int(split["policy"].sum()),
        "policy_benign": int((split["policy"] & clean_benign).sum()),
        "positive": int(split["test_positive"].sum()),
        "clean_history_positive": int(split["clean_history_positive"].sum()),
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


def discover_audits(seq, available, max_audits):
    candidates = []
    rejected = []
    for family in available:
        for episode in _episodes_for_family(seq, family):
            split = _build_split(seq, family, episode)
            if split is None:
                continue
            s = support_for(seq, split)
            row = {
                "family": family,
                "episode": [int(episode[0]), int(episode[1])],
                "support": s,
                "split": split,
            }
            if support_ok(s):
                candidates.append(row)
            else:
                rejected.append({k: row[k] for k in ("family", "episode", "support")})

    if not candidates:
        raise RuntimeError(
            "No UNSW episode satisfies the conservative benign-reference support contract; "
            f"closest_support={sorted(rejected, key=lambda r: (r['support']['policy_benign'], r['support']['calibration_benign'], r['support']['positive']), reverse=True)[:12]}"
        )

    # One prospective episode per family: choose the earliest episode that becomes
    # eligible under the predeclared support contract. No model outcome is available.
    first_by_family = {}
    for row in sorted(candidates, key=lambda r: (r["family"], r["episode"][0], r["episode"][1])):
        first_by_family.setdefault(row["family"], row)

    rows = list(first_by_family.values())
    # If runtime must be bounded, prefer larger test support only. Still no model score.
    rows.sort(
        key=lambda r: (
            r["support"]["positive"],
            r["support"]["negative"],
            r["support"]["policy_benign"],
            r["support"]["calibration_benign"],
            r["family"],
        ),
        reverse=True,
    )
    selected = rows[:max_audits]
    support_audit = [
        {"family": r["family"], "episode": r["episode"], "support": r["support"]}
        for r in rows
    ]
    return selected, support_audit, rejected[:100]


def decorate_result(result):
    perfect_flags = []
    conservative_seed_passes = []
    for seed, row in result["seeds"].items():
        m = row["all_future_test"]
        tp, fn, fp, tn = m.get("tp", 0), m.get("fn", 0), m.get("fp", 0), m.get("tn", 0)
        rci = wilson_interval(tp, tp + fn)
        fci = wilson_interval(fp, fp + tn)
        m["recall_wilson95"] = rci
        m["fpr_wilson95"] = fci
        m["conservative_recall_lower95"] = rci["lower"]
        m["conservative_fpr_upper95"] = fci["upper"]
        point_perfect = m.get("recall") == 1.0
        m["perfect_point_estimate_warning"] = bool(point_perfect)
        if point_perfect:
            perfect_flags.append(str(seed))
        conservative_seed_passes.append(
            rci["lower"] is not None
            and fci["upper"] is not None
            and rci["lower"] >= 0.80
            and fci["upper"] <= 0.01
        )

    result["summary"]["perfect_recall_point_estimate_seeds"] = perfect_flags
    result["summary"]["conservative_interval_gate_passed_all_seeds"] = all(conservative_seed_passes)
    result["summary"]["conservative_recall_lower95"] = {
        "min": float(min(r["all_future_test"]["recall_wilson95"]["lower"] for r in result["seeds"].values())),
        "mean": float(np.mean([r["all_future_test"]["recall_wilson95"]["lower"] for r in result["seeds"].values()])),
    }
    result["summary"]["conservative_fpr_upper95"] = {
        "max": float(max(r["all_future_test"]["fpr_wilson95"]["upper"] for r in result["seeds"].values())),
        "mean": float(np.mean([r["all_future_test"]["fpr_wilson95"]["upper"] for r in result["seeds"].values()])),
    }
    return result


def aggregate(results):
    point_recalls, point_fprs, lower_recalls, upper_fprs = [], [], [], []
    for result in results:
        for row in result["seeds"].values():
            m = row["all_future_test"]
            point_recalls.append(m["recall"])
            point_fprs.append(m["fpr"])
            lower_recalls.append(m["recall_wilson95"]["lower"])
            upper_fprs.append(m["fpr_wilson95"]["upper"])
    return {
        "family_episode_audits": len(results),
        "seed_evaluations": len(point_recalls),
        "raw_macro_recall_mean": float(np.mean(point_recalls)),
        "raw_macro_recall_sd": float(np.std(point_recalls, ddof=1)) if len(point_recalls) > 1 else 0.0,
        "raw_macro_fpr_mean": float(np.mean(point_fprs)),
        "raw_macro_fpr_sd": float(np.std(point_fprs, ddof=1)) if len(point_fprs) > 1 else 0.0,
        "conservative_recall_lower95_worst": float(min(lower_recalls)),
        "conservative_recall_lower95_mean": float(np.mean(lower_recalls)),
        "conservative_fpr_upper95_worst": float(max(upper_fprs)),
        "conservative_fpr_upper95_mean": float(np.mean(upper_fprs)),
        "all_interval_gates_pass": bool(all(r["summary"]["conservative_interval_gate_passed_all_seeds"] for r in results)),
    }


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--dataset-root", required=True)
    p.add_argument("--frozen-config", required=True)
    p.add_argument("--output", required=True)
    p.add_argument("--seeds", nargs="+", type=int, default=[42, 43, 44])
    p.add_argument("--epochs", type=int, default=18)
    p.add_argument("--max-audits", type=int, default=4)
    args = p.parse_args()
    if len(set(args.seeds)) < 3:
        p.error("At least three distinct outer seeds required")

    out = Path(args.output)
    if out.exists():
        p.error("Output exists; V63 evidence is immutable")
    out.mkdir(parents=True)

    raw, shard_audit = load_unsw_raw(Path(args.dataset_root))
    adapted, y, family = adapt_unsw(raw)
    dt = pd.to_datetime(adapted["Timestamp"], unit="s", errors="coerce", utc=True)
    state, fcols, src_col = build_minute_state(adapted, dt, y, family, list(COMMON_FEATURES))
    seq = make_sequences(state, fcols)
    available = sorted({x for steps in seq["step_families"] for fams in steps for x in fams})

    selected, support_audit, rejected = discover_audits(seq, available, args.max_audits)
    frozen_path = Path(args.frozen_config)
    frozen = json.loads(frozen_path.read_text())
    results = [
        decorate_result(evaluate_one(seq, audit, tuple(args.seeds), args.epochs, frozen))
        for audit in selected
    ]
    summary = aggregate(results)

    report = {
        "protocol": "V63 conservative UNSW-NB15 unseen-family episode audit with frozen V57 fusion",
        "claim_boundary": (
            "Independent public-dataset unseen-family/campaign simulation. Family/episode selection uses timestamp/support only. "
            "Point estimates are accompanied by Wilson 95% intervals; conservative headline uses recall lower bound and FPR upper bound. "
            "This is not production zero-day proof."
        ),
        "anti_perfect_metric_policy": (
            "Do not headline a 100% point estimate without exact support and interval. The conservative result is the Wilson lower 95% recall bound, "
            "not a capped or manually reduced metric."
        ),
        "dataset": "UNSW-NB15 raw four-shard flow corpus combined by original timestamps",
        "dataset_shards": shard_audit,
        "frozen_config_sha256": sha256(frozen_path),
        "fusion_reused_without_selection": True,
        "unsw_metrics_used_for_fusion_selection": False,
        "episode_selection_uses_model_metrics": False,
        "support_contract": {
            "min_train": MIN_TRAIN,
            "min_train_benign": MIN_TRAIN_BENIGN,
            "min_train_attack": MIN_TRAIN_ATTACK,
            "min_calibration": MIN_CALIBRATION,
            "min_calibration_benign": MIN_CALIBRATION_BENIGN,
            "min_policy": MIN_POLICY,
            "min_policy_benign": MIN_POLICY_BENIGN,
            "min_positive": MIN_POSITIVE,
            "min_negative": MIN_NEGATIVE,
        },
        "available_families": available,
        "selected_audits": [{"family": a["family"], "episode": a["episode"], "support": a["support"]} for a in selected],
        "qualified_family_audit": support_audit,
        "rejected_support_examples": rejected,
        "common_network_features": list(COMMON_FEATURES),
        "source_group_column": src_col,
        "seeds": list(args.seeds),
        "results": results,
        "summary": summary,
    }
    (out / "summary.json").write_text(json.dumps(report, indent=2, allow_nan=False) + "\n")
    print(json.dumps({"selected": report["selected_audits"], "summary": summary}, indent=2), flush=True)


if __name__ == "__main__":
    main()
