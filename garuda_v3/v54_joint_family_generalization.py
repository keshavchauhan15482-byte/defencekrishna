"""V54 joint-family generalisation hardening.

Purpose
-------
Fix the gap exposed by the V48 joint-reserve diagnostic without tuning on the
Exploitation/C&C regression families.

V54 selects one alert fusion only from already-exposed development families.
Selection itself simulates the hard deployment condition by withholding pairs
of development families *together* while the V48 reserve families are excluded
from model fitting, calibration, policy fitting and score-selection metrics.

Only after the score rule is frozen do we run the already-exposed
Exploitation+C&C joint-reserve regression. These two families are therefore a
regression benchmark, not a fresh untouched holdout.
"""
from __future__ import annotations

import argparse
import itertools
import json
from pathlib import Path

import numpy as np
import pandas as pd

from .v47_unseen_family import (
    FPR_BUDGET,
    SEEDS,
    binary_metrics,
    build_minute_state,
    choose_network_numeric_features,
    detect_label_hierarchy,
    fpr_threshold,
    make_sequences,
    parse_time,
    sha256,
    temporal_masks,
    train_world_model,
)
from .v48_strict_runner import canonical_family_name, reserve_exposure_mask
from .v48_unseen_fusion import (
    COMPONENTS,
    EXPOSED_DEVELOPMENT_FAMILIES,
    fused_score,
    raw_components,
)

DEFAULT_RESERVE = ("exploitation", "c&c")
DEFAULT_POLICY_BUDGETS = (0.001, 0.0025, 0.005, 0.01)


def _future_presence(sequences, family):
    return np.asarray(
        [any(family in step for step in steps) for steps in sequences["step_families"]],
        dtype=bool,
    )


def _joint_development_split(sequences, time_masks, withheld_families, reserve_mask):
    """Development split with pair holdout plus permanent reserve isolation."""
    pair_mask = reserve_exposure_mask(sequences, withheld_families)
    blocked = pair_mask | reserve_mask
    return {
        "train": time_masks["train"] & ~blocked,
        "calibration": time_masks["calibration"] & ~blocked,
        "policy": time_masks["policy"] & ~blocked,
        # Score selection must not inspect reserve-adjacent negatives either.
        "selection_negative": (
            time_masks["test"]
            & sequences["clean"]
            & (sequences["y"] == 0)
            & ~reserve_mask
        ),
        "blocked": blocked,
    }


def _joint_reserve_split(sequences, time_masks, reserve_families):
    """One fitting contract excluding every reserve family together."""
    blocked = reserve_exposure_mask(sequences, reserve_families)
    return {
        "train": time_masks["train"] & ~blocked,
        "calibration": time_masks["calibration"] & ~blocked,
        "policy": time_masks["policy"] & ~blocked,
        "test_negative": time_masks["test"] & sequences["clean"] & (sequences["y"] == 0),
        "blocked": blocked,
    }


def _prepare_world_components(sequences, split, seed, epochs):
    world = train_world_model(
        sequences["X"],
        sequences["future"],
        split["train"],
        split["calibration"],
        seed,
        epochs=epochs,
    )
    components = raw_components(world, sequences, split, seed)
    if components is None:
        raise RuntimeError(
            f"Seed {seed}: insufficient benign calibration/policy support after joint exclusion"
        )
    return world, components


def _simplex_weight_sets(step=0.25):
    """Deterministic score candidates on comparable benign-tail evidence axes."""
    n = int(round(1.0 / step))
    rows = []
    seen = set()

    def add(name, vals):
        vals = np.asarray(vals, dtype=float)
        if np.any(vals < 0) or not np.isclose(vals.sum(), 1.0):
            return
        key = tuple(np.round(vals, 8).tolist())
        if key in seen:
            return
        seen.add(key)
        rows.append(
            {
                "name": name,
                "weights": {c: float(v) for c, v in zip(COMPONENTS, vals)},
            }
        )

    # Full 0.25 simplex gives 70 combinations for five components.
    def compositions(total, parts, prefix=()):
        if parts == 1:
            yield prefix + (total,)
            return
        for i in range(total + 1):
            yield from compositions(total - i, parts - 1, prefix + (i,))

    for counts in compositions(n, len(COMPONENTS)):
        vals = [x / n for x in counts]
        label = "_".join(
            f"{COMPONENTS[i]}{int(round(v * 100))}"
            for i, v in enumerate(vals)
            if v > 0
        )
        add(label, vals)

    # Preserve exact published V48 fusion as an explicit candidate.
    add(
        "published_v48_transfer75_energy25",
        [
            0.75 if c == "known_attack_transfer"
            else 0.25 if c == "transition_energy"
            else 0.0
            for c in COMPONENTS
        ],
    )
    return rows


def _metric(positive, negative, score, threshold):
    ids = np.where(positive | negative)[0]
    if int(positive.sum()) == 0 or int(negative.sum()) == 0:
        return None
    return binary_metrics(positive[ids].astype(int), score[ids], threshold)


def _selection_objective(fold_rows):
    """Prioritise robustness: gate folds, safe folds, then worst-family recall."""
    state_rows = [r for r in fold_rows if r["state_gate_passed"]]
    if not state_rows:
        return (0, 0, 0.0, 0.0, -1.0)

    safe = [
        r for r in state_rows
        if r["fpr"] is not None and r["fpr"] <= FPR_BUDGET
    ]
    gate = [
        r for r in safe
        if r["recall"] is not None and r["recall"] >= 0.80
    ]
    recalls = [float(r["recall"]) for r in safe if r["recall"] is not None]
    worst = min(recalls) if recalls else 0.0
    mean = float(np.mean(recalls)) if recalls else 0.0
    max_fpr = max((float(r["fpr"]) for r in state_rows if r["fpr"] is not None), default=1.0)
    return (len(gate), len(safe), worst, mean, -max_fpr)


def choose_joint_robust_fusion(dev_folds, policy_budgets=DEFAULT_POLICY_BUDGETS):
    """Select only on development pair-holdout folds; reserve labels never enter."""
    candidates = []
    for candidate in _simplex_weight_sets():
        for budget in policy_budgets:
            rows = []
            for fold in dev_folds:
                score = fused_score(fold["components"]["evidence"], candidate["weights"])
                policy = fold["components"]["policy_benign"]
                threshold = fpr_threshold(score[policy], budget)
                metrics = _metric(fold["positive"], fold["negative"], score, threshold)
                if metrics is None:
                    continue
                rows.append(
                    {
                        "withheld_pair": list(fold["withheld_pair"]),
                        "family": fold["family"],
                        "seed": fold["seed"],
                        "state_gate_passed": bool(fold["world"]["state_gate_passed"]),
                        "threshold": float(threshold),
                        "recall": metrics.get("recall"),
                        "fpr": metrics.get("fpr"),
                    }
                )
            objective = _selection_objective(rows)
            candidates.append(
                {
                    "name": candidate["name"],
                    "weights": candidate["weights"],
                    "policy_budget": float(budget),
                    "objective": list(objective),
                    "folds": rows,
                }
            )
    candidates.sort(key=lambda r: tuple(r["objective"]) + (-r["policy_budget"],), reverse=True)
    if not candidates:
        raise RuntimeError("No development fusion candidates")
    return candidates[0], candidates


def build_pair_holdout_cache(
    sequences,
    time_masks,
    development_families,
    reserve_families,
    seeds,
    epochs,
):
    """Create pair-held-out development folds with reserve fully isolated."""
    reserve_mask = reserve_exposure_mask(sequences, reserve_families)
    cache = []
    pair_support = []

    for pair in itertools.combinations(development_families, 2):
        split = _joint_development_split(sequences, time_masks, pair, reserve_mask)
        positives = {
            fam: (_future_presence(sequences, fam) & ~reserve_mask)
            for fam in pair
        }
        negative = split["selection_negative"]
        support = {
            "pair": list(pair),
            "train": int(split["train"].sum()),
            "calibration": int(split["calibration"].sum()),
            "policy": int(split["policy"].sum()),
            "negative": int(negative.sum()),
            "positive": {fam: int(positives[fam].sum()) for fam in pair},
        }
        pair_support.append(support)
        if (
            support["train"] < 50
            or support["calibration"] < 20
            or support["policy"] < 20
            or support["negative"] < 50
            or any(v < 20 for v in support["positive"].values())
        ):
            continue

        for seed in seeds:
            print(f"V54 DEV pair={pair} seed={seed}", flush=True)
            world, components = _prepare_world_components(sequences, split, seed, epochs)
            for fam in pair:
                cache.append(
                    {
                        "withheld_pair": pair,
                        "family": fam,
                        "seed": seed,
                        "world": world,
                        "components": components,
                        "positive": positives[fam],
                        "negative": negative,
                    }
                )

    if len(cache) < 6:
        raise RuntimeError(
            f"Insufficient pair-held-out development folds: {len(cache)}; support={pair_support}"
        )
    return cache, pair_support, reserve_mask


def evaluate_joint_reserve(
    sequences,
    time_masks,
    reserve_families,
    seeds,
    epochs,
    frozen,
):
    """Fit once per seed with all reserve families absent, then score each family."""
    split = _joint_reserve_split(sequences, time_masks, reserve_families)
    positives = {fam: _future_presence(sequences, fam) for fam in reserve_families}
    rows = {fam: {} for fam in reserve_families}
    group_rows = {}

    for seed in seeds:
        print(f"V54 JOINT RESERVE families={reserve_families} seed={seed}", flush=True)
        world, components = _prepare_world_components(sequences, split, seed, epochs)
        score = fused_score(components["evidence"], frozen["weights"])
        policy = components["policy_benign"]
        threshold = fpr_threshold(score[policy], frozen["policy_budget"])
        union_positive = np.logical_or.reduce([positives[f] for f in reserve_families])
        union_metric = _metric(union_positive, split["test_negative"], score, threshold)
        group_rows[str(seed)] = {
            "threshold": float(threshold),
            "test": union_metric,
            "state_gate_passed": bool(world["state_gate_passed"]),
        }

        for fam in reserve_families:
            metric = _metric(positives[fam], split["test_negative"], score, threshold)
            state_mask = positives[fam] | split["test_negative"]
            test_mse = float(
                np.mean(
                    (
                        world["pred"][state_mask]
                        - world["future_scaled"][state_mask]
                    )
                    ** 2
                )
            )
            persistence_mse = float(
                np.mean(
                    (
                        world["persistence"][state_mask]
                        - world["future_scaled"][state_mask]
                    )
                    ** 2
                )
            )
            rows[fam][str(seed)] = {
                "threshold": float(threshold),
                "test": metric,
                "state": {
                    "validation_mse": float(world["validation_mse"]),
                    "validation_persistence_mse": float(world["validation_persistence_mse"]),
                    "state_gate_passed": bool(world["state_gate_passed"]),
                    "test_mse": test_mse,
                    "test_persistence_mse": persistence_mse,
                    "test_state_gate_passed": bool(test_mse < persistence_mse),
                },
            }

    def summarize(seed_rows):
        vals = list(seed_rows.values())

        def stat(key):
            x = [r["test"].get(key) for r in vals if r.get("test") and r["test"].get(key) is not None]
            return {
                "mean": float(np.mean(x)) if x else None,
                "sd": float(np.std(x, ddof=1)) if len(x) > 1 else None,
            }

        return {
            "evaluated_seeds": len(vals),
            "recall": stat("recall"),
            "fpr": stat("fpr"),
            "precision": stat("precision"),
            "f1": stat("f1"),
            "state_gate_passed_all_seeds": bool(
                vals and all(r["state"]["state_gate_passed"] for r in vals)
            ),
            "test_state_gate_passed_all_seeds": bool(
                vals and all(r["state"]["test_state_gate_passed"] for r in vals)
            ),
            "reference_gate_passed_all_seeds": bool(
                vals
                and all(
                    r["state"]["state_gate_passed"]
                    and r["test"].get("fpr") is not None
                    and r["test"]["fpr"] <= FPR_BUDGET
                    and r["test"].get("recall") is not None
                    and r["test"]["recall"] >= 0.80
                    for r in vals
                )
            ),
        }

    return {
        "support": {
            "train": int(split["train"].sum()),
            "calibration": int(split["calibration"].sum()),
            "policy": int(split["policy"].sum()),
            "test_negative": int(split["test_negative"].sum()),
            "blocked": int(split["blocked"].sum()),
            "positive": {fam: int(positives[fam].sum()) for fam in reserve_families},
        },
        "families": {
            fam: {"seeds": rows[fam], "summary": summarize(rows[fam])}
            for fam in reserve_families
        },
        "group_seeds": group_rows,
    }


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--csv", required=True)
    p.add_argument("--output", required=True)
    p.add_argument("--epochs", type=int, default=12)
    p.add_argument("--seeds", nargs="+", type=int, default=list(SEEDS))
    p.add_argument("--reserve-families", nargs="+", default=list(DEFAULT_RESERVE))
    args = p.parse_args()
    if len(set(args.seeds)) < 3:
        p.error("At least three distinct seeds required")

    out = Path(args.output)
    if out.exists():
        p.error("Output exists; V54 evidence is immutable")
    out.mkdir(parents=True)

    csv_path = Path(args.csv)
    df = pd.read_csv(csv_path, low_memory=False)
    dt, date_col, ts_col, time_method = parse_time(df)
    binary, family, binary_col, family_col, label_profiles = detect_label_hierarchy(df)
    family = family.map(canonical_family_name)
    feature_cols, feature_audit = choose_network_numeric_features(df)
    state, state_features, src_col = build_minute_state(
        df, dt, binary, family, feature_cols
    )
    sequences = make_sequences(state, state_features)
    time_masks, boundaries = temporal_masks(sequences["cutoff"])

    available = sorted(
        {
            item
            for steps in sequences["step_families"]
            for fams in steps
            for item in fams
        }
    )
    reserve = [canonical_family_name(f) for f in args.reserve_families]
    missing = [f for f in reserve if f not in available]
    if missing:
        raise RuntimeError(f"Requested reserve families missing: {missing}; available={available}")

    exposed = [
        canonical_family_name(f)
        for f in EXPOSED_DEVELOPMENT_FAMILIES
        if canonical_family_name(f) in available
        and canonical_family_name(f) not in set(reserve)
    ]
    if len(exposed) < 4:
        raise RuntimeError(f"Need >=4 development families for pair simulation; found {exposed}")

    dev_cache, pair_support, reserve_mask = build_pair_holdout_cache(
        sequences,
        time_masks,
        exposed,
        reserve,
        tuple(args.seeds),
        args.epochs,
    )
    winner, candidates = choose_joint_robust_fusion(dev_cache)
    frozen = {
        "protocol": "V54 pair-held-out development-selected joint-family fusion",
        "development_families": exposed,
        "development_pair_count": len({tuple(r["withheld_pair"]) for r in dev_cache}),
        "reserve_families": reserve,
        "reserve_blocked_during_score_selection": True,
        "reserve_blocked_sequence_count": int(reserve_mask.sum()),
        "reserve_metrics_used_for_selection": False,
        "weights": winner["weights"],
        "policy_budget": winner["policy_budget"],
        "selection_candidate": winner["name"],
        "selection_objective": winner["objective"],
        "selection_rule": (
            "lexicographic: more >=80% recall + <=1% FPR gate folds, "
            "more <=1% FPR folds, higher worst safe recall, "
            "higher mean recall, lower max FPR"
        ),
    }
    (out / "frozen_config.json").write_text(
        json.dumps(frozen, indent=2, allow_nan=False) + "\n"
    )

    reserve_result = evaluate_joint_reserve(
        sequences,
        time_masks,
        reserve,
        tuple(args.seeds),
        args.epochs,
        frozen,
    )

    report = {
        "protocol": frozen["protocol"],
        "claim_boundary": (
            "Exploitation/C&C were already exposed by earlier project work. "
            "They are excluded from this V54 model fitting and from score selection, "
            "but this run is a regression diagnostic, not a fresh untouched holdout."
        ),
        "source": {
            "filename": csv_path.name,
            "sha256": sha256(csv_path),
            "rows": int(len(df)),
            "columns": int(len(df.columns)),
        },
        "seeds": list(args.seeds),
        "release_reference_gate": {"fpr_max": FPR_BUDGET, "recall_min": 0.80},
        "time": {
            "date_column": date_col,
            "timestamp_column": ts_col,
            "method": time_method,
            "boundaries": boundaries,
        },
        "labels": {
            "binary": binary_col,
            "family": family_col,
            "profiles": label_profiles,
        },
        "network_only_feature_audit": {
            "raw_selected": feature_cols,
            "state_feature_count": len(state_features),
            "audit": feature_audit,
        },
        "source_group_column": src_col,
        "development_pair_support": pair_support,
        "frozen_config": frozen,
        "candidate_count": len(candidates),
        "top_candidates": [
            {
                "name": c["name"],
                "weights": c["weights"],
                "policy_budget": c["policy_budget"],
                "objective": c["objective"],
            }
            for c in candidates[:20]
        ],
        "joint_reserve_regression": reserve_result,
        "automatic_containment_approved": False,
    }
    (out / "summary.json").write_text(
        json.dumps(report, indent=2, allow_nan=False) + "\n"
    )
    print(
        json.dumps(
            {
                "frozen_config": frozen,
                "joint_reserve_summary": {
                    fam: block["summary"]
                    for fam, block in reserve_result["families"].items()
                },
            },
            indent=2,
            allow_nan=False,
        ),
        flush=True,
    )


if __name__ == "__main__":
    main()
