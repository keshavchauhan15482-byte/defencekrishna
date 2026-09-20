"""V62 rolling-campaign fresh-family UNSW-NB15 benchmark.

V61 showed that a fixed global last-15% test window did not leave support for any
fresh family after Backdoors had already been inspected in V59. V62 keeps the
fresh-family rule but chooses a forward-in-time family campaign by support/timestamps
only, before any model score is computed.

Backdoors is development-only because V59 metrics were inspected. The selected V62
reserve family and campaign cutoff are frozen from support counts before training.
Fusion is selected only on other development-family campaign folds. The V60
persistence-anchored residual forecaster is used for state prediction.

This is controlled public cyber-range evidence, not a live Internet zero-day claim.
"""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path

import numpy as np
import pandas as pd

from .v47_unseen_family import EMBARGO_MINUTES, FPR_BUDGET, binary_metrics, build_minute_state, fpr_threshold
from .v48_unseen_fusion import raw_components
from .v55_nonlinear_joint_generalization import COMPONENTS, candidate_weights, extended_evidence, fused_extended
from .v59_unsw_independent_replication import COMMON_FEATURES, adapt_unsw, load_unsw_raw
from .v60_residual_state_forecasting import train_residual_world_model
from .v61_unsw_source_aware_fresh_holdout import (
    canonical,
    future_presence,
    history_presence,
    make_sequences_with_source,
    source_aware_exposure_mask,
)

SEEDS = (42, 43, 44)
CONTAMINATED = {"backdoors"}
MIN_TRAIN = 500
MIN_CAL = 100
MIN_POLICY = 100
MIN_NEGATIVE = 100
MIN_RESERVE_POSITIVE = 20
MIN_DEV_POSITIVE = 8
MAX_DEV_FAMILIES = 5
CAMPAIGN_FRACTION = 0.25
EMBARGO_SECONDS = EMBARGO_MINUTES * 60
POLICY_BUDGETS = (0.001, 0.0025, 0.005, 0.01)
DEV_FPR_MARGIN = 0.01


def canonical_hash(payload):
    raw = json.dumps(payload, sort_keys=True, separators=(",", ":"), allow_nan=False).encode()
    return hashlib.sha256(raw).hexdigest()


def clean_family_positive(seq, family):
    return seq["clean"] & future_presence(seq, family) & ~history_presence(seq, family)


def _chronological_fit_masks(seq, campaign_cutoff, blocked):
    fit_end = int(campaign_cutoff) - EMBARGO_SECONDS
    eligible = seq["cutoff"] < fit_end
    times = np.unique(seq["cutoff"][eligible])
    if len(times) < 20:
        return None, None
    b1 = int(times[int(0.60 * (len(times) - 1))])
    b2 = int(times[int(0.80 * (len(times) - 1))])
    train = (seq["cutoff"] <= b1) & ~blocked
    calibration = (seq["cutoff"] > b1 + EMBARGO_SECONDS) & (seq["cutoff"] <= b2) & ~blocked
    policy = (seq["cutoff"] > b2 + EMBARGO_SECONDS) & (seq["cutoff"] < fit_end) & ~blocked
    return {
        "train": train,
        "calibration": calibration,
        "policy": policy,
    }, {"fit_end": fit_end, "b1": b1, "b2": b2}


def campaign_split(seq, family, campaign_cutoff, *, upper_limit=None, permanent_block=()):
    family = canonical(family)
    permanent_block = tuple(canonical(x) for x in permanent_block)
    own_block = source_aware_exposure_mask(seq, [family])
    permanent_mask = source_aware_exposure_mask(seq, permanent_block) if permanent_block else np.zeros(len(seq["X"]), dtype=bool)
    blocked = own_block | permanent_mask
    fit, bounds = _chronological_fit_masks(seq, int(campaign_cutoff), blocked)
    if fit is None:
        return None

    period = seq["cutoff"] >= int(campaign_cutoff)
    if upper_limit is not None:
        period &= seq["cutoff"] < int(upper_limit) - EMBARGO_SECONDS

    positive = period & clean_family_positive(seq, family) & ~permanent_mask
    negative = period & seq["clean"] & (seq["y"] == 0) & ~blocked
    out = dict(fit)
    out.update({
        "positive": positive,
        "negative": negative,
        "blocked": blocked,
        "permanent_blocked": permanent_mask,
        "campaign_cutoff": int(campaign_cutoff),
        "bounds": bounds,
    })
    return out


def support_row(split):
    if split is None:
        return {"train": 0, "calibration": 0, "policy": 0, "positive": 0, "negative": 0}
    return {
        "train": int(split["train"].sum()),
        "calibration": int(split["calibration"].sum()),
        "policy": int(split["policy"].sum()),
        "positive": int(split["positive"].sum()),
        "negative": int(split["negative"].sum()),
    }


def support_ok(s, min_positive):
    return (
        s["train"] >= MIN_TRAIN
        and s["calibration"] >= MIN_CAL
        and s["policy"] >= MIN_POLICY
        and s["negative"] >= MIN_NEGATIVE
        and s["positive"] >= min_positive
    )


def campaign_candidates(seq, family, *, upper_limit=None, permanent_block=(), min_positive=MIN_RESERVE_POSITIVE):
    pos = clean_family_positive(seq, family)
    if upper_limit is not None:
        pos &= seq["cutoff"] < int(upper_limit) - EMBARGO_SECONDS
    times = np.sort(np.unique(seq["cutoff"][pos]))
    rows = []
    if len(times) == 0:
        return rows
    # Test only cutoffs that can retain the requested number of positive windows.
    for cutoff in times.tolist():
        split = campaign_split(seq, family, cutoff, upper_limit=upper_limit, permanent_block=permanent_block)
        support = support_row(split)
        if support_ok(support, min_positive):
            rows.append({
                "family": canonical(family),
                "campaign_cutoff": int(cutoff),
                "support": support,
                "bounds": split["bounds"],
            })
    return rows


def choose_reserve_support_only(seq, available):
    all_rows = []
    selected_per_family = []
    for family in available:
        family = canonical(family)
        if family in CONTAMINATED:
            continue
        rows = campaign_candidates(seq, family, min_positive=MIN_RESERVE_POSITIVE)
        all_rows.extend(rows)
        if not rows:
            continue
        # Latest support-qualified campaign for each family, using no model outputs.
        best = max(rows, key=lambda r: (r["campaign_cutoff"], r["support"]["positive"], r["support"]["negative"]))
        selected_per_family.append(best)
    if not selected_per_family:
        raise RuntimeError("No fresh UNSW family has a support-qualified rolling campaign")
    # Prefer the chronologically latest campaign; tie-break on support only.
    winner = max(
        selected_per_family,
        key=lambda r: (r["campaign_cutoff"], r["support"]["positive"], r["support"]["negative"], r["support"]["calibration"]),
    )
    return winner, selected_per_family


def choose_dev_campaign(seq, family, reserve_family, reserve_cutoff):
    rows = campaign_candidates(
        seq,
        family,
        upper_limit=reserve_cutoff,
        permanent_block=(reserve_family,),
        min_positive=MIN_DEV_POSITIVE,
    )
    if not rows:
        return None
    return max(rows, key=lambda r: (r["campaign_cutoff"], r["support"]["positive"], r["support"]["negative"]))


def metric(positive, negative, score, threshold):
    ids = np.where(positive | negative)[0]
    if int(positive.sum()) == 0 or int(negative.sum()) == 0:
        return None
    return binary_metrics(positive[ids].astype(int), score[ids], threshold)


def prepare_fold(seq, family, reserve_family, reserve_cutoff, campaign, seed, epochs):
    split = campaign_split(
        seq,
        family,
        campaign["campaign_cutoff"],
        upper_limit=reserve_cutoff,
        permanent_block=(reserve_family,),
    )
    if split is None:
        return None
    world = train_residual_world_model(
        seq["X"], seq["future"], split["train"], split["calibration"], seed, epochs=epochs
    )
    base = raw_components(world, seq, split, seed)
    if base is None:
        return None
    evidence = extended_evidence(base, seq, split, seed)
    return {
        "family": family,
        "seed": int(seed),
        "split": split,
        "world": world,
        "base": base,
        "evidence": evidence,
    }


def robust_objective(rows):
    state_rows = [r for r in rows if r["state_gate_passed"]]
    safe = [r for r in state_rows if r["fpr"] is not None and r["fpr"] <= DEV_FPR_MARGIN]
    gate = [r for r in safe if r["recall"] is not None and r["recall"] >= 0.80]
    recalls = np.asarray([float(r["recall"]) for r in safe if r["recall"] is not None], dtype=float)
    q10 = float(np.quantile(recalls, 0.10)) if len(recalls) else 0.0
    worst = float(np.min(recalls)) if len(recalls) else 0.0
    mean = float(np.mean(recalls)) if len(recalls) else 0.0
    max_fpr = max((float(r["fpr"]) for r in state_rows if r["fpr"] is not None), default=1.0)
    return (len(gate), len(safe), q10, worst, mean, -max_fpr)


def select_fusion(dev_folds):
    candidates = []
    for cand in candidate_weights():
        for budget in POLICY_BUDGETS:
            rows = []
            for fold in dev_folds:
                score = fused_extended(fold["evidence"], cand["weights"])
                policy = fold["base"]["policy_benign"]
                threshold = fpr_threshold(score[policy], budget)
                m = metric(fold["split"]["positive"], fold["split"]["negative"], score, threshold)
                if m is None:
                    continue
                rows.append({
                    "family": fold["family"],
                    "seed": fold["seed"],
                    "state_gate_passed": bool(fold["world"]["state_gate_passed"]),
                    "recall": m.get("recall"),
                    "fpr": m.get("fpr"),
                    "precision": m.get("precision"),
                    "f1": m.get("f1"),
                    "threshold": float(threshold),
                })
            candidates.append({
                "name": cand["name"],
                "weights": cand["weights"],
                "policy_budget": float(budget),
                "objective": list(robust_objective(rows)),
                "folds": rows,
            })
    candidates.sort(key=lambda c: tuple(c["objective"]) + (-c["policy_budget"],), reverse=True)
    return candidates[0], candidates


def confusion_from_metric_inputs(positive, negative, score, threshold):
    ids = np.where(positive | negative)[0]
    y = positive[ids].astype(int)
    pred = (score[ids] >= threshold).astype(int)
    tp = int(((pred == 1) & (y == 1)).sum())
    fn = int(((pred == 0) & (y == 1)).sum())
    fp = int(((pred == 1) & (y == 0)).sum())
    tn = int(((pred == 0) & (y == 0)).sum())
    return {"tp": tp, "fn": fn, "fp": fp, "tn": tn}


def evaluate_reserve(seq, reserve, campaign, seeds, epochs, frozen):
    split = campaign_split(seq, reserve, campaign["campaign_cutoff"])
    rows = {}
    component_reference = {c: [] for c in COMPONENTS}
    for seed in seeds:
        print(f"V62 FRESH reserve={reserve} seed={seed}", flush=True)
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
        m = metric(split["positive"], split["negative"], score, threshold)
        ids = split["positive"] | split["negative"]
        mse = float(np.mean((world["pred"][ids] - world["future_scaled"][ids]) ** 2))
        pmse = float(np.mean((world["persistence"][ids] - world["future_scaled"][ids]) ** 2))
        rows[str(seed)] = {
            "threshold": float(threshold),
            "test": m,
            "confusion": confusion_from_metric_inputs(split["positive"], split["negative"], score, threshold),
            "validation_state_gate_passed": bool(world["state_gate_passed"]),
            "test_state_mse": mse,
            "test_persistence_mse": pmse,
            "test_state_gate_passed": bool(mse < pmse),
            "blend_alpha": float(world["blend_alpha"]),
            "trend_beta": float(world["trend_beta"]),
        }
        for c in COMPONENTS:
            ct = fpr_threshold(evidence[c][policy], frozen["policy_budget"])
            cm = metric(split["positive"], split["negative"], evidence[c], ct)
            component_reference[c].append({"seed": int(seed), "threshold": float(ct), "test": cm})

    vals = list(rows.values())
    def st(k):
        x = [r["test"].get(k) for r in vals if r["test"] and r["test"].get(k) is not None]
        return {"mean": float(np.mean(x)) if x else None, "sd": float(np.std(x, ddof=1)) if len(x) > 1 else None}
    summary = {
        "evaluated_seeds": len(vals),
        "recall": st("recall"),
        "fpr": st("fpr"),
        "precision": st("precision"),
        "f1": st("f1"),
        "alert_gate_passed_all_seeds": all(
            r["test"] is not None and r["test"]["recall"] >= 0.80 and r["test"]["fpr"] <= FPR_BUDGET
            for r in vals
        ),
        "validation_state_gate_passed_all_seeds": all(r["validation_state_gate_passed"] for r in vals),
        "test_state_gate_passed_all_seeds": all(r["test_state_gate_passed"] for r in vals),
    }
    return {
        "support": support_row(split),
        "campaign_cutoff": int(campaign["campaign_cutoff"]),
        "seeds": rows,
        "summary": summary,
        "component_reference": component_reference,
    }


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--dataset-root", required=True)
    p.add_argument("--output", required=True)
    p.add_argument("--epochs", type=int, default=18)
    p.add_argument("--seeds", nargs="+", type=int, default=list(SEEDS))
    args = p.parse_args()
    if len(set(args.seeds)) < 3:
        p.error("At least three distinct seeds required")

    out = Path(args.output)
    if out.exists():
        p.error("Output exists; V62 evidence is immutable")
    out.mkdir(parents=True)

    raw, shard_audit = load_unsw_raw(Path(args.dataset_root))
    adapted, y, family = adapt_unsw(raw)
    family = family.map(canonical)
    dt = pd.to_datetime(adapted["Timestamp"], unit="s", errors="coerce", utc=True)
    state, names, src_col = build_minute_state(adapted, dt, y, family, list(COMMON_FEATURES))
    seq = make_sequences_with_source(state, names)
    available = sorted({canonical(x) for steps in seq["step_families"] for fams in steps for x in fams})

    reserve_campaign, reserve_candidates = choose_reserve_support_only(seq, available)
    reserve = reserve_campaign["family"]
    reserve_cutoff = reserve_campaign["campaign_cutoff"]

    support_freeze = {
        "protocol": "V62 support-only reserve/campaign freeze",
        "fresh_reserve_family": reserve,
        "campaign_cutoff": int(reserve_cutoff),
        "support": reserve_campaign["support"],
        "bounds": reserve_campaign["bounds"],
        "contaminated_not_eligible": sorted(CONTAMINATED),
        "selection_used_model_metrics": False,
        "candidate_family_campaigns": reserve_candidates,
    }
    support_freeze["freeze_sha256"] = canonical_hash(support_freeze)
    (out / "support_freeze.json").write_text(json.dumps(support_freeze, indent=2, allow_nan=False) + "\n")
    print(json.dumps({"support_freeze": support_freeze}, indent=2), flush=True)

    dev_campaigns = []
    for fam in available:
        if fam == reserve:
            continue
        campaign = choose_dev_campaign(seq, fam, reserve, reserve_cutoff)
        if campaign is not None:
            dev_campaigns.append(campaign)
    # Support-only cap for runtime; prefer strongest positive support, then latest campaign.
    dev_campaigns.sort(key=lambda r: (r["support"]["positive"], r["campaign_cutoff"]), reverse=True)
    dev_campaigns = dev_campaigns[:MAX_DEV_FAMILIES]
    if len(dev_campaigns) < 2:
        raise RuntimeError(f"Need >=2 support-qualified development campaigns; got {dev_campaigns}")

    dev_folds = []
    for campaign in dev_campaigns:
        fam = campaign["family"]
        for seed in args.seeds:
            print(f"V62 DEV family={fam} seed={seed}", flush=True)
            fold = prepare_fold(seq, fam, reserve, reserve_cutoff, campaign, seed, args.epochs)
            if fold is None:
                raise RuntimeError(f"Development fold failed family={fam} seed={seed}")
            dev_folds.append(fold)

    winner, candidates = select_fusion(dev_folds)
    frozen = {
        "protocol": "V62 rolling-campaign development-selected fusion",
        "weights": winner["weights"],
        "policy_budget": winner["policy_budget"],
        "selection_candidate": winner["name"],
        "selection_objective": winner["objective"],
        "development_families": [r["family"] for r in dev_campaigns],
        "development_campaigns": [
            {"family": r["family"], "campaign_cutoff": r["campaign_cutoff"], "support": r["support"]}
            for r in dev_campaigns
        ],
        "fresh_reserve_family": reserve,
        "fresh_reserve_campaign_cutoff": int(reserve_cutoff),
        "support_freeze_sha256": support_freeze["freeze_sha256"],
        "reserve_metrics_used_for_selection": False,
        "reserve_selected_by_support_only": True,
        "campaign_selected_by_support_only": True,
        "source_aware_embargo": True,
        "previously_inspected_backdoors_used_only_as_development_if_supported": True,
    }
    frozen["config_sha256"] = canonical_hash(frozen)
    (out / "frozen_config.json").write_text(json.dumps(frozen, indent=2, allow_nan=False) + "\n")

    fresh = evaluate_reserve(seq, reserve, reserve_campaign, tuple(args.seeds), args.epochs, frozen)
    report = {
        "protocol": frozen["protocol"],
        "claim_boundary": (
            "Fresh family/campaign evaluation inside independent UNSW-NB15 cyber-range data. "
            "Reserve identity and cutoff were frozen using support/timestamps before model metrics. "
            "This is not an undisclosed live Internet zero-day."
        ),
        "dataset": "UNSW-NB15 raw four-shard flow corpus",
        "dataset_shards": shard_audit,
        "source_group_column": src_col,
        "seeds": list(args.seeds),
        "available_families": available,
        "support_freeze": support_freeze,
        "frozen_config": frozen,
        "candidate_count": len(candidates),
        "top_candidates": [
            {k: c[k] for k in ("name", "weights", "policy_budget", "objective")}
            for c in candidates[:20]
        ],
        "fresh_reserve": fresh,
    }
    (out / "summary.json").write_text(json.dumps(report, indent=2, allow_nan=False) + "\n")
    print(json.dumps({
        "fresh_reserve_family": reserve,
        "campaign_cutoff": reserve_cutoff,
        "frozen_fusion": {k: frozen[k] for k in ("selection_candidate", "weights", "policy_budget", "config_sha256")},
        "support": fresh["support"],
        "summary": fresh["summary"],
    }, indent=2), flush=True)


if __name__ == "__main__":
    main()
