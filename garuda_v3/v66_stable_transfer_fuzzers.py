"""V66 seed-stable transfer benchmark with a precommitted fresh Fuzzers reserve.

V65 exposed a real reproducibility problem: the Worms reserve had 21/21 detections
for two outer seeds but only 1/21 for the third. V66 treats Worms as an inspected
diagnostic and fixes the source of avoidable classifier randomness before evaluating
an untouched reserve.

The Fuzzers family/campaign and the stability change are committed in
``docs/release/v66_stable_transfer/precommit.json`` before this script is executed.
Fuzzers metrics are never used for feature, fusion, threshold, or model selection.

The nonlinear transfer component is now an average of three fixed ExtraTrees members.
The outer 42/43/44 seeds still train independent state/world models, so genuine world-
model variability remains visible. Fusion selection is development-only and explicitly
prioritizes configurations that pass all outer seeds for each development family.

Point estimates are not rounded down or capped. Exact confusion counts plus Wilson 95%
intervals are reported. A 100% point estimate, if observed, is therefore accompanied by
a lower confidence bound rather than being described as a perfect detector.
"""
from __future__ import annotations

import hashlib
import json
import math
from pathlib import Path

import numpy as np
from sklearn.ensemble import ExtraTreesClassifier

from . import v62_unsw_rolling_campaign_holdout as engine
from .v48_unseen_fusion import tail_evidence
from .v55_nonlinear_joint_generalization import temporal_history_features
from .v64_unsw_unseen_transition_fast import (
    cached_campaign_split,
    fast_campaign_candidates,
    unseen_family_positive,
)

EXPECTED_RESERVE = "fuzzers"
EXPECTED_CUTOFF = 1424257500
EXPECTED_SUPPORT = {
    "train": 10412,
    "calibration": 3521,
    "policy": 3579,
    "positive": 20,
    "negative": 1067,
}
PRECOMMIT = Path("docs/release/v66_stable_transfer/precommit.json")
FIXED_TREE_SEEDS = (20260920, 20260921, 20260922)
TREES_PER_MEMBER = 320
MIN_BENIGN_REFERENCE = 20
MIN_TRAIN_ATTACK = 20
_RAW_TRANSFER_CACHE: dict[str, np.ndarray] = {}
_ORIGINAL_CHOOSE_DEV = engine.choose_dev_campaign


def _sha256(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for block in iter(lambda: f.read(1024 * 1024), b""):
            h.update(block)
    return h.hexdigest()


def _split_cache_key(split) -> str:
    h = hashlib.sha256()
    for name in ("train", "calibration", "policy"):
        h.update(name.encode())
        h.update(np.packbits(np.asarray(split[name], dtype=np.uint8)).tobytes())
    return h.hexdigest()


def stable_nonlinear_transfer_score(X, target, split):
    """Deterministic three-member ExtraTrees probability ensemble.

    The same split receives the same transfer score regardless of the outer world-model
    seed. This removes classifier RNG as a source of deployment instability while the
    independently trained world model remains part of the outer-seed audit.
    """
    key = _split_cache_key(split)
    if key in _RAW_TRANSFER_CACHE:
        return _RAW_TRANSFER_CACHE[key]

    tr = np.where(split["train"])[0]
    target = np.asarray(target, dtype=int)
    if len(tr) < 50 or len(np.unique(target[tr])) < 2:
        raise RuntimeError("Stable nonlinear transfer requires two-class train support")

    feat = temporal_history_features(X)
    feat[~np.isfinite(feat)] = np.nan
    med = np.nanmedian(feat[tr], axis=0)
    med[~np.isfinite(med)] = 0.0
    bad = ~np.isfinite(feat)
    if bad.any():
        feat[bad] = med[np.where(bad)[1]]

    probs = []
    for seed in FIXED_TREE_SEEDS:
        model = ExtraTreesClassifier(
            n_estimators=TREES_PER_MEMBER,
            max_features="sqrt",
            min_samples_leaf=2,
            class_weight="balanced",
            random_state=seed,
            n_jobs=1,
        )
        model.fit(feat[tr], target[tr])
        probs.append(model.predict_proba(feat)[:, 1])
    raw = np.mean(np.stack(probs, axis=0), axis=0)
    _RAW_TRANSFER_CACHE[key] = raw
    return raw


def stable_extended_evidence(base_components, sequences, split, seed):
    del seed  # nonlinear transfer is intentionally independent of the outer seed
    evidence = dict(base_components["evidence"])
    raw = stable_nonlinear_transfer_score(sequences["X"], sequences["y"], split)
    cal_benign = base_components["cal_benign"]
    evidence["nonlinear_temporal_transfer"] = tail_evidence(raw[cal_benign], raw)
    return evidence


def _model_free_dev_feasible(seq, split) -> bool:
    if split is None:
        return False
    tr = np.where(split["train"])[0]
    if len(tr) < engine.MIN_TRAIN:
        return False
    y = np.asarray(seq["y"], dtype=int)
    if len(np.unique(y[tr])) < 2 or int((y[tr] == 1).sum()) < MIN_TRAIN_ATTACK:
        return False
    benign = np.asarray(seq["clean"], dtype=bool) & (y == 0)
    cal_benign = int((split["calibration"] & benign).sum())
    policy_benign = int((split["policy"] & benign).sum())
    return cal_benign >= MIN_BENIGN_REFERENCE and policy_benign >= MIN_BENIGN_REFERENCE


def model_free_choose_dev_campaign(seq, family, reserve_family, reserve_cutoff):
    fam = engine.canonical(family)
    if fam in {EXPECTED_RESERVE, "worms"}:
        return None
    campaign = _ORIGINAL_CHOOSE_DEV(seq, family, reserve_family, reserve_cutoff)
    if campaign is None:
        return None
    split = cached_campaign_split(
        seq,
        family,
        campaign["campaign_cutoff"],
        upper_limit=reserve_cutoff,
        permanent_block=(reserve_family,),
    )
    return campaign if _model_free_dev_feasible(seq, split) else None


def precommitted_reserve_support_only(seq, available):
    """Return the already committed Fuzzers campaign; inspect support only."""
    all_candidates = []
    chosen = None
    for family in available:
        fam = engine.canonical(family)
        if fam in engine.CONTAMINATED:
            continue
        rows = fast_campaign_candidates(seq, fam, min_positive=engine.MIN_RESERVE_POSITIVE)
        if rows:
            best = max(
                rows,
                key=lambda r: (
                    r["campaign_cutoff"],
                    r["support"]["positive"],
                    r["support"]["negative"],
                    r["support"]["calibration"],
                ),
            )
            all_candidates.append(best)
        if fam == EXPECTED_RESERVE:
            exact = [r for r in rows if int(r["campaign_cutoff"]) == EXPECTED_CUTOFF]
            if len(exact) == 1:
                chosen = exact[0]
    if chosen is None:
        raise RuntimeError("Precommitted Fuzzers campaign is not support-qualified in this dataset copy")
    if chosen["support"] != EXPECTED_SUPPORT:
        raise RuntimeError(f"Fuzzers support changed: {chosen['support']} != {EXPECTED_SUPPORT}")
    return chosen, all_candidates


def stable_robust_objective(rows):
    """Development-only objective that explicitly rewards all-seed stability."""
    state = [r for r in rows if r["state_gate_passed"]]
    safe = [r for r in state if r["fpr"] is not None and r["fpr"] <= engine.DEV_FPR_MARGIN]
    gate = [r for r in safe if r["recall"] is not None and r["recall"] >= 0.80]

    by_family = {}
    for r in state:
        by_family.setdefault(r["family"], []).append(r)
    family_all_seed_gate = 0
    for fam_rows in by_family.values():
        if len(fam_rows) >= 3 and all(
            r["fpr"] is not None
            and r["recall"] is not None
            and r["fpr"] <= engine.DEV_FPR_MARGIN
            and r["recall"] >= 0.80
            for r in fam_rows
        ):
            family_all_seed_gate += 1

    recalls = np.asarray([float(r["recall"]) for r in safe if r["recall"] is not None], dtype=float)
    worst = float(np.min(recalls)) if len(recalls) else 0.0
    q10 = float(np.quantile(recalls, 0.10)) if len(recalls) else 0.0
    mean = float(np.mean(recalls)) if len(recalls) else 0.0
    sd = float(np.std(recalls, ddof=1)) if len(recalls) > 1 else 1.0
    max_fpr = max((float(r["fpr"]) for r in state if r["fpr"] is not None), default=1.0)
    return (family_all_seed_gate, len(gate), len(safe), worst, q10, mean, -sd, -max_fpr)


def wilson(successes: int, total: int, z: float = 1.959963984540054):
    if total <= 0:
        return {"lower": None, "upper": None}
    p = successes / total
    z2 = z * z
    den = 1.0 + z2 / total
    center = (p + z2 / (2.0 * total)) / den
    margin = z * math.sqrt(p * (1.0 - p) / total + z2 / (4.0 * total * total)) / den
    return {
        "lower": float(max(0.0, center - margin)),
        "upper": float(min(1.0, center + margin)),
    }


def rewrite_evidence(output_dir: Path):
    summary_path = output_dir / "summary.json"
    frozen_path = output_dir / "frozen_config.json"
    support_path = output_dir / "support_freeze.json"
    if not (summary_path.exists() and frozen_path.exists() and support_path.exists()):
        raise RuntimeError("V66 evidence files missing")

    report = json.loads(summary_path.read_text())
    frozen = json.loads(frozen_path.read_text())
    support = json.loads(support_path.read_text())
    pre = json.loads(PRECOMMIT.read_text())

    if support["fresh_reserve_family"] != EXPECTED_RESERVE or int(support["campaign_cutoff"]) != EXPECTED_CUTOFF:
        raise RuntimeError("V66 reserve/campaign deviated from precommit")
    if report["fresh_reserve"]["support"] != EXPECTED_SUPPORT:
        raise RuntimeError("V66 reserve support deviated from precommit")
    if frozen.get("reserve_metrics_used_for_selection") is not False:
        raise RuntimeError("V66 leakage contract violated")

    seed_rows = report["fresh_reserve"]["seeds"]
    recall_lowers = []
    fpr_uppers = []
    for seed, row in seed_rows.items():
        c = row["confusion"]
        rci = wilson(int(c["tp"]), int(c["tp"]) + int(c["fn"]))
        fci = wilson(int(c["fp"]), int(c["fp"]) + int(c["tn"]))
        row["test"]["recall_wilson95"] = rci
        row["test"]["fpr_wilson95"] = fci
        row["test"]["perfect_recall_point_estimate_warning"] = bool(row["test"].get("recall") == 1.0)
        recall_lowers.append(rci["lower"])
        fpr_uppers.append(fci["upper"])

    s = report["fresh_reserve"]["summary"]
    s["conservative_recall_lower95_min"] = float(min(recall_lowers))
    s["conservative_recall_lower95_mean"] = float(np.mean(recall_lowers))
    s["conservative_fpr_upper95_max"] = float(max(fpr_uppers))
    s["conservative_fpr_upper95_mean"] = float(np.mean(fpr_uppers))
    s["conservative_interval_gate_passed_all_seeds"] = bool(
        min(recall_lowers) >= 0.80 and max(fpr_uppers) <= engine.FPR_BUDGET
    )
    s["raw_point_estimate_gate_is_not_sufficient_for_release"] = True

    report["protocol"] = "V66 stable-transfer precommitted Fuzzers unseen-family transition benchmark"
    report["precommit"] = {
        "path": str(PRECOMMIT),
        "sha256": _sha256(PRECOMMIT),
        "reserve_scores_seen_before_precommit": pre["fresh_reserve"]["reserve_scores_seen_before_this_precommit"],
    }
    report["stability_change"] = pre["stability_change"]
    report["reporting_contract"] = pre["reporting_contract"]
    report["claim_boundary"] = (
        "Fuzzers is an unseen-family transition test inside independent UNSW-NB15 cyber-range data. "
        "Its family/campaign and the seed-stability change were committed before any Fuzzers model score was computed. "
        "Other attack-family history may exist. Exact support and Wilson intervals are reported. "
        "This is not clean-history lead-time proof and not a live Internet zero-day."
    )
    summary_path.write_text(json.dumps(report, indent=2, allow_nan=False) + "\n")

    frozen["protocol"] = "V66 stable deterministic transfer ensemble, development-selected fusion"
    frozen["stable_transfer_member_seeds"] = list(FIXED_TREE_SEEDS)
    frozen["trees_per_member"] = TREES_PER_MEMBER
    frozen["fusion_objective"] = "development family-all-seed stability first; reserve metrics excluded"
    frozen["precommit_sha256"] = _sha256(PRECOMMIT)
    frozen_path.write_text(json.dumps(frozen, indent=2, allow_nan=False) + "\n")

    print(json.dumps({
        "reserve": EXPECTED_RESERVE,
        "support": report["fresh_reserve"]["support"],
        "development_families": frozen.get("development_families"),
        "fusion": {
            "candidate": frozen.get("selection_candidate"),
            "weights": frozen.get("weights"),
            "policy_budget": frozen.get("policy_budget"),
        },
        "summary": s,
        "seeds": {
            seed: {
                "confusion": row["confusion"],
                "recall": row["test"].get("recall"),
                "recall_wilson95": row["test"]["recall_wilson95"],
                "fpr": row["test"].get("fpr"),
                "fpr_wilson95": row["test"]["fpr_wilson95"],
            }
            for seed, row in seed_rows.items()
        },
    }, indent=2), flush=True)


def main():
    if not PRECOMMIT.exists():
        raise RuntimeError("V66 precommit missing")
    pre = json.loads(PRECOMMIT.read_text())
    if pre["fresh_reserve"]["family"] != EXPECTED_RESERVE:
        raise RuntimeError("V66 precommit reserve mismatch")
    if int(pre["fresh_reserve"]["campaign_cutoff"]) != EXPECTED_CUTOFF:
        raise RuntimeError("V66 precommit cutoff mismatch")

    engine.CONTAMINATED.update({"backdoor", "backdoors", "worms"})
    engine.clean_family_positive = unseen_family_positive
    engine.campaign_split = cached_campaign_split
    engine.campaign_candidates = fast_campaign_candidates
    engine.choose_reserve_support_only = precommitted_reserve_support_only
    engine.choose_dev_campaign = model_free_choose_dev_campaign
    engine.extended_evidence = stable_extended_evidence
    engine.robust_objective = stable_robust_objective
    engine.MAX_DEV_FAMILIES = int(pre["selection_contract"]["max_development_families"])

    engine.main()

    import sys
    if "--output" not in sys.argv:
        raise RuntimeError("--output required for V66 evidence rewrite")
    output_dir = Path(sys.argv[sys.argv.index("--output") + 1])
    rewrite_evidence(output_dir)


if __name__ == "__main__":
    main()
