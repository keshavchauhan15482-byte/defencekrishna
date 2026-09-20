"""V64 optimized execution of the V63 unseen-family transition protocol.

Scientific contract is unchanged from V63. This wrapper only caches family exposure
masks and evaluates a fixed support-only campaign grid instead of every positive
minute. No model score is used to choose reserve family/campaign.
"""
from __future__ import annotations

import json
from pathlib import Path

import numpy as np

from . import v62_unsw_rolling_campaign_holdout as engine

_MASK_CACHE = {}


def unseen_family_positive(seq, family):
    return engine.future_presence(seq, family) & ~engine.history_presence(seq, family)


def cached_campaign_split(seq, family, campaign_cutoff, *, upper_limit=None, permanent_block=()):
    family = engine.canonical(family)
    permanent_block = tuple(sorted(engine.canonical(x) for x in permanent_block))
    key = (id(seq), family, permanent_block)
    cached = _MASK_CACHE.get(key)
    if cached is None:
        own = engine.source_aware_exposure_mask(seq, [family])
        permanent = (
            engine.source_aware_exposure_mask(seq, permanent_block)
            if permanent_block else np.zeros(len(seq["X"]), dtype=bool)
        )
        cached = (own | permanent, permanent)
        _MASK_CACHE[key] = cached
    blocked, permanent_mask = cached
    fit, bounds = engine._chronological_fit_masks(seq, int(campaign_cutoff), blocked)
    if fit is None:
        return None
    period = seq["cutoff"] >= int(campaign_cutoff)
    if upper_limit is not None:
        period &= seq["cutoff"] < int(upper_limit) - engine.EMBARGO_SECONDS
    positive = period & unseen_family_positive(seq, family) & ~permanent_mask
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


def fixed_support_grid_times(pos_cutoffs):
    """Predeclared support-only campaign grid, independent of model outcomes."""
    x = np.sort(np.asarray(pos_cutoffs, dtype=np.int64))
    if len(x) == 0:
        return []
    idx = set()
    # Even chronological grid.
    for q in np.linspace(0.10, 0.92, 18):
        idx.add(int(round(q * (len(x) - 1))))
    # Exact tail-support targets so minimum positive support is represented.
    for tail in (20, 25, 30, 40, 50, 75, 100, 150, 200, 300, 500, 750, 1000):
        if len(x) >= tail:
            idx.add(max(0, len(x) - tail))
    idx.update({0, len(x) // 4, len(x) // 2, (3 * len(x)) // 4, len(x) - 1})
    return sorted({int(x[min(max(i, 0), len(x) - 1)]) for i in idx})


def fast_campaign_candidates(seq, family, *, upper_limit=None, permanent_block=(), min_positive=engine.MIN_RESERVE_POSITIVE):
    pos = unseen_family_positive(seq, family)
    if upper_limit is not None:
        pos &= seq["cutoff"] < int(upper_limit) - engine.EMBARGO_SECONDS
    candidate_times = fixed_support_grid_times(seq["cutoff"][pos])
    rows = []
    for cutoff in candidate_times:
        split = cached_campaign_split(
            seq, family, cutoff, upper_limit=upper_limit, permanent_block=permanent_block
        )
        support = engine.support_row(split)
        if engine.support_ok(support, min_positive):
            rows.append({
                "family": engine.canonical(family),
                "campaign_cutoff": int(cutoff),
                "support": support,
                "bounds": split["bounds"],
            })
    return rows


def rewrite_metadata(output_dir: Path):
    p = output_dir / "summary.json"
    if not p.exists():
        return
    d = json.loads(p.read_text())
    d["protocol"] = "V64 optimized V63 unseen-family transition benchmark"
    d["history_contract"] = {
        "same_reserve_family_absent_from_observed_history": True,
        "other_attack_families_allowed_in_observed_history": True,
        "clean_history_required": False,
        "clean_history_support_in_unsw": 0,
    }
    d["campaign_search_contract"] = {
        "selection_uses_model_metrics": False,
        "grid": "18 chronological quantiles plus fixed tail-support targets",
        "exposure_masks_cached_only_for_runtime": True,
    }
    d["claim_boundary"] = (
        "Fresh reserve-family transition evaluation inside independent UNSW-NB15 cyber-range data. "
        "Reserve identity/campaign use support and timestamps only; the same reserve family is absent from "
        "observed history and all fit/calibration/policy data. Other known attack-family history is allowed. "
        "Not clean-history lead-time proof and not a live Internet zero-day."
    )
    p.write_text(json.dumps(d, indent=2, allow_nan=False) + "\n")


if __name__ == "__main__":
    engine.CONTAMINATED.update({"backdoor", "backdoors"})
    engine.clean_family_positive = unseen_family_positive
    engine.campaign_split = cached_campaign_split
    engine.campaign_candidates = fast_campaign_candidates
    engine.main()

    import sys
    if "--output" in sys.argv:
        rewrite_metadata(Path(sys.argv[sys.argv.index("--output") + 1]))
