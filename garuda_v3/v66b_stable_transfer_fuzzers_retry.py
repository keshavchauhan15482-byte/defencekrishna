"""V66b execution fix for the precommitted V66 Fuzzers benchmark.

The first V66 attempt stopped before any development model was trained and before any
Fuzzers reserve score was computed. The cause was purely in the model-free development
campaign chooser: it checked only one support-qualified campaign per family and dropped
the whole family when that single campaign lacked two-class/benign-reference support.

V66b preserves the exact precommitted Fuzzers family/campaign and the exact model/
stability change. It only searches the already-predeclared support-only campaign grid
for a campaign that satisfies the predeclared model-free feasibility contract. No
Fuzzers model score is consulted in this search.
"""
from __future__ import annotations

from . import v62_unsw_rolling_campaign_holdout as engine
from . import v66_stable_transfer_fuzzers as v66
from .v64_unsw_unseen_transition_fast import cached_campaign_split, fast_campaign_candidates


def exhaustive_model_free_choose_dev_campaign(seq, family, reserve_family, reserve_cutoff):
    fam = engine.canonical(family)
    if fam in {v66.EXPECTED_RESERVE, "worms"}:
        return None

    rows = fast_campaign_candidates(
        seq,
        family,
        upper_limit=reserve_cutoff,
        permanent_block=(reserve_family,),
        min_positive=engine.MIN_DEV_POSITIVE,
    )
    feasible = []
    for campaign in rows:
        split = cached_campaign_split(
            seq,
            family,
            campaign["campaign_cutoff"],
            upper_limit=reserve_cutoff,
            permanent_block=(reserve_family,),
        )
        if v66._model_free_dev_feasible(seq, split):
            feasible.append(campaign)

    if not feasible:
        return None

    # Model-free deterministic choice: latest feasible campaign first; ties use only
    # support counts. No development metric and no reserve metric is available here.
    return max(
        feasible,
        key=lambda r: (
            int(r["campaign_cutoff"]),
            int(r["support"]["positive"]),
            int(r["support"]["negative"]),
            int(r["support"]["calibration"]),
            int(r["support"]["policy"]),
        ),
    )


def main():
    v66.model_free_choose_dev_campaign = exhaustive_model_free_choose_dev_campaign
    v66.main()


if __name__ == "__main__":
    main()
