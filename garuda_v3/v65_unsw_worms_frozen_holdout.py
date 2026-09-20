"""V65 precommitted fresh Worms holdout on UNSW-NB15.

V64 froze Worms as the fresh reserve from support/timestamps only, before any Worms
model score was computed. V64 then failed while preparing a third development family
(Shellcode), so Worms remains uninspected as a model outcome.

V65 preserves the exact V64 Worms reserve/campaign freeze and limits development to
the first two support/feasibility-qualified families that V64 successfully prepared:
Backdoor and Analysis. This is an engineering-feasibility restriction, not a
performance-based family selection. No Worms score is available before fusion freeze.

Positive contract: the future contains Worms while Worms is absent from the observed
history. Other known attack-family history is allowed because the V62 support audit
proved UNSW has zero fully-benign-history future-family windows.
"""
from __future__ import annotations

import json
from pathlib import Path

from . import v62_unsw_rolling_campaign_holdout as engine
from .v64_unsw_unseen_transition_fast import (
    cached_campaign_split,
    fast_campaign_candidates,
    unseen_family_positive,
)

EXPECTED_RESERVE = "worms"
EXPECTED_CUTOFF = 1424259420
EXPECTED_SUPPORT_FREEZE_SHA256 = "e1446ba66800160dcbf7a533dd5bebe32ebed9cdddc8ad262782ca390accb1ce"
EXPECTED_DEV_ORDER = ("backdoor", "analysis")


def verify_and_rewrite(output_dir: Path):
    support_path = output_dir / "support_freeze.json"
    summary_path = output_dir / "summary.json"
    frozen_path = output_dir / "frozen_config.json"
    if not support_path.exists():
        raise RuntimeError("V65 support freeze missing")

    sf = json.loads(support_path.read_text())
    if sf.get("fresh_reserve_family") != EXPECTED_RESERVE:
        raise RuntimeError(f"Reserve changed after precommit: {sf.get('fresh_reserve_family')}")
    if int(sf.get("campaign_cutoff")) != EXPECTED_CUTOFF:
        raise RuntimeError(f"Campaign cutoff changed after precommit: {sf.get('campaign_cutoff')}")
    if sf.get("freeze_sha256") != EXPECTED_SUPPORT_FREEZE_SHA256:
        raise RuntimeError(
            f"Support freeze hash changed: {sf.get('freeze_sha256')} != {EXPECTED_SUPPORT_FREEZE_SHA256}"
        )

    if not summary_path.exists() or not frozen_path.exists():
        raise RuntimeError("V65 final evidence missing")
    d = json.loads(summary_path.read_text())
    f = json.loads(frozen_path.read_text())
    dev = tuple(f.get("development_families", ()))
    if dev != EXPECTED_DEV_ORDER:
        raise RuntimeError(f"Unexpected development families/order: {dev}")
    if f.get("fresh_reserve_family") != EXPECTED_RESERVE:
        raise RuntimeError("Frozen fusion reserve mismatch")
    if f.get("reserve_metrics_used_for_selection") is not False:
        raise RuntimeError("Leakage contract violated")

    f["protocol"] = "V65 precommitted Worms development-selected fusion"
    f["precommitted_reserve"] = {
        "family": EXPECTED_RESERVE,
        "campaign_cutoff": EXPECTED_CUTOFF,
        "support_freeze_sha256": EXPECTED_SUPPORT_FREEZE_SHA256,
        "worms_scores_seen_before_fusion_freeze": False,
    }
    f["development_family_feasibility_basis"] = (
        "Backdoor and Analysis were the first two V64 support-selected development folds "
        "to complete component preparation on all three seeds. Shellcode preparation failed "
        "before any Worms reserve metric was computed."
    )
    frozen_path.write_text(json.dumps(f, indent=2, allow_nan=False) + "\n")

    d["protocol"] = "V65 UNSW-NB15 precommitted fresh Worms unseen-family transition benchmark"
    d["history_contract"] = {
        "same_reserve_family_absent_from_observed_history": True,
        "other_attack_families_allowed_in_observed_history": True,
        "clean_history_required": False,
        "clean_history_support_in_unsw": 0,
    }
    d["precommit_contract"] = {
        "reserve_family": EXPECTED_RESERVE,
        "campaign_cutoff": EXPECTED_CUTOFF,
        "support_freeze_sha256": EXPECTED_SUPPORT_FREEZE_SHA256,
        "reserve_model_scores_inspected_before_this_run": False,
        "reserve_metrics_used_for_fusion_selection": False,
    }
    d["claim_boundary"] = (
        "Fresh Worms-family transition evaluation inside independent UNSW-NB15 cyber-range data. "
        "Worms identity/campaign were frozen from support/timestamps in V64 before any Worms score. "
        "The Worms family is absent from observed history and all fit/calibration/policy data; "
        "other known attack-family history may exist. Not clean-history lead-time proof and not a live Internet zero-day."
    )
    summary_path.write_text(json.dumps(d, indent=2, allow_nan=False) + "\n")


if __name__ == "__main__":
    # Keep both raw aliases contaminated for fresh-reserve eligibility.
    engine.CONTAMINATED.update({"backdoor", "backdoors"})
    engine.clean_family_positive = unseen_family_positive
    engine.campaign_split = cached_campaign_split
    engine.campaign_candidates = fast_campaign_candidates

    # V64 execution showed the first two development folds (Backdoor, Analysis)
    # successfully prepare all three seeds. Restricting to two avoids allowing a
    # third unsupported dev family to abort before the precommitted reserve test.
    engine.MAX_DEV_FAMILIES = 2
    engine.main()

    import sys
    if "--output" in sys.argv:
        verify_and_rewrite(Path(sys.argv[sys.argv.index("--output") + 1]))
