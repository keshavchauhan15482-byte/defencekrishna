"""V63 fresh unseen-family transition benchmark on UNSW-NB15.

The V62 support audit established that UNSW-NB15 has zero future-family windows whose
entire 8-minute history is benign. Therefore a clean-history pre-compromise claim is
not identifiable from this corpus.

V63 evaluates a different, explicit question: can Garuda warn when a family appears
in the future even though that same family has never appeared in the observed history
or any fit/calibration/policy data? Histories may contain other known attack families.
This is an unseen-family transition test, not clean-history lead-time evidence.

Implementation reuses the leakage-safe rolling-campaign engine from V62 with only the
positive-history contract changed before any V63 metrics are computed. Both `backdoor`
and `backdoors` are excluded from fresh reserve eligibility because Backdoors metrics
were already inspected in V59 and the raw corpus contains spelling variants.
"""
from __future__ import annotations

import json
from pathlib import Path

from . import v62_unsw_rolling_campaign_holdout as engine


def unseen_family_positive(seq, family):
    """Future reserve-family presence with zero same-family history exposure."""
    return engine.future_presence(seq, family) & ~engine.history_presence(seq, family)


def _rewrite_metadata(output_dir: Path):
    summary_path = output_dir / "summary.json"
    support_path = output_dir / "support_freeze.json"
    if not summary_path.exists():
        return
    d = json.loads(summary_path.read_text())
    d["protocol"] = "V63 UNSW rolling-campaign unseen-family transition benchmark"
    d["history_contract"] = {
        "same_reserve_family_absent_from_observed_history": True,
        "other_attack_families_allowed_in_observed_history": True,
        "clean_history_required": False,
        "reason": "V62 support-only audit found zero clean-history future-family windows in UNSW-NB15",
    }
    d["claim_boundary"] = (
        "Fresh reserve family/campaign evaluation inside independent UNSW-NB15 cyber-range data. "
        "The reserve family is absent from fit/calibration/policy and from each evaluated observed history; "
        "other known attack families may exist in history. This is unseen-family transition evidence, "
        "not clean-history pre-compromise lead-time evidence and not a live Internet zero-day."
    )
    summary_path.write_text(json.dumps(d, indent=2, allow_nan=False) + "\n")

    if support_path.exists():
        s = json.loads(support_path.read_text())
        s["protocol"] = "V63 support-only unseen-family/campaign freeze"
        s["history_contract"] = "same-family absent; other attack-family history allowed"
        support_path.write_text(json.dumps(s, indent=2, allow_nan=False) + "\n")


if __name__ == "__main__":
    # Conservative alias handling: both raw labels are treated as already contaminated.
    engine.CONTAMINATED.update({"backdoor", "backdoors"})
    engine.clean_family_positive = unseen_family_positive
    engine.main()

    # argparse is owned by the engine; recover --output without changing its parser.
    import sys
    if "--output" in sys.argv:
        out = Path(sys.argv[sys.argv.index("--output") + 1])
        _rewrite_metadata(out)
