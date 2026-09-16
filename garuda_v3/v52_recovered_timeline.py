"""Compatibility audit for the recovered CICAPT Attack_info.csv schema.

The recovered third-party Git-pinned copy uses the publisher-style headings
``Time of Attack``, ``Tactic Name`` and ``Technique Name``.  V52's original
resolver intentionally accepted a conservative alias set but did not include
these exact headings.  This module extends schema resolution without rewriting
or normalizing the source CSV, so the V52 audit continues to hash and report the
original 4,310-byte evidence file.

This does not upgrade the source to publisher-verified evidence and does not
change V52's compromise/containment claim boundaries.
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path

from garuda_v3 import v52_cicapt_timeline as v52


def resolve_recovered_schema(df):
    """Resolve V52 schema plus the exact recovered CICAPT publisher headings."""
    time_col = v52.pick_col(df.columns, [
        "time of attack", "attack_time", "attack time", "timestamp",
        "event_time", "event time", "start_time", "start time",
        "execution_time", "execution time", "time",
    ])
    tactic_col = v52.pick_col(df.columns, [
        "tactic name", "category", "tactic", "attack_category",
        "attack category", "stage", "phase",
    ])
    technique_col = v52.pick_col(df.columns, [
        "technique name", "technique", "technique_id", "technique id",
        "ability", "ability_name", "ability name",
    ])
    pid_col = v52.pick_col(df.columns, ["pid", "process_id", "process id"])
    status_col = v52.pick_col(df.columns, ["status", "result", "success", "outcome"])
    compromise_col = v52.pick_col(df.columns, [
        "compromise_time", "compromise time", "breach_time", "breach time",
        "successful_compromise_time", "successful compromise time",
    ])
    if time_col is None:
        raise ValueError(f"No attack event timestamp column found in {list(df.columns)}")
    if tactic_col is None and technique_col is None:
        raise ValueError("Attack_info.csv lacks both tactic/category and technique identity")
    return {
        "time": time_col,
        "tactic": tactic_col,
        "technique": technique_col,
        "pid": pid_col,
        "status": status_col,
        "compromise_time": compromise_col,
    }


def audit_recovered(attack_info, output, candidate_timeline=None, tolerance_seconds=180):
    """Run the existing V52 audit against the untouched recovered source bytes."""
    original = v52.resolve_attack_info_schema
    try:
        v52.resolve_attack_info_schema = resolve_recovered_schema
        report = v52.audit_attack_info(
            attack_info,
            output,
            candidate_timeline=candidate_timeline,
            tolerance_seconds=tolerance_seconds,
        )
    finally:
        v52.resolve_attack_info_schema = original

    report["source_tier"] = "third_party_git_pinned_copy"
    report["publisher_verified"] = False
    report["compatibility_adapter"] = "garuda_v3.v52_recovered_timeline.resolve_recovered_schema"
    report["claim_boundary"] = (
        "Development-grade attack-step timeline evidence from a commit-pinned third-party copy; "
        "not publisher-verified and not successful-compromise lead-time evidence."
    )
    target = Path(output) / "timeline_audit.json"
    target.write_text(json.dumps(report, indent=2, allow_nan=False) + "\n")
    return report


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--attack-info", required=True)
    p.add_argument("--output", required=True)
    p.add_argument("--candidate-timeline")
    p.add_argument("--tolerance-seconds", type=int, default=180)
    args = p.parse_args()
    result = audit_recovered(
        args.attack_info,
        args.output,
        candidate_timeline=args.candidate_timeline,
        tolerance_seconds=args.tolerance_seconds,
    )
    print(json.dumps(result, indent=2, allow_nan=False))


if __name__ == "__main__":
    main()
