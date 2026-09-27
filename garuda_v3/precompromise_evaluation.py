"""Strict verified pre-compromise warning evaluation.

Only an externally evidenced successful event explicitly marked as establishing
compromise can create a compromise timestamp.  Flow-label or attack-step onset is
never substituted for compromise.
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any, Iterable

from .verified_campaigns import clean_history_eligible, load_manifest, validate_manifest, verified_compromise_epoch

STATUS_VERIFIED = "VERIFIED_PRECOMPROMISE"
STATUS_MISS = "NO_WARNING_BEFORE_VERIFIED_COMPROMISE"
STATUS_NO_COMPROMISE = "NO_VERIFIED_COMPROMISE_TIMESTAMP"


def evaluate_manifest(manifest: dict[str, Any], warning_epochs: Iterable[float], *, history_minutes: int = 8) -> dict[str, Any]:
    validate_manifest(manifest)
    compromise = verified_compromise_epoch(manifest)
    warnings = sorted({float(t) for t in warning_epochs})
    if compromise is None:
        return {
            "status": STATUS_NO_COMPROMISE,
            "verified_compromise_epoch": None,
            "first_warning_before_compromise_epoch": None,
            "lead_seconds": None,
            "clean_history_at_warning": None,
            "claimable_as_verified_precompromise": False,
            "reason": "No successful externally evidenced event establishes compromise in the campaign manifest.",
        }

    before = [t for t in warnings if t < compromise]
    if not before:
        return {
            "status": STATUS_MISS,
            "verified_compromise_epoch": float(compromise),
            "first_warning_before_compromise_epoch": None,
            "lead_seconds": None,
            "clean_history_at_warning": None,
            "claimable_as_verified_precompromise": False,
            "reason": "No model warning occurred before the verified compromise timestamp.",
        }

    first = min(before)
    lead = float(compromise - first)
    clean = clean_history_eligible(manifest, first, history_minutes=history_minutes)
    return {
        "status": STATUS_VERIFIED,
        "verified_compromise_epoch": float(compromise),
        "first_warning_before_compromise_epoch": float(first),
        "lead_seconds": lead,
        "clean_history_at_warning": bool(clean),
        "history_minutes_checked": int(history_minutes),
        "claimable_as_verified_precompromise": bool(lead > 0),
        "reason": "Lead time is computed only as verified_compromise_epoch - first_model_warning_epoch.",
        "claim_boundary": "This result does not convert attack-step onset, flow labels, or MITRE-stage timestamps into compromise timestamps.",
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--manifest", required=True)
    parser.add_argument("--warnings", required=True, help="JSON file containing a list of model warning epoch seconds")
    parser.add_argument("--history-minutes", type=int, default=8)
    parser.add_argument("--output")
    args = parser.parse_args()
    manifest = load_manifest(args.manifest)
    raw = json.loads(Path(args.warnings).read_text(encoding="utf-8"))
    if not isinstance(raw, list):
        raise SystemExit("--warnings must contain a JSON list")
    result = evaluate_manifest(manifest, raw, history_minutes=args.history_minutes)
    text = json.dumps(result, indent=2, allow_nan=False) + "\n"
    if args.output:
        Path(args.output).parent.mkdir(parents=True, exist_ok=True)
        Path(args.output).write_text(text, encoding="utf-8")
    print(text, end="")


if __name__ == "__main__":
    main()
