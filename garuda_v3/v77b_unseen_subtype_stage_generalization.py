"""V77b honest unseen-subtype future-stage generalisation wrapper.

V76d established that X-IIoTID does not provide clean-onset support for all five fine
subtypes, especially Reconnaissance. V77b therefore evaluates a narrower but valid
question: can a Garuda model that never saw a held-out fine subtype during development
use the current observed history (which may already contain that subtype) to forecast the
future network state and map it to the correct lifecycle stage?

Development isolation remains strict: any sequence touching a selected subtype in its
history or future is removed from world-model and stage-mapper development, with a
source-local 12-step embargo. Only the test eligibility changes: the held-out subtype may
be present in observed history. This is NOT pre-onset warning or production zero-day
proof.
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

import numpy as np

from . import v77_unseen_subtype_stage_generalization as base


def reserve_masks_generalization(seq, frozen):
    selected = frozen["selected_reserve_subtype_by_stage"]
    reserve_pairs = {(stage, subtype) for stage, subtype in selected.items()}
    touch = np.asarray([
        bool(reserve_pairs.intersection(set(h) | set(f)))
        for h, f in zip(seq["history_pairs"], seq["future_pairs"])
    ], dtype=bool)

    blocked = touch.copy()
    by_src = {}
    for i, (src, t) in enumerate(zip(seq["src"], seq["cutoff"])):
        by_src.setdefault(str(src), []).append((i, int(t)))
    for _src, rows in by_src.items():
        touched_times = [t for i, t in rows if touch[i]]
        if not touched_times:
            continue
        blocked_times = set()
        for t in touched_times:
            for k in range(-base.EMBARGO_STEPS, base.EMBARGO_STEPS + 1):
                blocked_times.add(t + 60 * k)
        for i, t in rows:
            if t in blocked_times:
                blocked[i] = True

    tests = {}
    diagnostics = {}
    for stage_index, stage in enumerate(base.STAGES):
        subtype = selected[stage]
        pair = (stage, subtype)
        mask = np.asarray([
            seq["y_stage"][i] == stage_index and pair in seq["future_pairs"][i]
            for i in range(len(seq["X"]))
        ], dtype=bool)
        tests[stage] = mask
        ids = np.where(mask)[0]
        diagnostics[stage] = {
            "history_exposed": int(sum(pair in seq["history_pairs"][i] for i in ids)),
            "clean_onset": int(sum(pair not in seq["history_pairs"][i] for i in ids)),
            "other_reserved_future_cooccurrence": int(sum(
                bool((reserve_pairs - {pair}).intersection(seq["future_pairs"][i])) for i in ids
            )),
        }

    # Base V77 expects the fifth return value to be one integer diagnostic per stage.
    cooccurrence = {
        stage: diagnostics[stage]["other_reserved_future_cooccurrence"]
        for stage in base.STAGES
    }
    reserve_masks_generalization.last_diagnostics = diagnostics
    return reserve_pairs, touch, blocked, tests, cooccurrence


def _arg_value(flag: str):
    try:
        return sys.argv[sys.argv.index(flag) + 1]
    except (ValueError, IndexError):
        return None


def main():
    base.reserve_masks = reserve_masks_generalization
    base.main()

    out_arg = _arg_value("--output")
    if not out_arg:
        return
    summary_path = Path(out_arg) / "summary.json"
    report = json.loads(summary_path.read_text())
    diagnostics = getattr(reserve_masks_generalization, "last_diagnostics", {})
    report["protocol"] = "V77b five-stage leave-fine-subtype-out future-state mapping with history-exposed evaluation"
    report["claim_boundary"] = (
        "Selected X-IIoTID Class1 fine subtypes were frozen by support only and excluded from world-model and stage-mapper development, including a source-local overlap embargo. "
        "Test histories may already contain the held-out subtype; therefore this measures unseen-subtype future-state/stage generalisation after first observation, not clean-onset warning, pre-compromise lead time, undisclosed zero-day defence, or a globally chronological future benchmark. Exploitation remains an Initial Access proxy."
    )
    report["test_history_exposure_diagnostic"] = diagnostics
    report["leakage_contract"]["test_history_may_contain_held_out_subtype"] = True
    report["leakage_contract"]["clean_onset_test_claim"] = False
    report["leakage_contract"]["pre_compromise_claim"] = False
    report["leakage_contract"]["reserve_subtypes_seen_by_world_model_fit"] = False
    report["leakage_contract"]["reserve_subtypes_seen_by_world_validation"] = False
    report["leakage_contract"]["reserve_subtypes_seen_by_stage_mapper_fit"] = False
    for stage, diag in diagnostics.items():
        if stage in report.get("per_stage_summary", {}):
            report["per_stage_summary"][stage]["history_exposed_test_sequences"] = diag["history_exposed"]
            report["per_stage_summary"][stage]["clean_onset_test_sequences"] = diag["clean_onset"]
    summary_path.write_text(json.dumps(report, indent=2, allow_nan=False) + "\n")
    print(json.dumps({
        "history_exposure": diagnostics,
        "summary": report["summary"],
    }, indent=2), flush=True)


if __name__ == "__main__":
    main()
