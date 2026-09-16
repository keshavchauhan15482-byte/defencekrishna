from __future__ import annotations

"""V32 development: 300k-row isolation baseline over V29.

Only the per-scenario raw-row cap changes. V29's strict network-only feature
representation, HGB + benign-IsolationForest branches, calibration, global
policy-only fusion/threshold selection, split hygiene and held-out-family block
exclusion are reused unchanged. Event reporting uses V30's corrected evaluable
clean-onset denominator so unsupported onsets remain explicit coverage gaps.
"""

import json
import sys
from pathlib import Path

import numpy as np

HERE = Path(__file__).resolve().parent
V29_DIR = HERE.parent / "v29"
if str(V29_DIR) not in sys.path:
    sys.path.insert(0, str(V29_DIR))
import v29_iot23_topology_precursor as v29

# The single intended experimental intervention.
v29.v23.MAX_ROWS_PER_SCENARIO = 300_000

OUT = HERE / "artifacts" / "iot23_expanded_support"
OUT.mkdir(parents=True, exist_ok=True)
SEEDS = [42, 43, 44]
DEV_FAMILIES = ["c&c-heartbeat", "c&c", "partofahorizontalportscan"]


def add_evaluable_event_accounting(result: dict) -> dict:
    test = result["test"]
    events = list(test.get("events", []))
    evaluable = [e for e in events if int(e.get("candidate_windows", 0)) > 0]
    unsupported = [e for e in events if int(e.get("candidate_windows", 0)) == 0]
    for e in events:
        e["evaluable"] = bool(int(e.get("candidate_windows", 0)) > 0)
    if not evaluable:
        raise RuntimeError(f"{result['family']}: no evaluable clean-onset event")
    test["total_event_n"] = int(len(events))
    test["evaluable_event_n"] = int(len(evaluable))
    test["unsupported_event_n"] = int(len(unsupported))
    test["evaluable_event_recall"] = float(np.mean([bool(e.get("detected")) for e in evaluable]))
    return result


def main():
    states = v29.load_states()
    print(
        f"V32 loaded scenarios={len(states)} row_cap={v29.v23.MAX_ROWS_PER_SCENARIO} "
        f"state_features={v29.base_feature_count()+v29.topology_feature_count()}",
        flush=True,
    )
    S, target, clean, scenario, cutoff, block, eligible, hist_fams, future_fams = v29.make_sequences(states)
    print(
        f"V32 histories={len(S)} clean={int(clean.sum())} "
        f"clean_future_positive={int((clean & (target == 1)).sum())}",
        flush=True,
    )

    report = {
        "schema": "krishna-v32-iot23-expanded-support-dev-v1",
        "row_cap": 300000,
        "strict_network_only": True,
        "raw_identity_model_feature": False,
        "model_and_global_policy_logic": "exact V29 reuse",
        "event_denominator": "evaluable clean-onset events only",
        "development_families": DEV_FAMILIES,
        "seeds": SEEDS,
        "summary_feature_count": int(S.shape[1]),
        "results": {},
    }

    completed = []
    for family in DEV_FAMILIES:
        report["results"][family] = {}
        try:
            for seed in SEEDS:
                print(f"V32 family={family} seed={seed}", flush=True)
                result = v29.run_family(
                    states, S, target, clean, scenario, cutoff, block, eligible,
                    hist_fams, future_fams, family, seed,
                )
                result = add_evaluable_event_accounting(result)
                report["results"][family][str(seed)] = result
                print(json.dumps(result, indent=2), flush=True)
            completed.append(family)
        except RuntimeError as exc:
            report["results"][family]["skipped"] = str(exc)
            print(f"V32 SKIP {family}: {exc}", flush=True)

    if len(completed) < 3:
        (OUT / "results.json").write_text(json.dumps(report, indent=2), encoding="utf-8")
        raise RuntimeError(f"Only {len(completed)} V32 families completed")

    per_family = {}
    for family in completed:
        tests = [report["results"][family][str(seed)]["test"] for seed in SEEDS]
        per_family[family] = {
            "fpr": float(np.mean([x["fpr"] for x in tests])),
            "sequence_recall": float(np.mean([x["sequence_recall"] for x in tests])),
            "evaluable_event_recall": float(np.mean([x["evaluable_event_recall"] for x in tests])),
            "unsupported_event_n": int(max(x["unsupported_event_n"] for x in tests)),
            "max_lead_seconds_mean": float(np.mean([
                max(
                    [int(e.get("max_lead_seconds") or 0) for e in x["events"] if e.get("evaluable")],
                    default=0,
                )
                for x in tests
            ])),
        }

    macro = {
        "fpr": float(np.mean([per_family[f]["fpr"] for f in completed])),
        "sequence_recall": float(np.mean([per_family[f]["sequence_recall"] for f in completed])),
        "evaluable_event_recall": float(np.mean([per_family[f]["evaluable_event_recall"] for f in completed])),
        "max_lead_seconds_mean": float(np.mean([per_family[f]["max_lead_seconds_mean"] for f in completed])),
    }
    gate = {
        "macro_fpr_pass": macro["fpr"] <= 0.02,
        "macro_evaluable_event_recall_pass": macro["evaluable_event_recall"] >= 0.80,
        "all_family_evaluable_event_recall_ge_0_70": all(
            per_family[f]["evaluable_event_recall"] >= 0.70 for f in completed
        ),
        "positive_lead_time_pass": all(
            per_family[f]["max_lead_seconds_mean"] >= 30 for f in completed
        ),
        "unsupported_events_reported": True,
    }
    gate["pass"] = bool(all(gate.values()))

    report["per_family_mean"] = per_family
    report["macro_mean"] = macro
    report["development_gate"] = gate
    report["isolation_note"] = (
        "Only the V29 per-scenario row cap changed to 300k; global policy logic stayed V29-identical."
    )
    (OUT / "results.json").write_text(json.dumps(report, indent=2), encoding="utf-8")
    (OUT / "REPORT.md").write_text(
        "# V32 300k-row expanded-support isolation baseline\n\n"
        "Exact V29 model/global-policy logic with only the row cap changed to 300k; "
        "V30 evaluable-event accounting is used.\n\n"
        "```json\n" + json.dumps(
            {"macro_mean": macro, "per_family_mean": per_family, "development_gate": gate},
            indent=2,
        ) + "\n```\n",
        encoding="utf-8",
    )
    print(json.dumps({"macro_mean": macro, "per_family_mean": per_family, "development_gate": gate}, indent=2), flush=True)
    if not gate["pass"]:
        raise RuntimeError("V32 expanded-support development gate not met")


if __name__ == "__main__":
    main()
