from __future__ import annotations

"""V30 development correction over V29.

V29 exposed two distinct issues: (1) some labelled onsets have no eligible clean
8-minute history inside the capture, so counting them as model misses makes the
old event gate mathematically impossible; (2) global policy thresholds drift
across scenarios. V30 keeps V29 features/model fixed, reports unsupported events
as coverage gaps, scores event recall only on evaluable events, and derives
same-scenario thresholds from policy-benign traffic when support is sufficient.
No test result selects a model, fusion weight, budget, or threshold.
"""

import json
import sys
from pathlib import Path

import numpy as np
from sklearn.ensemble import HistGradientBoostingClassifier, IsolationForest
from sklearn.preprocessing import StandardScaler

HERE = Path(__file__).resolve().parent
V29_DIR = HERE.parent / "v29"
if str(V29_DIR) not in sys.path:
    sys.path.insert(0, str(V29_DIR))
import v29_iot23_topology_precursor as v29

v23 = v29.v23
OUT = HERE / "artifacts" / "iot23_evaluable_calibrated"
OUT.mkdir(parents=True, exist_ok=True)
SEEDS = [42, 43, 44]
DEV_FAMILIES = ["c&c-heartbeat", "c&c", "partofahorizontalportscan"]
MIN_SCENARIO_POLICY_BENIGN = 50


def threshold_from_scores(scores, budget, min_support=100):
    scores = np.asarray(scores, float)
    if len(scores) < int(min_support):
        raise RuntimeError(f"policy benign support too small: {len(scores)} < {min_support}")
    return float(np.quantile(scores, 1.0 - float(budget), method="higher"))


def threshold_plan(policy_idx, scenario, target, fused, budget):
    """Build thresholds with policy-local scores and global dataset metadata.

    `fused` is aligned 0..len(policy_idx)-1, so metadata is first projected to
    policy-local arrays. This prevents accidental use of global dataset indices
    against the compact policy score vector.
    """
    policy_idx = np.asarray(policy_idx, dtype=int)
    fused = np.asarray(fused, dtype=float)
    if len(fused) != len(policy_idx):
        raise RuntimeError(f"policy score alignment mismatch: scores={len(fused)} policy={len(policy_idx)}")

    y_local = np.asarray(target[policy_idx], dtype=int)
    scenario_local = np.asarray(scenario[policy_idx], dtype=object)
    benign_local = np.where(y_local == 0)[0]
    global_th = threshold_from_scores(fused[benign_local], budget, min_support=100)

    per_scenario = {}
    for sc in sorted(set(str(x) for x in scenario_local[benign_local])):
        idx_local = benign_local[scenario_local[benign_local] == sc]
        if len(idx_local) >= MIN_SCENARIO_POLICY_BENIGN:
            per_scenario[sc] = {
                "threshold": threshold_from_scores(
                    fused[idx_local], budget, min_support=MIN_SCENARIO_POLICY_BENIGN
                ),
                "policy_benign_n": int(len(idx_local)),
            }
    return {
        "budget": float(budget),
        "global_threshold": global_th,
        "global_policy_benign_n": int(len(benign_local)),
        "per_scenario": per_scenario,
    }


def thresholds_for(indices, scenario, plan):
    return np.asarray([
        plan["per_scenario"].get(str(scenario[i]), {}).get("threshold", plan["global_threshold"])
        for i in indices
    ], dtype=float)


def run_family(states, S, target, clean, scenario, cutoff, block, eligible, hist_fams, future_fams, family, seed):
    future = v23.fam_future(future_fams, family)
    hist = v23.fam_hist(hist_fams, family)
    exposed = future | hist
    held_blocks = set(str(x) for x in block[exposed])
    notheld = np.asarray([str(b) not in held_blocks for b in block], bool)

    def idx(name):
        return np.where(v23.split_mask(block, eligible, name) & clean & ~exposed & notheld)[0]

    tr, ca, po, te = (idx(x) for x in ("train", "calibration", "policy", "test"))
    for name, x, minpos in (("train", tr, 10), ("calibration", ca, 2), ("policy", po, 2)):
        counts = np.bincount(target[x], minlength=2)
        if len(x) < 100 or counts[0] < 100 or counts[1] < minpos:
            raise RuntimeError(f"{family} {name} support={counts.tolist()} n={len(x)}")

    rng = np.random.default_rng(seed)
    if len(tr) > 80000:
        tr = rng.choice(tr, 80000, replace=False)

    med = np.nanmedian(S[tr].astype(np.float64), axis=0)
    med[~np.isfinite(med)] = 0.0
    Z = S.astype(np.float32, copy=True)
    bad = ~np.isfinite(Z)
    if bad.any():
        Z[bad] = med[np.where(bad)[1]].astype(np.float32)
    scaler = StandardScaler().fit(Z[tr])
    ZA = scaler.transform(Z)

    sup = HistGradientBoostingClassifier(
        max_iter=350, learning_rate=.04, max_leaf_nodes=31,
        min_samples_leaf=15, l2_regularization=2.0,
        class_weight="balanced", random_state=seed,
    )
    sup.fit(ZA[tr], target[tr])
    cal = v29.calibrator(sup.predict_proba(ZA[ca])[:, 1], target[ca])
    ps_po = v29.apply_cal(cal, sup.predict_proba(ZA[po])[:, 1])

    benign_tr = tr[target[tr] == 0]
    if len(benign_tr) > 50000:
        benign_tr = rng.choice(benign_tr, 50000, replace=False)
    iso = IsolationForest(
        n_estimators=300, max_samples=min(8192, len(benign_tr)),
        contamination="auto", random_state=seed, n_jobs=1,
    ).fit(ZA[benign_tr])
    nov_ref = -iso.decision_function(ZA[ca][target[ca] == 0])
    pn_po = v29.empirical_percentile(nov_ref, -iso.decision_function(ZA[po]))

    # Fusion weight and budget are selected exclusively on the policy split.
    policy = v29.choose_policy(target[po], ps_po, pn_po)

    def components(indices):
        if not len(indices):
            return np.asarray([], float), np.asarray([], float)
        ps = v29.apply_cal(cal, sup.predict_proba(ZA[indices])[:, 1])
        pn = v29.empirical_percentile(nov_ref, -iso.decision_function(ZA[indices]))
        return ps, pn

    def fused(indices):
        ps, pn = components(indices)
        return (1.0 - policy["weight"]) * ps + policy["weight"] * pn

    fused_po = (1.0 - policy["weight"]) * ps_po + policy["weight"] * pn_po
    plan = threshold_plan(po, scenario, target, fused_po, policy["budget"])

    neg = te[target[te] == 0]
    pos = np.where(eligible & clean & future)[0]
    if len(neg) < 100 or len(pos) < 1:
        raise RuntimeError(f"{family} eval neg={len(neg)} pos={len(pos)}")

    pneg = fused(neg)
    ppos = fused(pos)
    neg_th = thresholds_for(neg, scenario, plan)
    pos_th = thresholds_for(pos, scenario, plan)

    event_rows = []
    for event in v23.build_events(states, family):
        cand = np.where(
            eligible & clean & future & (scenario == event["scenario"])
            & (cutoff < event["onset"])
            & ((event["onset"] - cutoff) >= v23.WINDOW_SECONDS)
            & ((event["onset"] - cutoff) <= v23.FUTURE_WINDOWS * v23.WINDOW_SECONDS)
        )[0]
        if len(cand):
            ss = fused(cand)
            th = thresholds_for(cand, scenario, plan)
            hit = ss >= th
            leads = (event["onset"] - cutoff[cand]).astype(int)
            detected_leads = leads[hit]
            detected = bool(hit.any())
            max_lead = int(detected_leads.max()) if len(detected_leads) else None
        else:
            detected = False
            max_lead = None
        event_rows.append({
            "scenario": event["scenario"],
            "onset": int(event["onset"]),
            "candidate_windows": int(len(cand)),
            "evaluable": bool(len(cand) > 0),
            "detected": detected,
            "max_lead_seconds": max_lead,
        })

    evaluable = [e for e in event_rows if e["evaluable"]]
    unsupported = [e for e in event_rows if not e["evaluable"]]
    if not evaluable:
        raise RuntimeError(f"{family}: no evaluable clean-onset event")

    return {
        "family": family,
        "seed": seed,
        "clean_history_training_only": True,
        "heldout_blocks": int(len(held_blocks)),
        "heldout_family_exposure_in_train_cal_policy": 0,
        "split_support": {"train": int(len(tr)), "calibration": int(len(ca)), "policy": int(len(po)), "test": int(len(te))},
        "policy_selection": policy,
        "threshold_plan": plan,
        "test": {
            "reserved_clean_benign_n": int(len(neg)),
            "heldout_clean_future_positive_windows": int(len(pos)),
            "fpr": float(np.mean(pneg >= neg_th)),
            "sequence_recall": float(np.mean(ppos >= pos_th)),
            "total_event_n": int(len(event_rows)),
            "evaluable_event_n": int(len(evaluable)),
            "unsupported_event_n": int(len(unsupported)),
            "evaluable_event_recall": float(np.mean([e["detected"] for e in evaluable])),
            "events": event_rows,
        },
    }


def main():
    states = v29.load_states()
    S, target, clean, scenario, cutoff, block, eligible, hist_fams, future_fams = v29.make_sequences(states)
    print(f"V30 histories={len(S)} clean={int(clean.sum())} clean_future_positive={int((clean & (target==1)).sum())}", flush=True)
    report = {
        "schema": "krishna-v30-iot23-evaluable-calibrated-dev-v1",
        "strict_network_only": True,
        "raw_identity_model_feature": False,
        "development_families": DEV_FAMILIES,
        "seeds": SEEDS,
        "results": {},
    }
    completed = []
    for family in DEV_FAMILIES:
        report["results"][family] = {}
        try:
            for seed in SEEDS:
                print(f"V30 family={family} seed={seed}", flush=True)
                r = run_family(states, S, target, clean, scenario, cutoff, block, eligible, hist_fams, future_fams, family, seed)
                report["results"][family][str(seed)] = r
                print(json.dumps(r, indent=2), flush=True)
            completed.append(family)
        except RuntimeError as exc:
            report["results"][family]["skipped"] = str(exc)
            print(f"V30 SKIP {family}: {exc}", flush=True)

    if len(completed) < 3:
        (OUT / "results.json").write_text(json.dumps(report, indent=2), encoding="utf-8")
        raise RuntimeError(f"Only {len(completed)} V30 families completed")

    per = {}
    for family in completed:
        vals = [report["results"][family][str(s)]["test"] for s in SEEDS]
        per[family] = {
            "fpr": float(np.mean([x["fpr"] for x in vals])),
            "sequence_recall": float(np.mean([x["sequence_recall"] for x in vals])),
            "evaluable_event_recall": float(np.mean([x["evaluable_event_recall"] for x in vals])),
            "unsupported_event_n": int(max(x["unsupported_event_n"] for x in vals)),
            "max_lead_seconds_mean": float(np.mean([
                max([e["max_lead_seconds"] or 0 for e in x["events"] if e["evaluable"]], default=0)
                for x in vals
            ])),
        }
    macro = {
        "fpr": float(np.mean([per[f]["fpr"] for f in completed])),
        "sequence_recall": float(np.mean([per[f]["sequence_recall"] for f in completed])),
        "evaluable_event_recall": float(np.mean([per[f]["evaluable_event_recall"] for f in completed])),
        "max_lead_seconds_mean": float(np.mean([per[f]["max_lead_seconds_mean"] for f in completed])),
    }
    gate = {
        "macro_fpr_pass": macro["fpr"] <= 0.02,
        "macro_evaluable_event_recall_pass": macro["evaluable_event_recall"] >= 0.80,
        "all_family_evaluable_event_recall_ge_0_70": all(per[f]["evaluable_event_recall"] >= 0.70 for f in completed),
        "positive_lead_time_pass": all(per[f]["max_lead_seconds_mean"] >= 30 for f in completed),
        "unsupported_events_reported": True,
    }
    gate["pass"] = bool(all(gate.values()))
    report["per_family_mean"] = per
    report["macro_mean"] = macro
    report["development_gate"] = gate
    (OUT / "results.json").write_text(json.dumps(report, indent=2), encoding="utf-8")
    (OUT / "REPORT.md").write_text(
        "# V30 evaluable-event + scenario-calibrated development gate\n\n"
        "Unsupported onsets with no eligible 8-minute clean-history candidate are reported as coverage gaps, not model misses.\n\n"
        "```json\n" + json.dumps({"macro_mean": macro, "per_family_mean": per, "development_gate": gate}, indent=2) + "\n```\n",
        encoding="utf-8",
    )
    print(json.dumps({"macro_mean": macro, "per_family_mean": per, "development_gate": gate}, indent=2), flush=True)
    if not gate["pass"]:
        raise RuntimeError("V30 evaluable-event scenario-calibrated development gate not met")


if __name__ == "__main__":
    main()
