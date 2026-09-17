from __future__ import annotations

"""V27: clean-history held-out-family future forecasting development gate.

Key correction over prior supervised experiments: *every* train/calibration/policy
example has an entirely benign preceding 8-minute history. A positive label means
malicious network traffic begins within the next four minutes. Therefore the
supervised branches cannot solve the task by recognizing an attack already in the
history. The evaluated family and every block exposing that family remain absent
from train/calibration/policy.
"""

import json
import sys
from pathlib import Path

import numpy as np
from sklearn.ensemble import HistGradientBoostingClassifier, IsolationForest
from sklearn.linear_model import LogisticRegression
from sklearn.preprocessing import StandardScaler

HERE = Path(__file__).resolve().parent
V23_DIR = HERE.parent / "v23"
if str(V23_DIR) not in sys.path:
    sys.path.insert(0, str(V23_DIR))
import v23_iot23_unseen_forecast as v23
import v24_iot23_adaptive_forecast as v24

v23.MAX_ROWS_PER_SCENARIO = 100_000
OUT = HERE / "artifacts" / "iot23_clean_precursor"
OUT.mkdir(parents=True, exist_ok=True)
SEEDS = [42, 43, 44]
DEV_FAMILIES = ["c&c-heartbeat", "c&c", "partofahorizontalportscan"]
TREE_WEIGHTS = [0.0, 0.25, 0.5, 0.75, 1.0]
NOVELTY_WEIGHTS = [0.0, 0.25]
POLICY_BUDGETS = [0.005, 0.01, 0.02]


def calibrator(raw_p, y):
    if len(np.unique(y)) < 2:
        return None
    p = np.clip(np.asarray(raw_p, float), 1e-6, 1 - 1e-6)
    x = np.log(p / (1 - p)).reshape(-1, 1)
    return LogisticRegression(C=1e3, max_iter=500).fit(x, y)


def apply_cal(model, p):
    p = np.asarray(p, float)
    if model is None:
        return p
    q = np.clip(p, 1e-6, 1 - 1e-6)
    return model.predict_proba(np.log(q / (1 - q)).reshape(-1, 1))[:, 1]


def percentile(reference, values):
    ref = np.sort(np.asarray(reference, float))
    if len(ref) < 50:
        raise RuntimeError(f"novelty benign calibration reference too small: {len(ref)}")
    return np.searchsorted(ref, np.asarray(values, float), side="right") / float(len(ref))


def benign_threshold(scores, budget):
    s = np.asarray(scores, float)
    if len(s) < 100:
        raise RuntimeError(f"policy benign support too small: {len(s)}")
    return float(np.quantile(s, 1.0 - budget, method="higher"))


def choose_policy(y, ptree, plinear, pnov):
    benign_mask = y == 0
    positive_mask = y == 1
    if benign_mask.sum() < 100 or positive_mask.sum() < 3:
        raise RuntimeError(
            f"clean policy support insufficient: benign={int(benign_mask.sum())} positive={int(positive_mask.sum())}"
        )
    best = None
    for tw in TREE_WEIGHTS:
        for nw in NOVELTY_WEIGHTS:
            lw = 1.0 - tw - nw
            if lw < -1e-9:
                continue
            lw = max(0.0, lw)
            fused = tw * ptree + lw * plinear + nw * pnov
            for budget in POLICY_BUDGETS:
                th = benign_threshold(fused[benign_mask], budget)
                pred = fused >= th
                fpr = float(pred[benign_mask].mean())
                recall = float(pred[positive_mask].mean())
                # Fixed ordering decided before held-out evaluation.
                key = (recall, -fpr, -nw, tw, -budget)
                cand = {
                    "tree_weight": float(tw),
                    "linear_weight": float(lw),
                    "novelty_weight": float(nw),
                    "budget": float(budget),
                    "threshold": float(th),
                    "policy_fpr": fpr,
                    "policy_clean_future_recall": recall,
                }
                if fpr <= 0.0205 and (best is None or key > best[0]):
                    best = (key, cand)
    if best is None:
        raise RuntimeError("no clean-policy fusion satisfies FPR <= 2.05%")
    return best[1]


def run_family(states, S, target, clean, scenario, cutoff, block, eligible, hist_fams, future_fams, family, seed):
    future = v23.fam_future(future_fams, family)
    hist = v23.fam_hist(hist_fams, family)
    exposed = future | hist
    held_blocks = set(str(x) for x in block[exposed])
    outside_held = np.asarray([str(x) not in held_blocks for x in block], bool)

    def clean_split(name):
        m = v23.split_mask(block, eligible, name) & outside_held & ~exposed & clean
        return np.where(m)[0]

    tr, ca, po, te = (clean_split(x) for x in ("train", "calibration", "policy", "test"))
    support = {}
    for name, idx in (("train", tr), ("calibration", ca), ("policy", po)):
        counts = np.bincount(target[idx], minlength=2)
        support[name] = {"benign_future": int(counts[0]), "future_attack": int(counts[1]), "n": int(len(idx))}
        if len(idx) < 100 or counts[0] < 100 or counts[1] < 3:
            raise RuntimeError(f"{family}: {name} clean support {counts.tolist()} n={len(idx)}")

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

    tree = HistGradientBoostingClassifier(
        max_iter=350,
        learning_rate=0.04,
        max_leaf_nodes=31,
        min_samples_leaf=12,
        l2_regularization=2.0,
        class_weight="balanced",
        random_state=seed,
    )
    tree.fit(ZA[tr], target[tr])
    tree_cal = calibrator(tree.predict_proba(ZA[ca])[:, 1], target[ca])

    linear = LogisticRegression(
        C=0.25,
        class_weight="balanced",
        max_iter=1000,
        random_state=seed,
    )
    linear.fit(ZA[tr], target[tr])
    linear_cal = calibrator(linear.predict_proba(ZA[ca])[:, 1], target[ca])

    benign_train = tr[target[tr] == 0]
    if len(benign_train) > 50000:
        benign_train = rng.choice(benign_train, 50000, replace=False)
    iso = IsolationForest(
        n_estimators=300,
        max_samples=min(8192, len(benign_train)),
        contamination="auto",
        random_state=seed,
        n_jobs=1,
    ).fit(ZA[benign_train])
    nov_cal_raw = -iso.decision_function(ZA[ca])
    nov_ref = nov_cal_raw[target[ca] == 0]

    def branch_scores(idx):
        if len(idx) == 0:
            return (np.asarray([], float),) * 3
        pt = apply_cal(tree_cal, tree.predict_proba(ZA[idx])[:, 1])
        pl = apply_cal(linear_cal, linear.predict_proba(ZA[idx])[:, 1])
        pn = percentile(nov_ref, -iso.decision_function(ZA[idx]))
        return pt, pl, pn

    pt_po, pl_po, pn_po = branch_scores(po)
    policy = choose_policy(target[po], pt_po, pl_po, pn_po)

    def fused(idx):
        pt, pl, pn = branch_scores(idx)
        return (
            policy["tree_weight"] * pt
            + policy["linear_weight"] * pl
            + policy["novelty_weight"] * pn
        )

    neg = te[target[te] == 0]
    pos = np.where(clean & future)[0]
    events = v23.build_events(states, family)
    if len(neg) < 100 or len(pos) < 1 or len(events) < 1:
        raise RuntimeError(f"{family}: evaluation support neg={len(neg)} pos={len(pos)} events={len(events)}")

    th = policy["threshold"]
    pneg = fused(neg)
    ppos = fused(pos)
    event_rows = []
    for event in events:
        cand = np.where(
            (scenario == event["scenario"])
            & clean
            & future
            & (cutoff < event["onset"])
            & ((event["onset"] - cutoff) >= v23.WINDOW_SECONDS)
            & ((event["onset"] - cutoff) <= v23.FUTURE_WINDOWS * v23.WINDOW_SECONDS)
        )[0]
        scores = fused(cand)
        hit = scores >= th
        leads = (event["onset"] - cutoff[cand]).astype(int) if len(cand) else np.asarray([], int)
        detected_leads = leads[hit] if len(leads) else np.asarray([], int)
        event_rows.append({
            "scenario": event["scenario"],
            "onset": int(event["onset"]),
            "candidate_windows": int(len(cand)),
            "detected": bool(hit.any()) if len(hit) else False,
            "max_lead_seconds": int(detected_leads.max()) if len(detected_leads) else None,
            "horizon_detected": {
                "60": bool(np.any(hit & (leads <= 60))) if len(leads) else False,
                "120": bool(np.any(hit & (leads <= 120))) if len(leads) else False,
                "240": bool(np.any(hit & (leads <= 240))) if len(leads) else False,
            },
        })

    return {
        "family": family,
        "seed": seed,
        "clean_history_training_only": True,
        "heldout_blocks": int(len(held_blocks)),
        "heldout_family_exposure_in_train_cal_policy": 0,
        "clean_support": support,
        "policy_selection": policy,
        "test": {
            "reserved_clean_benign_n": int(len(neg)),
            "heldout_clean_future_positive_windows": int(len(pos)),
            "fpr": float(np.mean(pneg >= th)),
            "sequence_recall": float(np.mean(ppos >= th)),
            "event_n": int(len(event_rows)),
            "event_recall": float(np.mean([e["detected"] for e in event_rows])),
            "events": event_rows,
        },
    }


def main():
    states = v23.load_states()
    print(f"V27 loaded scenarios={len(states)} state_features={v23.feature_count()}", flush=True)
    S, target, clean, scenario, cutoff, block, eligible, hist_fams, future_fams = v24.adaptive_sequences(states)
    print(
        f"V27 histories={len(S)} clean={int(clean.sum())} clean_future_attack={int((clean & (target == 1)).sum())}",
        flush=True,
    )

    report = {
        "schema": "krishna-v27-iot23-clean-precursor-dev-v1",
        "purpose": "Development only; clean-history precursor learning for held-out attack behaviours; final validation remains locked.",
        "strict_network_only": True,
        "attack_in_history_training_allowed": False,
        "heldout_family_as_model_input": False,
        "window_seconds": v23.WINDOW_SECONDS,
        "history_minutes": 8,
        "future_minutes": 4,
        "development_families": DEV_FAMILIES,
        "seeds": SEEDS,
        "results": {},
    }

    completed = []
    for family in DEV_FAMILIES:
        report["results"][family] = {}
        try:
            for seed in SEEDS:
                print(f"V27 family={family} seed={seed}", flush=True)
                result = run_family(
                    states, S, target, clean, scenario, cutoff, block, eligible,
                    hist_fams, future_fams, family, seed,
                )
                report["results"][family][str(seed)] = result
                print(json.dumps(result, indent=2), flush=True)
            completed.append(family)
        except RuntimeError as exc:
            report["results"][family]["skipped"] = str(exc)
            print(f"SKIP {family}: {exc}", flush=True)

    if len(completed) < 3:
        report["development_gate"] = {"pass": False, "reason": f"only {len(completed)} families completed"}
        (OUT / "results.json").write_text(json.dumps(report, indent=2), encoding="utf-8")
        raise RuntimeError(report["development_gate"]["reason"])

    per_family = {}
    for family in completed:
        tests = [report["results"][family][str(seed)]["test"] for seed in SEEDS]
        max_leads = []
        for test in tests:
            detected = [e["max_lead_seconds"] for e in test["events"] if e["max_lead_seconds"] is not None]
            max_leads.append(max(detected, default=0))
        per_family[family] = {
            "fpr": float(np.mean([x["fpr"] for x in tests])),
            "sequence_recall": float(np.mean([x["sequence_recall"] for x in tests])),
            "event_recall": float(np.mean([x["event_recall"] for x in tests])),
            "max_lead_seconds_mean": float(np.mean(max_leads)),
        }

    macro = {
        key: float(np.mean([per_family[f][key] for f in completed]))
        for key in ["fpr", "sequence_recall", "event_recall", "max_lead_seconds_mean"]
    }
    gate = {
        "macro_fpr_pass": macro["fpr"] <= 0.02,
        "macro_event_recall_pass": macro["event_recall"] >= 0.80,
        "all_family_event_recall_ge_0_70": all(per_family[f]["event_recall"] >= 0.70 for f in completed),
        "positive_lead_time_pass": all(per_family[f]["max_lead_seconds_mean"] >= 30 for f in completed),
    }
    gate["pass"] = bool(all(gate.values()))
    report["per_family_mean"] = per_family
    report["macro_mean"] = macro
    report["development_gate"] = gate
    (OUT / "results.json").write_text(json.dumps(report, indent=2), encoding="utf-8")
    (OUT / "REPORT.md").write_text(
        "# V27 clean-history unseen precursor forecast\n\n"
        "All model-fitting splits contain only attack-free 8-minute histories.\n\n"
        "```json\n" + json.dumps({"macro_mean": macro, "per_family_mean": per_family, "development_gate": gate}, indent=2) + "\n```\n",
        encoding="utf-8",
    )
    print(json.dumps({"macro_mean": macro, "per_family_mean": per_family, "development_gate": gate}, indent=2), flush=True)
    if not gate["pass"]:
        raise RuntimeError("V27 clean-history unseen precursor development gate not met")


if __name__ == "__main__":
    main()
