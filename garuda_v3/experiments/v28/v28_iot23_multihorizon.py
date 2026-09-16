from __future__ import annotations

"""V28 development: multi-horizon clean-history unseen-family forecasting.

This experiment is deliberately prediction-first. Every model input contains an
attack-free 8-minute history. Four hazard heads estimate whether malicious
network traffic will begin within 30, 60, 120 or 240 seconds. The evaluated
family and every block exposing it are absent from train/calibration/policy.
Thresholds are derived only from policy-benign traffic, with a same-scenario
policy threshold when enough benign support exists and a global fallback.
"""

import json
import sys
from pathlib import Path

import numpy as np
from sklearn.ensemble import HistGradientBoostingClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.preprocessing import StandardScaler

HERE = Path(__file__).resolve().parent
V23_DIR = HERE.parent / "v23"
if str(V23_DIR) not in sys.path:
    sys.path.insert(0, str(V23_DIR))
import v23_iot23_unseen_forecast as v23
import v24_iot23_adaptive_forecast as v24

v23.MAX_ROWS_PER_SCENARIO = 100_000
OUT = HERE / "artifacts" / "iot23_multihorizon"
OUT.mkdir(parents=True, exist_ok=True)

SEEDS = [42, 43, 44]
DEV_FAMILIES = ["c&c-heartbeat", "c&c", "partofahorizontalportscan"]
HORIZONS = {30: 1, 60: 2, 120: 4, 240: 8}
POLICY_FPR_BUDGET = 0.01
MIN_TRAIN_POS = 10
MIN_CAL_POS = 2
MIN_SCENARIO_POLICY_BENIGN = 50


def any_attack_targets(future_fams):
    out = {}
    for seconds, windows in HORIZONS.items():
        out[seconds] = np.asarray([
            int(any(len(step) > 0 for step in seq[:windows]))
            for seq in future_fams
        ], dtype=int)
    return out


def calibrator(raw_p, y):
    y = np.asarray(y, int)
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


def quantile_threshold(scores, min_support=100):
    scores = np.asarray(scores, float)
    if len(scores) < min_support:
        raise RuntimeError(f"policy benign support too small: {len(scores)} < {min_support}")
    return float(np.quantile(scores, 1.0 - POLICY_FPR_BUDGET, method="higher"))


def threshold_plan(policy_idx, scenario, y240, fused):
    benign = policy_idx[y240[policy_idx] == 0]
    global_th = quantile_threshold(fused[benign], 100)
    per_scenario = {}
    for sc in sorted(set(str(x) for x in scenario[benign])):
        idx = benign[scenario[benign] == sc]
        if len(idx) >= MIN_SCENARIO_POLICY_BENIGN:
            per_scenario[sc] = {
                "threshold": quantile_threshold(fused[idx], MIN_SCENARIO_POLICY_BENIGN),
                "policy_benign_n": int(len(idx)),
            }
    return {
        "global_threshold": global_th,
        "per_scenario": per_scenario,
        "policy_benign_n": int(len(benign)),
    }


def thresholds_for(indices, scenario, plan):
    return np.asarray([
        plan["per_scenario"].get(str(scenario[i]), {}).get("threshold", plan["global_threshold"])
        for i in indices
    ], dtype=float)


def fit_heads(Z, horizon_targets, tr, ca, seed):
    heads = {}
    probs = []
    for seconds in sorted(HORIZONS):
        y = horizon_targets[seconds]
        tr_counts = np.bincount(y[tr], minlength=2)
        ca_counts = np.bincount(y[ca], minlength=2)
        if tr_counts[1] < MIN_TRAIN_POS or ca_counts[1] < MIN_CAL_POS or tr_counts[0] < 100 or ca_counts[0] < 50:
            heads[str(seconds)] = {
                "enabled": False,
                "train_support": tr_counts.tolist(),
                "calibration_support": ca_counts.tolist(),
            }
            continue
        model = HistGradientBoostingClassifier(
            max_iter=350,
            learning_rate=0.04,
            max_leaf_nodes=31,
            min_samples_leaf=12,
            l2_regularization=2.0,
            class_weight="balanced",
            random_state=seed + seconds,
        )
        model.fit(Z[tr], y[tr])
        cal = calibrator(model.predict_proba(Z[ca])[:, 1], y[ca])
        p_all = apply_cal(cal, model.predict_proba(Z)[:, 1])
        probs.append(p_all)
        heads[str(seconds)] = {
            "enabled": True,
            "train_support": tr_counts.tolist(),
            "calibration_support": ca_counts.tolist(),
        }
    if not probs:
        raise RuntimeError("no V28 horizon head has sufficient support")
    return heads, np.max(np.stack(probs, axis=1), axis=1)


def heldout_within_horizon(future_fams, family, windows):
    return np.asarray([
        any(family in set(step) for step in seq[:windows])
        for seq in future_fams
    ], dtype=bool)


def run_family(states, S, target240, clean, scenario, cutoff, block, eligible, hist_fams, future_fams, family, seed):
    held_future = v23.fam_future(future_fams, family)
    held_hist = v23.fam_hist(hist_fams, family)
    exposed = held_future | held_hist
    held_blocks = set(str(x) for x in block[exposed])
    outside_held = np.asarray([str(x) not in held_blocks for x in block], bool)

    def clean_split(name):
        m = v23.split_mask(block, eligible, name) & outside_held & ~exposed & clean
        return np.where(m)[0]

    tr, ca, po, te = (clean_split(x) for x in ("train", "calibration", "policy", "test"))
    if min(len(tr), len(ca), len(po), len(te)) < 100:
        raise RuntimeError(f"{family}: split support train={len(tr)} cal={len(ca)} policy={len(po)} test={len(te)}")

    rng = np.random.default_rng(seed)
    if len(tr) > 80000:
        tr = rng.choice(tr, 80000, replace=False)

    med = np.nanmedian(S[tr].astype(np.float64), axis=0)
    med[~np.isfinite(med)] = 0.0
    X = S.astype(np.float32, copy=True)
    bad = ~np.isfinite(X)
    if bad.any():
        X[bad] = med[np.where(bad)[1]].astype(np.float32)
    scaler = StandardScaler().fit(X[tr])
    Z = scaler.transform(X)

    horizon_targets = any_attack_targets(future_fams)
    heads, fused = fit_heads(Z, horizon_targets, tr, ca, seed)
    plan = threshold_plan(po, scenario, horizon_targets[240], fused)

    neg = te[horizon_targets[240][te] == 0]
    pos = np.where(eligible & clean & held_future)[0]
    events = v23.build_events(states, family)
    if len(neg) < 100 or len(pos) < 1 or len(events) < 1:
        raise RuntimeError(f"{family}: eval support neg={len(neg)} pos={len(pos)} events={len(events)}")

    neg_th = thresholds_for(neg, scenario, plan)
    pos_th = thresholds_for(pos, scenario, plan)
    neg_hit = fused[neg] >= neg_th
    pos_hit = fused[pos] >= pos_th

    per_horizon = {}
    for seconds, windows in HORIZONS.items():
        hp = np.where(eligible & clean & heldout_within_horizon(future_fams, family, windows))[0]
        if len(hp):
            hth = thresholds_for(hp, scenario, plan)
            per_horizon[str(seconds)] = {
                "positive_windows": int(len(hp)),
                "recall": float(np.mean(fused[hp] >= hth)),
            }
        else:
            per_horizon[str(seconds)] = {"positive_windows": 0, "recall": None}

    event_rows = []
    for event in events:
        cand = np.where(
            eligible
            & (scenario == event["scenario"])
            & clean
            & held_future
            & (cutoff < event["onset"])
            & ((event["onset"] - cutoff) >= v23.WINDOW_SECONDS)
            & ((event["onset"] - cutoff) <= v23.FUTURE_WINDOWS * v23.WINDOW_SECONDS)
        )[0]
        if len(cand):
            cth = thresholds_for(cand, scenario, plan)
            hit = fused[cand] >= cth
            leads = (event["onset"] - cutoff[cand]).astype(int)
            det = leads[hit]
        else:
            hit = np.asarray([], bool)
            leads = np.asarray([], int)
            det = np.asarray([], int)
        event_rows.append({
            "scenario": event["scenario"],
            "onset": int(event["onset"]),
            "candidate_windows": int(len(cand)),
            "detected": bool(hit.any()) if len(hit) else False,
            "max_lead_seconds": int(det.max()) if len(det) else None,
            "horizon_detected": {
                str(seconds): bool(np.any(hit & (leads <= seconds))) if len(leads) else False
                for seconds in HORIZONS
            },
        })

    return {
        "family": family,
        "seed": seed,
        "clean_history_training_only": True,
        "heldout_blocks": int(len(held_blocks)),
        "heldout_family_exposure_in_train_cal_policy": 0,
        "split_support": {"train": int(len(tr)), "calibration": int(len(ca)), "policy": int(len(po)), "test": int(len(te))},
        "heads": heads,
        "threshold_plan": plan,
        "test": {
            "reserved_clean_benign_n": int(len(neg)),
            "heldout_clean_future_positive_windows": int(len(pos)),
            "fpr": float(neg_hit.mean()),
            "sequence_recall": float(pos_hit.mean()),
            "per_horizon": per_horizon,
            "event_n": int(len(event_rows)),
            "event_recall": float(np.mean([e["detected"] for e in event_rows])),
            "events": event_rows,
        },
    }


def main():
    states = v23.load_states()
    print(f"V28 loaded scenarios={len(states)} state_features={v23.feature_count()}", flush=True)
    S, target240, clean, scenario, cutoff, block, eligible, hist_fams, future_fams = v24.adaptive_sequences(states)
    targets = any_attack_targets(future_fams)
    print(
        "V28 histories={} clean={} clean positives 30/60/120/240={}".format(
            len(S), int(clean.sum()),
            {k: int((clean & (v == 1)).sum()) for k, v in targets.items()},
        ),
        flush=True,
    )

    report = {
        "schema": "krishna-v28-iot23-multihorizon-dev-v1",
        "purpose": "Development only; multi-horizon future hazard from clean network histories; final validation remains locked.",
        "strict_network_only": True,
        "attack_in_history_training_allowed": False,
        "heldout_family_as_model_input": False,
        "forecast_horizons_seconds": sorted(HORIZONS),
        "policy_fpr_budget": POLICY_FPR_BUDGET,
        "scenario_policy_benign_min": MIN_SCENARIO_POLICY_BENIGN,
        "development_families": DEV_FAMILIES,
        "seeds": SEEDS,
        "results": {},
    }

    completed = []
    for family in DEV_FAMILIES:
        report["results"][family] = {}
        try:
            for seed in SEEDS:
                print(f"V28 family={family} seed={seed}", flush=True)
                result = run_family(
                    states, S, target240, clean, scenario, cutoff, block, eligible,
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
        "# V28 multi-horizon clean-history unseen forecast\n\n"
        "Four future hazard heads (30/60/120/240s), clean-history-only training, policy-only scenario thresholds.\n\n"
        "```json\n" + json.dumps({"macro_mean": macro, "per_family_mean": per_family, "development_gate": gate}, indent=2) + "\n```\n",
        encoding="utf-8",
    )
    print(json.dumps({"macro_mean": macro, "per_family_mean": per_family, "development_gate": gate}, indent=2), flush=True)
    if not gate["pass"]:
        raise RuntimeError("V28 multi-horizon clean-history development gate not met")


if __name__ == "__main__":
    main()
