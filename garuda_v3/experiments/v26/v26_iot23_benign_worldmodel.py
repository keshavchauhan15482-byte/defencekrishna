from __future__ import annotations

"""V26 development: benign-only network-dynamics forecasting for unseen attacks.

The predictive model never learns an attack-family label or a malicious/benign
classification target. It learns second-order transitions only from sequences
whose full 8-minute history and full next 4-minute future are benign. At a
cutoff, Garuda scores how poorly recent traffic follows those learned benign
dynamics plus causal state novelty and recursive rollout drift.

Attack-family labels are used only after scoring to construct strict held-out
V23 development evaluations. Final-validation families remain untouched.
"""

import json
import sys
from pathlib import Path

import numpy as np
from sklearn.linear_model import Ridge

HERE = Path(__file__).resolve().parent
V23_DIR = HERE.parent / "v23"
if str(V23_DIR) not in sys.path:
    sys.path.insert(0, str(V23_DIR))
import v23_iot23_unseen_forecast as v23

v23.MAX_ROWS_PER_SCENARIO = 100_000

OUT = HERE / "artifacts" / "iot23_benign_worldmodel"
OUT.mkdir(parents=True, exist_ok=True)
SEEDS = [42, 43, 44]
DEV_FAMILIES = ["c&c-heartbeat", "c&c", "partofahorizontalportscan"]
ALPHA = 10.0
POLICY_BUDGET = 0.01
EPS = 1e-3
WEIGHTS = np.asarray([0.40, 0.25, 0.20, 0.15], dtype=np.float64)


def build_histories(states):
    histories = []
    target = []
    clean = []
    scenario = []
    cutoff = []
    block = []
    eligible = []
    hist_fams = []
    future_fams = []

    for sc, rows in states.items():
        t = np.asarray([x[0] for x in rows], np.int64)
        z = np.stack([x[1] for x in rows]).astype(np.float32)
        a = np.asarray([x[2] for x in rows], int)
        fam = [set(x[3]) for x in rows]
        start = int(t[0])
        for i in range(v23.HISTORY_WINDOWS - 1, len(rows) - v23.FUTURE_WINDOWS):
            lo = i - v23.HISTORY_WINDOWS + 1
            h = z[lo:i + 1]
            fut_a = a[i + 1:i + v23.FUTURE_WINDOWS + 1]
            hf = tuple(sorted(set().union(*fam[lo:i + 1]) if fam[lo:i + 1] else set()))
            ff = tuple(tuple(sorted(x)) for x in fam[i + 1:i + v23.FUTURE_WINDOWS + 1])
            local = int(t[i] - start)
            bi = local // v23.BLOCK_SECONDS
            pos = local % v23.BLOCK_SECONDS
            histories.append(h)
            target.append(int(fut_a.max()))
            clean.append(bool(a[lo:i + 1].max() == 0))
            scenario.append(sc)
            cutoff.append(int(t[i]))
            block.append(f"{sc}:{bi}")
            eligible.append(bool(
                pos >= (v23.HISTORY_WINDOWS - 1) * v23.WINDOW_SECONDS
                and pos <= v23.BLOCK_SECONDS - v23.FUTURE_WINDOWS * v23.WINDOW_SECONDS - v23.WINDOW_SECONDS
            ))
            hist_fams.append(hf)
            future_fams.append(ff)

    if not histories:
        raise RuntimeError("No V26 histories")
    return (
        np.stack(histories).astype(np.float32),
        np.asarray(target, int), np.asarray(clean, bool),
        np.asarray(scenario, object), np.asarray(cutoff, np.int64),
        np.asarray(block, object), np.asarray(eligible, bool),
        np.asarray(hist_fams, object), np.asarray(future_fams, object),
    )


def causal_coordinates(histories):
    h = histories.astype(np.float64)
    med = np.median(h, axis=1)
    q25 = np.quantile(h, 0.25, axis=1)
    q75 = np.quantile(h, 0.75, axis=1)
    scale = np.maximum(q75 - q25, EPS)
    r = np.clip((h - med[:, None, :]) / scale[:, None, :], -12.0, 12.0)
    return r.astype(np.float32)


def empirical_percentile(reference, values):
    ref = np.sort(np.asarray(reference, np.float64))
    if len(ref) < 50:
        raise RuntimeError(f"benign calibration reference too small: {len(ref)}")
    return np.searchsorted(ref, np.asarray(values, np.float64), side="right") / float(len(ref))


def raw_components(model, r):
    n, steps, f = r.shape
    errors = []
    for j in range(max(2, steps - 4), steps):
        x = np.concatenate([r[:, j - 2, :], r[:, j - 1, :]], axis=1)
        pred = model.predict(x)
        errors.append(np.sqrt(np.mean((pred - r[:, j, :]) ** 2, axis=1)))
    residual = np.mean(np.stack(errors, axis=1), axis=1)

    novelty = np.max(np.sqrt(np.mean(r[:, -4:, :] ** 2, axis=2)), axis=1)
    last2 = r[:, -2:, :].mean(axis=1)
    prev2 = r[:, -4:-2, :].mean(axis=1)
    trend = np.sqrt(np.mean((last2 - prev2) ** 2, axis=1))

    prev = r[:, -2, :].astype(np.float64)
    cur = r[:, -1, :].astype(np.float64)
    drifts = []
    for _ in range(v23.FUTURE_WINDOWS):
        x = np.concatenate([prev, cur], axis=1)
        nxt = np.clip(model.predict(x), -20.0, 20.0)
        drifts.append(np.sqrt(np.mean(nxt ** 2, axis=1)))
        prev, cur = cur, nxt
    rollout = np.max(np.stack(drifts, axis=1), axis=1)
    return np.stack([residual, novelty, trend, rollout], axis=1)


def fused_risk(raw, refs):
    cols = [empirical_percentile(refs[j], raw[:, j]) for j in range(raw.shape[1])]
    pct = np.stack(cols, axis=1)
    return pct @ WEIGHTS


def threshold_from_benign(scores):
    s = np.asarray(scores, float)
    if len(s) < 100:
        raise RuntimeError(f"policy benign support too small: {len(s)}")
    return float(np.quantile(s, 1.0 - POLICY_BUDGET, method="higher"))


def family_run(states, r, target, clean, scenario, cutoff, block, eligible, hist_fams, future_fams, family, seed):
    future = v23.fam_future(future_fams, family)
    hist = v23.fam_hist(hist_fams, family)
    exposed = future | hist
    held_blocks = set(str(x) for x in block[exposed])
    outside_held = np.asarray([str(b) not in held_blocks for b in block], bool)

    def benign_idx(which):
        m = v23.split_mask(block, eligible, which) & outside_held & ~exposed & clean & (target == 0)
        return np.where(m)[0]

    tr = benign_idx("train")
    ca = benign_idx("calibration")
    po = benign_idx("policy")
    te = benign_idx("test")
    if len(tr) < 500 or len(ca) < 100 or len(po) < 100 or len(te) < 100:
        raise RuntimeError(f"{family}: benign support train={len(tr)} cal={len(ca)} policy={len(po)} test={len(te)}")

    rng = np.random.default_rng(seed)
    take = min(30000, max(1000, int(len(tr) * 0.8)))
    fit_idx = rng.choice(tr, size=min(take, len(tr)), replace=False)

    xfit = np.concatenate([r[fit_idx, -3, :], r[fit_idx, -2, :]], axis=1)
    yfit = r[fit_idx, -1, :]
    model = Ridge(alpha=ALPHA, fit_intercept=True)
    model.fit(xfit, yfit)

    raw_all = raw_components(model, r)
    refs = [raw_all[ca, j] for j in range(raw_all.shape[1])]
    risk_all = fused_risk(raw_all, refs)
    threshold = threshold_from_benign(risk_all[po])

    neg = te
    pos = np.where(clean & future)[0]
    events = v23.build_events(states, family)
    if len(pos) < 1 or len(events) < 1:
        raise RuntimeError(f"{family}: positive support windows={len(pos)} events={len(events)}")

    event_rows = []
    for event in events:
        cand = np.where(
            (scenario == event["scenario"]) & clean & future &
            (cutoff < event["onset"]) &
            ((event["onset"] - cutoff) >= v23.WINDOW_SECONDS) &
            ((event["onset"] - cutoff) <= v23.FUTURE_WINDOWS * v23.WINDOW_SECONDS)
        )[0]
        hit = risk_all[cand] >= threshold if len(cand) else np.asarray([], bool)
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
        "model_training_attack_target": False,
        "model_training_benign_only": True,
        "heldout_blocks": int(len(held_blocks)),
        "heldout_exposure_in_train_cal_policy": 0,
        "support": {
            "train_benign": int(len(tr)), "calibration_benign": int(len(ca)),
            "policy_benign": int(len(po)), "reserved_test_benign": int(len(neg)),
            "clean_future_positive_windows": int(len(pos)), "clean_onset_events": int(len(events)),
        },
        "threshold": threshold,
        "test": {
            "fpr": float(np.mean(risk_all[neg] >= threshold)),
            "sequence_recall": float(np.mean(risk_all[pos] >= threshold)),
            "event_recall": float(np.mean([e["detected"] for e in event_rows])),
            "events": event_rows,
        },
    }


def main():
    states = v23.load_states()
    print(f"V26 loaded scenarios={len(states)} features={v23.feature_count()}", flush=True)
    H, target, clean, scenario, cutoff, block, eligible, hist_fams, future_fams = build_histories(states)
    print(f"V26 histories={len(H)}", flush=True)
    r = causal_coordinates(H)

    report = {
        "schema": "krishna-v26-iot23-benign-worldmodel-dev-v1",
        "purpose": "Development only; benign-trained dynamics, strict network-only; final validation remains locked.",
        "strict_network_only": True,
        "attack_label_as_model_target": False,
        "attack_family_as_model_input": False,
        "window_seconds": v23.WINDOW_SECONDS,
        "history_minutes": 8,
        "future_minutes": 4,
        "policy_fpr_budget": POLICY_BUDGET,
        "risk_weights": WEIGHTS.tolist(),
        "development_families": DEV_FAMILIES,
        "seeds": SEEDS,
        "results": {},
    }

    completed = []
    for family in DEV_FAMILIES:
        report["results"][family] = {}
        try:
            for seed in SEEDS:
                print(f"V26 family={family} seed={seed}", flush=True)
                result = family_run(states, r, target, clean, scenario, cutoff, block, eligible, hist_fams, future_fams, family, seed)
                report["results"][family][str(seed)] = result
                print(json.dumps(result, indent=2), flush=True)
            completed.append(family)
        except RuntimeError as exc:
            report["results"][family]["skipped"] = str(exc)
            print(f"SKIP {family}: {exc}", flush=True)

    if len(completed) < 3:
        raise RuntimeError(f"Only {len(completed)} V26 development families completed")

    per_family = {}
    for family in completed:
        tests = [report["results"][family][str(seed)]["test"] for seed in SEEDS]
        leads = []
        for test in tests:
            detected = [e["max_lead_seconds"] for e in test["events"] if e["max_lead_seconds"] is not None]
            leads.append(max(detected, default=0))
        per_family[family] = {
            "fpr": float(np.mean([x["fpr"] for x in tests])),
            "sequence_recall": float(np.mean([x["sequence_recall"] for x in tests])),
            "event_recall": float(np.mean([x["event_recall"] for x in tests])),
            "max_lead_seconds_mean": float(np.mean(leads)),
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
        "# V26 benign-only unseen future world model\n\n"
        "The model is trained only on benign network dynamics; attack labels are evaluation-only.\n\n"
        "```json\n" + json.dumps({"macro_mean": macro, "per_family_mean": per_family, "development_gate": gate}, indent=2) + "\n```\n",
        encoding="utf-8",
    )
    print(json.dumps({"macro_mean": macro, "per_family_mean": per_family, "development_gate": gate}, indent=2), flush=True)
    if not gate["pass"]:
        raise RuntimeError("V26 benign-only unseen forecasting development gate not met")


if __name__ == "__main__":
    main()
