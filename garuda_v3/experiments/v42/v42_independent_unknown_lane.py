from __future__ import annotations

"""V42: independent unknown lane for unseen-family early progression.

V41 showed that its policy optimizer always chose OOD fusion weight 0.0. V42
removes that failure mode. The supervised future-progression lane and a benign-
only unknown/anomaly lane receive independent benign FPR budgets and are ORed.
No held-out-family examples or test outcomes select thresholds or budgets.
"""

import json
import sys
import tempfile
import zipfile
from collections import defaultdict
from pathlib import Path

import numpy as np
from sklearn.ensemble import HistGradientBoostingClassifier, IsolationForest
from sklearn.linear_model import LogisticRegression

HERE = Path(__file__).resolve().parent
V41_DIR = HERE.parent / "v41"
if str(V41_DIR) not in sys.path:
    sys.path.insert(0, str(V41_DIR))
import v41_unsw_unseen_progression as v41

OUT = HERE / "artifacts" / "independent_unknown_lane"
OUT.mkdir(parents=True, exist_ok=True)

BUDGET_PAIRS = [(0.003, 0.007), (0.0025, 0.005), (0.001, 0.003)]
SEEDS = [42, 43, 44]


def robust_profiles(samples, X, y, splits):
    """Per-device benign TRAIN baseline; deployable environment normalization."""
    profiles = {}
    devices = sorted({s["device"] for s in samples})
    for dev in devices:
        idx = np.asarray([
            i for i, s in enumerate(samples)
            if s["device"] == dev and splits[i] == "train" and y[i] == 0
        ], dtype=int)
        if len(idx) < 100:
            raise RuntimeError(f"{dev}: insufficient benign TRAIN profile n={len(idx)}")
        med = np.median(X[idx], axis=0)
        q25 = np.quantile(X[idx], 0.25, axis=0)
        q75 = np.quantile(X[idx], 0.75, axis=0)
        scale = np.maximum(q75 - q25, 0.02)
        profiles[dev] = (med.astype(np.float32), scale.astype(np.float32))
    return profiles


def apply_profiles(samples, X, profiles):
    Z = np.empty_like(X, dtype=np.float32)
    for i, s in enumerate(samples):
        med, scale = profiles[s["device"]]
        Z[i] = np.clip((X[i] - med) / scale, -25.0, 25.0)
    return Z


def calibrator(raw, y):
    y = np.asarray(y, int)
    if len(np.unique(y)) < 2:
        raise RuntimeError("calibration split lacks both classes")
    p = np.clip(np.asarray(raw, float), 1e-6, 1 - 1e-6)
    z = np.log(p / (1 - p)).reshape(-1, 1)
    return LogisticRegression(C=1e3, max_iter=500).fit(z, y)


def apply_cal(model, p):
    q = np.clip(np.asarray(p, float), 1e-6, 1 - 1e-6)
    return model.predict_proba(np.log(q / (1 - q)).reshape(-1, 1))[:, 1]


def empirical_percentile(ref, values):
    r = np.sort(np.asarray(ref, float))
    return np.searchsorted(r, np.asarray(values, float), side="right") / float(max(1, len(r)))


def shock_score(Z):
    """Generic abrupt-change score; no attack labels and no family semantics."""
    A = np.abs(np.asarray(Z, float))
    # Robustly combine the strongest few changed channels rather than one spike.
    k = min(4, A.shape[1])
    top = np.partition(A, A.shape[1] - k, axis=1)[:, -k:]
    return np.mean(top, axis=1)


def qthreshold(scores, budget):
    scores = np.asarray(scores, float)
    if len(scores) < 100:
        raise RuntimeError(f"benign policy support too small: {len(scores)}")
    return float(np.quantile(scores, 1.0 - budget, method="higher"))


def support(y, idx):
    c = np.bincount(np.asarray(y, int)[idx], minlength=2)
    return {"n": int(len(idx)), "benign": int(c[0]), "positive": int(c[1])}


def fit_family(samples, event_lookup, family, seed):
    X = np.stack([s["x"] for s in samples]).astype(np.float32)
    y = np.asarray([s["y"] for s in samples], int)
    splits = np.asarray([s["split"] for s in samples], object)
    exposure = np.asarray([family in s["families"] for s in samples], bool)

    def idx(name):
        return np.where((splits == name) & (~exposure))[0]

    tr, ca, po, te = [idx(n) for n in ("train", "calibration", "policy", "test")]
    for name, ii, minpos in (("train", tr, 20), ("calibration", ca, 5), ("policy", po, 5)):
        s = support(y, ii)
        if s["benign"] < 100 or s["positive"] < minpos:
            raise RuntimeError(f"{family} {name} support insufficient: {s}")

    profiles = robust_profiles(samples, X, y, splits)
    Z = apply_profiles(samples, X, profiles)

    # Known/progression lane: held-out family has zero exposure here.
    clf = HistGradientBoostingClassifier(
        max_iter=300, learning_rate=0.04, max_leaf_nodes=31,
        min_samples_leaf=10, l2_regularization=2.0,
        class_weight="balanced", random_state=seed,
    ).fit(Z[tr], y[tr])
    cal = calibrator(clf.predict_proba(Z[ca])[:, 1], y[ca])
    ps_po = apply_cal(cal, clf.predict_proba(Z[po])[:, 1])

    # Unknown lane: fit only benign train histories.
    benign_tr = tr[y[tr] == 0]
    rng = np.random.default_rng(seed)
    if len(benign_tr) > 60000:
        benign_tr = rng.choice(benign_tr, 60000, replace=False)
    iso = IsolationForest(
        n_estimators=300, max_samples=min(8192, len(benign_tr)),
        contamination="auto", random_state=seed, n_jobs=1,
    ).fit(Z[benign_tr])

    benign_ca = ca[y[ca] == 0]
    if_ref = -iso.decision_function(Z[benign_ca])
    shock_ref = shock_score(Z[benign_ca])

    def lane_scores(ii):
        if len(ii) == 0:
            return np.asarray([], float), np.asarray([], float)
        sup = apply_cal(cal, clf.predict_proba(Z[ii])[:, 1])
        p_if = empirical_percentile(if_ref, -iso.decision_function(Z[ii]))
        p_shock = empirical_percentile(shock_ref, shock_score(Z[ii]))
        # A single benign-calibrated unknown score. Both constituents are label-free.
        unknown = np.maximum(p_if, p_shock)
        return sup, unknown

    sup_po, unk_po = lane_scores(po)
    benign_po = y[po] == 0
    selected = None
    for sup_budget, unk_budget in BUDGET_PAIRS:
        th_sup = qthreshold(sup_po[benign_po], sup_budget)
        th_unk = qthreshold(unk_po[benign_po], unk_budget)
        alert = (sup_po >= th_sup) | (unk_po >= th_unk)
        fpr = float(np.mean(alert[benign_po]))
        if fpr <= 0.0105:
            selected = {
                "supervised_budget": float(sup_budget), "unknown_budget": float(unk_budget),
                "supervised_threshold": th_sup, "unknown_threshold": th_unk,
                "policy_or_fpr": fpr,
                "policy_positive_recall_diagnostic": float(np.mean(alert[y[po] == 1])) if np.any(y[po] == 1) else None,
            }
            break
    if selected is None:
        raise RuntimeError(f"{family}: no predeclared budget pair controls policy OR FPR")

    benign_test = te[y[te] == 0]
    if len(benign_test) < 500:
        raise RuntimeError(f"{family}: test benign support {len(benign_test)}")
    st, ut = lane_scores(benign_test)
    a_sup = st >= selected["supervised_threshold"]
    a_unk = ut >= selected["unknown_threshold"]
    a_or = a_sup | a_unk

    candidate_by_event = defaultdict(list)
    for i, s in enumerate(samples):
        if family not in s["families"]:
            continue
        for eid in s["early_event_ids"]:
            e = event_lookup.get(eid)
            if e and e["family"] == family:
                candidate_by_event[eid].append(i)

    rows, delays = [], []
    lane_hits = {"supervised": 0, "unknown": 0, "or": 0}
    for eid, e in event_lookup.items():
        if e["family"] != family:
            continue
        ii = np.asarray(candidate_by_event.get(eid, []), dtype=int)
        if len(ii) == 0:
            rows.append({"event_id": eid, "device": e["device"], "label": e["label"],
                         "candidate_windows": 0, "evaluable": False, "detected": False,
                         "supervised_detected": False, "unknown_detected": False,
                         "detection_delay_seconds": None})
            continue
        ss, uu = lane_scores(ii)
        hs = ss >= selected["supervised_threshold"]
        hu = uu >= selected["unknown_threshold"]
        ho = hs | hu
        sup_det, unk_det, det = bool(hs.any()), bool(hu.any()), bool(ho.any())
        lane_hits["supervised"] += int(sup_det)
        lane_hits["unknown"] += int(unk_det)
        lane_hits["or"] += int(det)
        if det:
            hit_idx = np.where(ho)[0]
            ds = [max(0.0, samples[ii[j]]["cutoff_ts"] - e["start"]) for j in hit_idx]
            delay = float(min(ds)); delays.append(delay)
        else:
            delay = None
        rows.append({"event_id": eid, "device": e["device"], "label": e["label"],
                     "candidate_windows": int(len(ii)), "evaluable": True, "detected": det,
                     "supervised_detected": sup_det, "unknown_detected": unk_det,
                     "detection_delay_seconds": delay})

    evaluable = [r for r in rows if r["evaluable"]]
    return {
        "family": family, "seed": seed,
        "heldout_family_exposure_in_train_cal_policy": 0,
        "split_support": {"train": support(y, tr), "calibration": support(y, ca),
                          "policy": support(y, po), "test": support(y, te)},
        "decision_policy": selected,
        "test": {
            "reserved_benign_n": int(len(benign_test)),
            "supervised_fpr": float(np.mean(a_sup)),
            "unknown_fpr": float(np.mean(a_unk)),
            "or_fpr": float(np.mean(a_or)),
            "event_n": int(len(rows)),
            "evaluable_event_n": int(len(evaluable)),
            "unsupported_event_n": int(len(rows) - len(evaluable)),
            "supervised_event_recall": float(lane_hits["supervised"] / max(1, len(evaluable))),
            "unknown_event_recall": float(lane_hits["unknown"] / max(1, len(evaluable))),
            "or_event_recall": float(lane_hits["or"] / max(1, len(evaluable))),
            "median_detection_delay_seconds": float(np.median(delays)) if delays else None,
            "events": rows,
        },
    }


def main():
    with tempfile.TemporaryDirectory(prefix="krishna-v42-") as tmp:
        td = Path(tmp); fp = td / "flowdata.zip"; ap = td / "annotations.zip"
        fm = v41.v35.download(v41.v35.FLOW_URL, fp); am = v41.v35.download(v41.v35.ANN_URL, ap)
        if fm["sha256"] != v41.v35.EXPECTED_FLOW_SHA or am["sha256"] != v41.v35.EXPECTED_ANN_SHA:
            raise RuntimeError("UNSW source hash mismatch")
        with zipfile.ZipFile(fp) as zf:
            flows, schema = v41.v35.load_flows(zf)
        with zipfile.ZipFile(ap) as za:
            events = v41.v35.load_events(za)

    samples, event_lookup = v41.build_samples(flows, events)
    print(f"V42 samples={len(samples)} positives={sum(s['y'] for s in samples)} features={len(samples[0]['x'])}", flush=True)
    report = {
        "schema": "krishna-v42-independent-unknown-lane-v1",
        "source_provenance": {"flow": fm, "annotations": am},
        "strict_network_only": True,
        "development_holdout_families": v41.DEV_HOLDOUT,
        "locked_final_validation_families": sorted(v41.LOCKED_FINAL),
        "results": {},
    }
    completed = []
    for family in v41.DEV_HOLDOUT:
        report["results"][family] = {}
        try:
            for seed in SEEDS:
                print(f"V42 family={family} seed={seed}", flush=True)
                r = fit_family(samples, event_lookup, family, seed)
                report["results"][family][str(seed)] = r
                t = r["test"]
                print(json.dumps({"family": family, "seed": seed,
                    "policy": r["decision_policy"],
                    "test": {k:v for k,v in t.items() if k != "events"}}, indent=2), flush=True)
            completed.append(family)
        except RuntimeError as exc:
            report["results"][family]["skipped"] = str(exc)
            print(f"V42 SKIP {family}: {exc}", flush=True)

    if len(completed) != len(v41.DEV_HOLDOUT):
        (OUT / "results.json").write_text(json.dumps(report, indent=2), encoding="utf-8")
        raise RuntimeError(f"V42 only {len(completed)}/{len(v41.DEV_HOLDOUT)} families completed")

    per = {}
    for family in completed:
        vals = [report["results"][family][str(seed)]["test"] for seed in SEEDS]
        delays = [x["median_detection_delay_seconds"] for x in vals if x["median_detection_delay_seconds"] is not None]
        per[family] = {
            "fpr": float(np.mean([x["or_fpr"] for x in vals])),
            "supervised_event_recall": float(np.mean([x["supervised_event_recall"] for x in vals])),
            "unknown_event_recall": float(np.mean([x["unknown_event_recall"] for x in vals])),
            "event_recall": float(np.mean([x["or_event_recall"] for x in vals])),
            "evaluable_event_n": int(min(x["evaluable_event_n"] for x in vals)),
            "median_detection_delay_seconds": float(np.mean(delays)) if delays else None,
        }
    macro_fpr = float(np.mean([x["fpr"] for x in per.values()]))
    macro_rec = float(np.mean([x["event_recall"] for x in per.values()]))
    d = [x["median_detection_delay_seconds"] for x in per.values() if x["median_detection_delay_seconds"] is not None]
    macro_delay = float(np.mean(d)) if d else None
    gate = {
        "macro_fpr_pass": macro_fpr <= 0.01,
        "macro_unseen_event_recall_pass": macro_rec >= 0.80,
        "all_family_event_recall_pass": all(x["event_recall"] >= 0.70 for x in per.values()),
        "event_support_pass": all(x["evaluable_event_n"] >= 5 for x in per.values()),
        "detection_delay_pass": macro_delay is not None and macro_delay <= 120.0,
    }
    gate["pass"] = bool(all(gate.values()))
    report["per_family_mean"] = per
    report["macro_mean"] = {"fpr": macro_fpr, "unseen_event_recall": macro_rec,
                            "median_detection_delay_seconds": macro_delay}
    report["development_gate"] = gate
    (OUT / "results.json").write_text(json.dumps(report, indent=2), encoding="utf-8")
    (OUT / "REPORT.md").write_text(
        "# V42 independent unknown lane\n\n```json\n" +
        json.dumps({"macro_mean": report["macro_mean"], "per_family_mean": per,
                    "development_gate": gate}, indent=2) + "\n```\n", encoding="utf-8")
    print(json.dumps({"macro_mean": report["macro_mean"], "per_family_mean": per,
                      "development_gate": gate}, indent=2), flush=True)
    if not gate["pass"]:
        raise RuntimeError("V42 independent unknown-lane development gate not met")


if __name__ == "__main__":
    main()
