from __future__ import annotations

"""V43: continuous, tie-safe independent unknown lane.

V42 never reached held-out event evaluation because empirical-percentile anomaly
scores clipped many policy-benign examples to exactly 1.0. Quantile thresholds
combined with >= then could not honor the predeclared OR-FPR budgets. V43 keeps
V42's data, features, models and holdouts fixed, changing only anomaly-score
calibration and threshold comparison as frozen before this run.
"""

import json
import sys
import tempfile
import zipfile
from collections import defaultdict
from pathlib import Path

import numpy as np
from sklearn.ensemble import HistGradientBoostingClassifier, IsolationForest

HERE = Path(__file__).resolve().parent
V42_DIR = HERE.parent / "v42"
if str(V42_DIR) not in sys.path:
    sys.path.insert(0, str(V42_DIR))
import v42_independent_unknown_lane as v42

v41 = v42.v41
v35 = v41.v35

OUT = HERE / "artifacts" / "continuous_unknown_lane"
OUT.mkdir(parents=True, exist_ok=True)

BUDGET_PAIRS = [(0.003, 0.007), (0.0025, 0.005), (0.001, 0.003)]
SEEDS = [42, 43, 44]
ROBUST_EPS = 1e-6


def robust_calibration(ref: np.ndarray, values: np.ndarray) -> np.ndarray:
    """Continuous benign-reference calibration with no percentile clipping."""
    ref = np.asarray(ref, dtype=float)
    values = np.asarray(values, dtype=float)
    if len(ref) < 100:
        raise RuntimeError(f"benign calibration reference too small: {len(ref)}")
    med = float(np.median(ref))
    q25, q75 = np.quantile(ref, [0.25, 0.75])
    scale = max(float(q75 - q25), ROBUST_EPS)
    return (values - med) / scale


def qthreshold(scores: np.ndarray, budget: float) -> float:
    scores = np.asarray(scores, dtype=float)
    if len(scores) < 100:
        raise RuntimeError(f"benign policy support too small: {len(scores)}")
    return float(np.quantile(scores, 1.0 - budget, method="higher"))


def fit_family(samples, event_lookup, family: str, seed: int) -> dict:
    X = np.stack([s["x"] for s in samples]).astype(np.float32)
    y = np.asarray([s["y"] for s in samples], dtype=int)
    splits = np.asarray([s["split"] for s in samples], dtype=object)
    exposure = np.asarray([family in s["families"] for s in samples], dtype=bool)

    def idx(name: str) -> np.ndarray:
        return np.where((splits == name) & (~exposure))[0]

    tr, ca, po, te = [idx(name) for name in ("train", "calibration", "policy", "test")]
    for name, ii, min_pos in (("train", tr, 20), ("calibration", ca, 5), ("policy", po, 5)):
        s = v42.support(y, ii)
        if s["benign"] < 100 or s["positive"] < min_pos:
            raise RuntimeError(f"{family} {name} support insufficient: {s}")

    # Exact V42 environment normalization: benign TRAIN statistics only.
    profiles = v42.robust_profiles(samples, X, y, splits)
    Z = v42.apply_profiles(samples, X, profiles)

    # Exact V42 known/progression lane.
    clf = HistGradientBoostingClassifier(
        max_iter=300,
        learning_rate=0.04,
        max_leaf_nodes=31,
        min_samples_leaf=10,
        l2_regularization=2.0,
        class_weight="balanced",
        random_state=seed,
    ).fit(Z[tr], y[tr])
    cal = v42.calibrator(clf.predict_proba(Z[ca])[:, 1], y[ca])

    # Exact V42 unknown models: fit only benign training histories.
    benign_tr = tr[y[tr] == 0]
    rng = np.random.default_rng(seed)
    if len(benign_tr) > 60000:
        benign_tr = rng.choice(benign_tr, 60000, replace=False)
    iso = IsolationForest(
        n_estimators=300,
        max_samples=min(8192, len(benign_tr)),
        contamination="auto",
        random_state=seed,
        n_jobs=1,
    ).fit(Z[benign_tr])

    benign_ca = ca[y[ca] == 0]
    if_raw_ref = -iso.decision_function(Z[benign_ca])
    shock_raw_ref = v42.shock_score(Z[benign_ca])

    def lane_scores(ii: np.ndarray):
        ii = np.asarray(ii, dtype=int)
        if len(ii) == 0:
            return np.asarray([], float), np.asarray([], float)
        supervised = v42.apply_cal(cal, clf.predict_proba(Z[ii])[:, 1])
        if_z = robust_calibration(if_raw_ref, -iso.decision_function(Z[ii]))
        shock_z = robust_calibration(shock_raw_ref, v42.shock_score(Z[ii]))
        unknown = np.maximum(if_z, shock_z)
        return supervised, unknown

    # Policy selection is benign-only. Attack-positive policy outcomes are never
    # inspected to pick the budget pair or threshold.
    sup_po, unk_po = lane_scores(po)
    benign_po = y[po] == 0
    selected = None
    diagnostics = []
    for sup_budget, unk_budget in BUDGET_PAIRS:
        th_sup = qthreshold(sup_po[benign_po], sup_budget)
        th_unk = qthreshold(unk_po[benign_po], unk_budget)
        # Frozen V43 tie-safe semantics: equality is not an alert.
        a_sup = sup_po > th_sup
        a_unk = unk_po > th_unk
        a_or = a_sup | a_unk
        fpr = float(np.mean(a_or[benign_po]))
        diag = {
            "supervised_budget": float(sup_budget),
            "unknown_budget": float(unk_budget),
            "supervised_threshold": th_sup,
            "unknown_threshold": th_unk,
            "policy_or_fpr": fpr,
        }
        diagnostics.append(diag)
        if fpr <= 0.0105:
            selected = {
                **diag,
                "selection_used_attack_positives": False,
                "comparison": "strict_greater_than",
            }
            break
    if selected is None:
        raise RuntimeError(
            f"{family}: no predeclared V43 budget pair controls policy OR FPR; "
            f"diagnostics={diagnostics}"
        )

    def alerts(ii: np.ndarray):
        sup, unk = lane_scores(ii)
        a_sup = sup > selected["supervised_threshold"]
        a_unk = unk > selected["unknown_threshold"]
        return a_sup | a_unk, a_sup, a_unk, sup, unk

    benign_test = te[y[te] == 0]
    if len(benign_test) < 500:
        raise RuntimeError(f"{family}: reserved benign test support too small: {len(benign_test)}")
    a_or, a_sup, a_unk, _, _ = alerts(benign_test)

    # Held-out family is absent from train/calibration/policy but scored at its
    # early observable attack windows for development event recall.
    candidate_by_event = defaultdict(list)
    for i, s in enumerate(samples):
        if family not in s["families"]:
            continue
        for eid in s["early_event_ids"]:
            e = event_lookup.get(eid)
            if e and e["family"] == family:
                candidate_by_event[eid].append(i)

    event_rows = []
    delays = []
    sup_hits = unk_hits = or_hits = 0
    for eid, e in event_lookup.items():
        if e["family"] != family:
            continue
        ii = np.asarray(candidate_by_event.get(eid, []), dtype=int)
        if len(ii) == 0:
            event_rows.append({
                "event_id": eid,
                "device": e["device"],
                "label": e["label"],
                "candidate_windows": 0,
                "evaluable": False,
                "detected": False,
                "supervised_detected": False,
                "unknown_detected": False,
                "detection_delay_seconds": None,
            })
            continue

        ho, hs, hu, _, _ = alerts(ii)
        sup_det = bool(np.any(hs))
        unk_det = bool(np.any(hu))
        det = bool(np.any(ho))
        sup_hits += int(sup_det)
        unk_hits += int(unk_det)
        or_hits += int(det)
        if det:
            hit = np.where(ho)[0]
            ds = [max(0.0, samples[ii[j]]["cutoff_ts"] - e["start"]) for j in hit]
            delay = float(min(ds))
            delays.append(delay)
        else:
            delay = None
        event_rows.append({
            "event_id": eid,
            "device": e["device"],
            "label": e["label"],
            "candidate_windows": int(len(ii)),
            "evaluable": True,
            "detected": det,
            "supervised_detected": sup_det,
            "unknown_detected": unk_det,
            "detection_delay_seconds": delay,
        })

    evaluable = [r for r in event_rows if r["evaluable"]]
    if not evaluable:
        raise RuntimeError(f"{family}: no evaluable held-out-family events")

    return {
        "family": family,
        "seed": seed,
        "heldout_family_exposure_in_train_cal_policy": 0,
        "split_support": {
            "train": v42.support(y, tr),
            "calibration": v42.support(y, ca),
            "policy": v42.support(y, po),
            "test": v42.support(y, te),
        },
        "decision_policy": selected,
        "policy_budget_diagnostics": diagnostics,
        "test": {
            "reserved_benign_n": int(len(benign_test)),
            "supervised_fpr": float(np.mean(a_sup)),
            "unknown_fpr": float(np.mean(a_unk)),
            "or_fpr": float(np.mean(a_or)),
            "event_n": int(len(event_rows)),
            "evaluable_event_n": int(len(evaluable)),
            "unsupported_event_n": int(len(event_rows) - len(evaluable)),
            "supervised_event_recall": float(sup_hits / len(evaluable)),
            "unknown_event_recall": float(unk_hits / len(evaluable)),
            "or_event_recall": float(or_hits / len(evaluable)),
            "median_detection_delay_seconds": float(np.median(delays)) if delays else None,
            "mean_detection_delay_seconds": float(np.mean(delays)) if delays else None,
            "events": event_rows,
        },
    }


def main():
    with tempfile.TemporaryDirectory(prefix="krishna-v43-") as tmp:
        td = Path(tmp)
        fp, ap = td / "flowdata.zip", td / "annotations.zip"
        fm = v35.download(v35.FLOW_URL, fp)
        am = v35.download(v35.ANN_URL, ap)
        if fm["sha256"] != v35.EXPECTED_FLOW_SHA or am["sha256"] != v35.EXPECTED_ANN_SHA:
            raise RuntimeError("UNSW source hash mismatch")
        with zipfile.ZipFile(fp) as zf:
            flows, _ = v35.load_flows(zf)
        with zipfile.ZipFile(ap) as za:
            events = v35.load_events(za)

    samples, event_lookup = v41.build_samples(flows, events)
    print(
        f"V43 samples={len(samples)} positives={sum(s['y'] for s in samples)} "
        f"features={len(samples[0]['x'])}",
        flush=True,
    )

    report = {
        "schema": "krishna-v43-continuous-unknown-lane-v1",
        "source_provenance": {"flow": fm, "annotations": am},
        "strict_network_only": True,
        "development_holdout_families": list(v41.DEV_HOLDOUT),
        "locked_final_validation_families": sorted(v41.LOCKED_FINAL),
        "anomaly_calibration": "continuous benign-calibration median/IQR; no percentile clipping",
        "threshold_comparison": "strict_greater_than",
        "results": {},
    }

    completed = []
    for family in v41.DEV_HOLDOUT:
        report["results"][family] = {}
        try:
            for seed in SEEDS:
                print(f"V43 family={family} seed={seed}", flush=True)
                result = fit_family(samples, event_lookup, family, seed)
                report["results"][family][str(seed)] = result
                print(json.dumps({
                    "family": family,
                    "seed": seed,
                    "policy": result["decision_policy"],
                    "test": {k: v for k, v in result["test"].items() if k != "events"},
                }, indent=2), flush=True)
            completed.append(family)
        except RuntimeError as exc:
            report["results"][family]["skipped"] = str(exc)
            print(f"V43 SKIP {family}: {exc}", flush=True)

    if len(completed) != len(v41.DEV_HOLDOUT):
        (OUT / "results.json").write_text(json.dumps(report, indent=2), encoding="utf-8")
        raise RuntimeError(f"V43 only {len(completed)}/{len(v41.DEV_HOLDOUT)} families completed")

    per_family = {}
    for family in completed:
        tests = [report["results"][family][str(seed)]["test"] for seed in SEEDS]
        delays = [t["median_detection_delay_seconds"] for t in tests if t["median_detection_delay_seconds"] is not None]
        per_family[family] = {
            "fpr": float(np.mean([t["or_fpr"] for t in tests])),
            "supervised_event_recall": float(np.mean([t["supervised_event_recall"] for t in tests])),
            "unknown_event_recall": float(np.mean([t["unknown_event_recall"] for t in tests])),
            "event_recall": float(np.mean([t["or_event_recall"] for t in tests])),
            "evaluable_event_n": int(min(t["evaluable_event_n"] for t in tests)),
            "median_detection_delay_seconds": float(np.mean(delays)) if delays else None,
        }

    macro_fpr = float(np.mean([v["fpr"] for v in per_family.values()]))
    macro_recall = float(np.mean([v["event_recall"] for v in per_family.values()]))
    valid_delays = [v["median_detection_delay_seconds"] for v in per_family.values() if v["median_detection_delay_seconds"] is not None]
    macro_delay = float(np.mean(valid_delays)) if valid_delays else None
    gate = {
        "macro_fpr_pass": macro_fpr <= 0.01,
        "macro_unseen_event_recall_pass": macro_recall >= 0.80,
        "all_family_event_recall_pass": all(v["event_recall"] >= 0.70 for v in per_family.values()),
        "event_support_pass": all(v["evaluable_event_n"] >= 5 for v in per_family.values()),
        "detection_delay_pass": macro_delay is not None and macro_delay <= 120.0,
    }
    gate["pass"] = bool(all(gate.values()))

    report["per_family_mean"] = per_family
    report["macro_mean"] = {
        "fpr": macro_fpr,
        "unseen_event_recall": macro_recall,
        "median_detection_delay_seconds": macro_delay,
    }
    report["development_gate"] = gate
    report["claim_boundary"] = (
        "Early-observed unseen-family progression forecasting only; not pre-first-packet or universal zero-day prediction."
    )

    (OUT / "results.json").write_text(json.dumps(report, indent=2), encoding="utf-8")
    (OUT / "REPORT.md").write_text(
        "# V43 continuous unknown-lane unseen progression\n\n```json\n"
        + json.dumps({
            "macro_mean": report["macro_mean"],
            "per_family_mean": per_family,
            "development_gate": gate,
        }, indent=2)
        + "\n```\n",
        encoding="utf-8",
    )
    print(json.dumps({
        "macro_mean": report["macro_mean"],
        "per_family_mean": per_family,
        "development_gate": gate,
    }, indent=2), flush=True)
    if not gate["pass"]:
        raise RuntimeError("V43 continuous unknown-lane development gate not met")


if __name__ == "__main__":
    main()
