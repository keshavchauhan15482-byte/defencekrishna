from __future__ import annotations

"""V38 grouped cross-device clean-onset forecasting using the V37-selected view.

The representation was selected only by benign device-invariance in V37. V38
uses eight development devices in four whole-device folds. The two previously
inspected V35 test devices are excluded entirely. Model/calibration/policy/test
roles are disjoint by device in every fold.
"""

import json
import sys
import tempfile
import zipfile
from collections import defaultdict
from pathlib import Path

import numpy as np
from sklearn.ensemble import HistGradientBoostingClassifier
from sklearn.preprocessing import StandardScaler

HERE = Path(__file__).resolve().parent
V35_DIR = HERE.parent / "v35"
V37_DIR = HERE.parent / "v37"
for p in (V35_DIR, V37_DIR):
    if str(p) not in sys.path:
        sys.path.insert(0, str(p))
import v35_unsw_cross_device_forecast as v35
import v37_unsw_invariant_representation as v37

OUT = HERE / "artifacts" / "unsw_invariant_cross_device"
OUT.mkdir(parents=True, exist_ok=True)
SEEDS = [42, 43, 44]
MAX_TRAIN_BENIGN = 60_000
POLICY_BUDGETS = [0.005, 0.01, 0.02, 0.05]
SELECTED_VIEW = "fraction_derivatives"
FOLDS = [
    {"name":"fold0", "test":["00166cab6b88","0017882b9a25"], "calibration":["44650d56ccd3"], "policy":["50c7bf005639"], "train":["70ee50183443","74c63b29d71d","d073d5018308","ec1a5979f489"]},
    {"name":"fold1", "test":["44650d56ccd3","50c7bf005639"], "calibration":["70ee50183443"], "policy":["74c63b29d71d"], "train":["00166cab6b88","0017882b9a25","d073d5018308","ec1a5979f489"]},
    {"name":"fold2", "test":["70ee50183443","74c63b29d71d"], "calibration":["d073d5018308"], "policy":["ec1a5979f489"], "train":["00166cab6b88","0017882b9a25","44650d56ccd3","50c7bf005639"]},
    {"name":"fold3", "test":["d073d5018308","ec1a5979f489"], "calibration":["00166cab6b88"], "policy":["0017882b9a25"], "train":["44650d56ccd3","50c7bf005639","70ee50183443","74c63b29d71d"]},
]


def join_devices(data, devices, with_meta=False):
    X = np.concatenate([data[d]["X"] for d in devices], axis=0)
    y = np.concatenate([data[d]["y"] for d in devices], axis=0)
    if not with_meta:
        return X, y
    meta = []
    for d in devices:
        meta.extend(data[d]["meta"])
    return X, y, meta


def choose_policy_threshold(scores, y):
    scores = np.asarray(scores, float); y = np.asarray(y, int)
    benign = scores[y == 0]
    if len(benign) < 100:
        raise RuntimeError(f"policy benign support too small: {len(benign)}")
    rows = []
    for budget in POLICY_BUDGETS:
        th = float(np.quantile(benign, 1.0 - budget, method="higher"))
        m = v35.binary_metrics(y, scores, th)
        rows.append({"budget": float(budget), "threshold": th, "metrics": m})
    valid = [r for r in rows if r["metrics"]["fpr"] <= 0.0505]
    if not valid:
        raise RuntimeError("no policy threshold satisfies <=5.05% policy FPR")
    chosen = sorted(valid, key=lambda r: (-r["metrics"]["recall"], r["metrics"]["fpr"], r["budget"]))[0]
    return {"candidates": rows, "chosen": chosen}


def event_metrics(test_devices, meta, scores, threshold, events_by_device):
    candidates = defaultdict(list)
    for i, s in enumerate(meta):
        for eid in s["event_ids"]:
            candidates[eid].append(i)
    rows = []
    detected_leads = []
    for device in test_devices:
        for e in events_by_device[device]:
            idx = candidates.get(e["id"], [])
            if not idx:
                rows.append({
                    "event_id": e["id"], "device": device, "label": e["label"],
                    "start": e["start"], "candidate_windows": 0, "evaluable": False,
                    "detected": False, "max_lead_seconds": None,
                })
                continue
            hit = [i for i in idx if scores[i] >= threshold]
            leads = [float(e["start"] - meta[i]["cutoff_ts"]) for i in hit]
            max_lead = max(leads) if leads else None
            if max_lead is not None:
                detected_leads.append(max_lead)
            rows.append({
                "event_id": e["id"], "device": device, "label": e["label"],
                "start": e["start"], "candidate_windows": int(len(idx)), "evaluable": True,
                "detected": bool(hit), "max_lead_seconds": max_lead,
            })
    evaluable = [r for r in rows if r["evaluable"]]
    detected = [r for r in evaluable if r["detected"]]
    return {
        "total_annotated_events": int(len(rows)),
        "evaluable_event_n": int(len(evaluable)),
        "unsupported_event_n": int(len(rows) - len(evaluable)),
        "event_recall": float(len(detected) / max(1, len(evaluable))),
        "detected_event_n": int(len(detected)),
        "detected_event_median_max_lead_seconds": float(np.median(detected_leads)) if detected_leads else 0.0,
        "detected_event_mean_max_lead_seconds": float(np.mean(detected_leads)) if detected_leads else 0.0,
        "events": rows,
    }


def run_fold_seed(data, events, fold, seed):
    rng = np.random.default_rng(seed + 100 * int(fold["name"].replace("fold", "")))
    Xtr_all, ytr_all = join_devices(data, fold["train"])
    Xca, yca = join_devices(data, fold["calibration"])
    Xpo, ypo = join_devices(data, fold["policy"])
    Xte, yte, meta_te = join_devices(data, fold["test"], with_meta=True)

    # Keep every positive training precursor and cap only benign histories.
    pos = np.where(ytr_all == 1)[0]
    neg = np.where(ytr_all == 0)[0]
    if len(neg) > MAX_TRAIN_BENIGN:
        neg = rng.choice(neg, MAX_TRAIN_BENIGN, replace=False)
    tr_idx = np.concatenate([pos, neg])
    rng.shuffle(tr_idx)
    Xtr, ytr = Xtr_all[tr_idx], ytr_all[tr_idx]

    for name, y, min_pos in (("train", ytr, 20), ("calibration", yca, 5), ("policy", ypo, 5), ("test", yte, 10)):
        c = np.bincount(y, minlength=2)
        if len(y) < 50 or c[0] < 30 or c[1] < min_pos:
            raise RuntimeError(f"{fold['name']} {name} support n={len(y)} counts={c.tolist()}")

    scaler = StandardScaler().fit(Xtr)
    Ztr = scaler.transform(Xtr); Zca = scaler.transform(Xca)
    Zpo = scaler.transform(Xpo); Zte = scaler.transform(Xte)
    model = HistGradientBoostingClassifier(
        max_iter=350, learning_rate=0.04, max_leaf_nodes=31,
        min_samples_leaf=12, l2_regularization=2.0,
        class_weight="balanced", random_state=seed,
    ).fit(Ztr, ytr)
    cal = v35.calibrator(model.predict_proba(Zca)[:, 1], yca)
    ppo = v35.apply_cal(cal, model.predict_proba(Zpo)[:, 1])
    plan = choose_policy_threshold(ppo, ypo)
    th = plan["chosen"]["threshold"]
    pte = v35.apply_cal(cal, model.predict_proba(Zte)[:, 1])
    bm = v35.binary_metrics(yte, pte, th)
    em = event_metrics(fold["test"], meta_te, pte, th, events)
    return {
        "fold": fold["name"], "seed": seed,
        "devices": fold,
        "support": {
            "train_used": int(len(ytr)), "train_positive": int((ytr == 1).sum()),
            "calibration": int(len(yca)), "calibration_positive": int((yca == 1).sum()),
            "policy": int(len(ypo)), "policy_positive": int((ypo == 1).sum()),
            "test": int(len(yte)), "test_positive": int((yte == 1).sum()),
        },
        "policy_plan": plan,
        "test": bm,
        "event_test": em,
    }


def main():
    with tempfile.TemporaryDirectory(prefix="krishna-v38-") as tmp:
        td = Path(tmp); fp = td / "flowdata.zip"; ap = td / "annotations.zip"
        flow_meta = v35.download(v35.FLOW_URL, fp); ann_meta = v35.download(v35.ANN_URL, ap)
        if flow_meta["sha256"] != v35.EXPECTED_FLOW_SHA:
            raise RuntimeError("flow archive hash mismatch")
        if ann_meta["sha256"] != v35.EXPECTED_ANN_SHA:
            raise RuntimeError("annotation archive hash mismatch")
        with zipfile.ZipFile(fp) as zf:
            flows, _ = v35.load_flows(zf)
        with zipfile.ZipFile(ap) as za:
            events = v35.load_events(za)

    devs = sorted(set(d for f in FOLDS for role in ("train","calibration","policy","test") for d in f[role]))
    excluded = set(v35.TEST_DEVICES)
    if set(devs) & excluded:
        raise RuntimeError("V35 inspected test device leaked into V38")

    data = {}
    support = {}
    for device in devs:
        ds = v35.build_device_samples(device, flows[device], events[device])
        Xfull = np.stack([s["x"] for s in ds]).astype(np.float32)
        X = v37.transform(Xfull, SELECTED_VIEW)
        y = np.asarray([s["y"] for s in ds], int)
        meta = [{"device": device, "cutoff_ts": s["cutoff_ts"], "event_ids": s["event_ids"]} for s in ds]
        data[device] = {"X": X, "y": y, "meta": meta}
        support[device] = {"samples": int(len(y)), "positive": int((y == 1).sum()), "benign": int((y == 0).sum()), "events": int(len(events[device]))}
        print(f"V38 {device} n={len(y)} pos={support[device]['positive']} dim={X.shape[1]}", flush=True)

    runs = []
    for fold in FOLDS:
        for seed in SEEDS:
            print(f"V38 {fold['name']} seed={seed}", flush=True)
            r = run_fold_seed(data, events, fold, seed)
            runs.append(r)
            print(json.dumps({
                "fold": r["fold"], "seed": seed,
                "test": r["test"],
                "event_test": {k:v for k,v in r["event_test"].items() if k != "events"},
                "policy_chosen": r["policy_plan"]["chosen"],
            }, indent=2), flush=True)

    mean = {
        "fpr": float(np.mean([r["test"]["fpr"] for r in runs])),
        "sequence_recall": float(np.mean([r["test"]["recall"] for r in runs])),
        "precision": float(np.mean([r["test"]["precision"] for r in runs])),
        "f1": float(np.mean([r["test"]["f1"] for r in runs])),
        "pr_auc": float(np.mean([r["test"]["pr_auc"] for r in runs])),
        "event_recall": float(np.mean([r["event_test"]["event_recall"] for r in runs])),
        "detected_event_median_max_lead_seconds": float(np.mean([r["event_test"]["detected_event_median_max_lead_seconds"] for r in runs])),
    }
    per_fold = {}
    for fold in FOLDS:
        rr = [r for r in runs if r["fold"] == fold["name"]]
        per_fold[fold["name"]] = {
            "fpr": float(np.mean([r["test"]["fpr"] for r in rr])),
            "sequence_recall": float(np.mean([r["test"]["recall"] for r in rr])),
            "event_recall": float(np.mean([r["event_test"]["event_recall"] for r in rr])),
            "evaluable_event_n": int(min(r["event_test"]["evaluable_event_n"] for r in rr)),
            "median_max_lead_seconds_mean": float(np.mean([r["event_test"]["detected_event_median_max_lead_seconds"] for r in rr])),
        }
    gate = {
        "mean_test_fpr_pass": bool(mean["fpr"] <= 0.05),
        "mean_sequence_recall_pass": bool(mean["sequence_recall"] >= 0.70),
        "mean_event_recall_pass": bool(mean["event_recall"] >= 0.80),
        "minimum_fold_event_support_pass": bool(all(x["evaluable_event_n"] >= 5 for x in per_fold.values())),
        "lead_time_pass": bool(mean["detected_event_median_max_lead_seconds"] >= 60),
    }
    gate["pass"] = bool(all(gate.values()))
    report = {
        "schema": "krishna-v38-unsw-invariant-cross-device-dev-v1",
        "representation": {"view": SELECTED_VIEW, "dimension": 36, "selected_by": "V37 benign device-invariance only"},
        "source_provenance": {"flow": flow_meta, "annotations": ann_meta},
        "excluded_inspected_v35_test_devices": list(v35.TEST_DEVICES),
        "support": support,
        "runs": runs,
        "mean": mean,
        "per_fold_mean": per_fold,
        "development_gate": gate,
        "claim_boundary": "development cross-device evidence only; external/new final validation required",
    }
    (OUT / "results.json").write_text(json.dumps(report, indent=2), encoding="utf-8")
    (OUT / "REPORT.md").write_text(
        "# V38 invariant cross-device clean-onset forecasting\n\n"
        "V37 selected the 36-D representation using benign-domain invariance only.\n\n"
        "```json\n" + json.dumps({"mean": mean, "per_fold_mean": per_fold, "development_gate": gate}, indent=2) + "\n```\n",
        encoding="utf-8",
    )
    print(json.dumps({"mean": mean, "per_fold_mean": per_fold, "development_gate": gate}, indent=2), flush=True)
    if not gate["pass"]:
        raise RuntimeError("V38 invariant cross-device development gate not met")


if __name__ == "__main__":
    main()
