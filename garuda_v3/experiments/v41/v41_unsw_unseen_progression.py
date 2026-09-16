from __future__ import annotations

"""V41: unseen-family early attack-progression forecasting on UNSW IoT traces.

Unlike the failed clean-onset experiments, V41 does not claim to predict the first
malicious packet from benign victim history. It asks a deployable question: once
the first observable network change of an attack appears, can Garuda recognize an
attack family never used for model development and forecast malicious continuation
for the next four minutes with low benign false-positive rate?
"""

import hashlib
import json
import math
import sys
import tempfile
import zipfile
from collections import defaultdict
from pathlib import Path

import numpy as np
from sklearn.ensemble import HistGradientBoostingClassifier, IsolationForest
from sklearn.linear_model import LogisticRegression
from sklearn.preprocessing import StandardScaler

HERE = Path(__file__).resolve().parent
V35_DIR = HERE.parent / "v35"
if str(V35_DIR) not in sys.path:
    sys.path.insert(0, str(V35_DIR))
import v35_unsw_cross_device_forecast as v35

OUT = HERE / "artifacts" / "unsw_unseen_progression"
OUT.mkdir(parents=True, exist_ok=True)

DEV_HOLDOUT = ["TcpSynReflection", "ArpSpoof", "PingOfDeath", "Ssdp"]
LOCKED_FINAL = {"TcpSynDevice", "UdpDevice"}
SEEDS = [42, 43, 44]
HISTORY = 4
FUTURE = 4
BLOCK_MINUTES = 30
WEIGHTS = [0.0, 0.25, 0.5, 0.75, 1.0]
BUDGETS = [0.0025, 0.005, 0.01]

FAMILY_PREFIXES = [
    "TcpSynReflection", "TcpSynDevice", "ArpSpoof", "PingOfDeath",
    "UdpDevice", "Smurf", "Ssdp", "Snmp",
]


def base_family(label: str) -> str:
    s = str(label).strip()
    for p in FAMILY_PREFIXES:
        if s.startswith(p):
            return p
    return s


def split_for(device: str, block_start: int) -> str:
    h = hashlib.sha256(f"{device}:{block_start}".encode()).digest()
    q = int.from_bytes(h[:8], "big") % 100
    if q < 60:
        return "train"
    if q < 75:
        return "calibration"
    if q < 88:
        return "policy"
    return "test"


def active_events_for_minute(minute: int, events: list[dict]) -> list[dict]:
    lo, hi = minute * 60.0, (minute + 1) * 60.0
    return [e for e in events if e["start"] < hi and e["end"] > lo]


def invariant_derivative(H: np.ndarray) -> np.ndarray:
    """Exact V37-style scale-free fraction derivative view: 3 x 12 = 36."""
    frac = np.asarray(H[:, len(v35.COUNT_NAMES):], dtype=np.float32)
    frac = np.clip(frac, 0.0, 1.0)
    return np.diff(frac, axis=0).reshape(-1).astype(np.float32)


def build_samples(flows: dict, events_by_device: dict):
    samples = []
    event_lookup = {}
    for device, events in events_by_device.items():
        for e in events:
            e["family"] = base_family(e["label"])
            event_lookup[e["id"]] = e

    for device in v35.ALL_DEVICES:
        rows = flows[device]["rows"]
        timestamps = flows[device]["timestamps"]
        minute_set = set(rows)
        events = events_by_device[device]
        active_cache = {m: active_events_for_minute(m, events) for m in minute_set}
        for m in sorted(minute_set):
            hist = list(range(m - HISTORY + 1, m + 1))
            fut = list(range(m + 1, m + FUTURE + 1))
            if not all(x in minute_set for x in hist + fut):
                continue
            block_start = (m // BLOCK_MINUTES) * BLOCK_MINUTES
            if hist[0] < block_start or fut[-1] >= block_start + BLOCK_MINUTES:
                continue

            window_events = []
            seen = set()
            for mm in hist + fut:
                for e in active_cache[mm]:
                    if e["id"] not in seen:
                        window_events.append(e); seen.add(e["id"])
            fams = {e["family"] for e in window_events}
            if fams & LOCKED_FINAL:
                continue

            current_ts = float(timestamps[m])
            current_events = active_cache[m]
            early = []
            for e in current_events:
                if e["family"] in LOCKED_FINAL:
                    continue
                delay = current_ts - float(e["start"])
                if 0.0 <= delay <= 120.0 and float(e["end"]) >= current_ts + 240.0:
                    early.append(e)

            all_benign = len(window_events) == 0
            if early:
                y = 1
                early_ids = [e["id"] for e in early]
            elif all_benign:
                y = 0
                early_ids = []
            else:
                continue

            H = np.stack([rows[x] for x in hist])
            samples.append({
                "x": invariant_derivative(H), "y": int(y), "device": device,
                "minute": int(m), "cutoff_ts": current_ts,
                "block_start": int(block_start), "split": split_for(device, block_start),
                "families": sorted(fams), "early_event_ids": early_ids,
            })
    return samples, event_lookup


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


def percentile(ref, x):
    r = np.sort(np.asarray(ref, float))
    return np.searchsorted(r, np.asarray(x, float), side="right") / float(max(1, len(r)))


def choose_policy(y, ps, pn):
    y = np.asarray(y, int)
    best = None
    for w in WEIGHTS:
        score = (1.0 - w) * ps + w * pn
        benign = score[y == 0]
        if len(benign) < 100:
            continue
        for budget in BUDGETS:
            th = float(np.quantile(benign, 1.0 - budget, method="higher"))
            pred = score >= th
            fpr = float(np.mean(pred[y == 0]))
            rec = float(np.mean(pred[y == 1])) if np.any(y == 1) else 0.0
            if fpr <= 0.0105:
                key = (rec, -fpr, -w, -budget)
                cand = {"weight": float(w), "budget": float(budget), "threshold": th,
                        "policy_fpr": fpr, "policy_recall": rec}
                if best is None or key > best[0]:
                    best = (key, cand)
    if best is None:
        raise RuntimeError("no policy configuration meets <=1% benign FPR")
    return best[1]


def support(y, idx):
    c = np.bincount(np.asarray(y, int)[idx], minlength=2)
    return {"n": int(len(idx)), "benign": int(c[0]), "positive": int(c[1])}


def fit_family(samples, event_lookup, family: str, seed: int):
    X = np.stack([s["x"] for s in samples])
    y = np.asarray([s["y"] for s in samples], int)
    exposure = np.asarray([family in s["families"] for s in samples], bool)
    splits = np.asarray([s["split"] for s in samples], object)

    def dev_idx(name):
        return np.where((splits == name) & (~exposure))[0]

    tr, ca, po, te = [dev_idx(x) for x in ("train", "calibration", "policy", "test")]
    for name, idx, min_pos in (("train", tr, 20), ("calibration", ca, 5), ("policy", po, 5)):
        s = support(y, idx)
        if s["benign"] < 100 or s["positive"] < min_pos:
            raise RuntimeError(f"{family} {name} support insufficient: {s}")

    scaler = StandardScaler().fit(X[tr])
    Z = scaler.transform(X)
    clf = HistGradientBoostingClassifier(
        max_iter=300, learning_rate=0.04, max_leaf_nodes=31,
        min_samples_leaf=10, l2_regularization=2.0,
        class_weight="balanced", random_state=seed,
    ).fit(Z[tr], y[tr])
    cal = calibrator(clf.predict_proba(Z[ca])[:, 1], y[ca])
    ps_po = apply_cal(cal, clf.predict_proba(Z[po])[:, 1])

    benign_tr = tr[y[tr] == 0]
    rng = np.random.default_rng(seed)
    if len(benign_tr) > 50000:
        benign_tr = rng.choice(benign_tr, 50000, replace=False)
    iso = IsolationForest(
        n_estimators=250, max_samples=min(8192, len(benign_tr)),
        contamination="auto", random_state=seed, n_jobs=1,
    ).fit(Z[benign_tr])
    nov_ref = -iso.decision_function(Z[ca][y[ca] == 0])
    pn_po = percentile(nov_ref, -iso.decision_function(Z[po]))
    policy = choose_policy(y[po], ps_po, pn_po)

    def score_idx(idx):
        if len(idx) == 0:
            return np.asarray([], float)
        ps = apply_cal(cal, clf.predict_proba(Z[idx])[:, 1])
        pn = percentile(nov_ref, -iso.decision_function(Z[idx]))
        return (1.0 - policy["weight"]) * ps + policy["weight"] * pn

    benign_test = te[y[te] == 0]
    if len(benign_test) < 500:
        raise RuntimeError(f"{family}: reserved benign test support too small: {len(benign_test)}")
    pneg = score_idx(benign_test)
    fpr = float(np.mean(pneg >= policy["threshold"]))

    # Held-out-family event candidates were never used in train/calibration/policy.
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
    for eid, e in event_lookup.items():
        if e["family"] != family:
            continue
        idx = np.asarray(candidate_by_event.get(eid, []), int)
        if len(idx) == 0:
            event_rows.append({"event_id": eid, "device": e["device"], "label": e["label"],
                               "candidate_windows": 0, "evaluable": False, "detected": False,
                               "detection_delay_seconds": None})
            continue
        sc = score_idx(idx)
        hit = np.where(sc >= policy["threshold"])[0]
        if len(hit):
            d = [max(0.0, samples[idx[j]]["cutoff_ts"] - e["start"]) for j in hit]
            delay = float(min(d)); delays.append(delay); detected = True
        else:
            delay = None; detected = False
        event_rows.append({"event_id": eid, "device": e["device"], "label": e["label"],
                           "candidate_windows": int(len(idx)), "evaluable": True,
                           "detected": detected, "detection_delay_seconds": delay})

    evaluable = [e for e in event_rows if e["evaluable"]]
    detected = [e for e in evaluable if e["detected"]]
    return {
        "family": family, "seed": seed,
        "heldout_family_exposure_in_train_cal_policy": 0,
        "split_support": {"train": support(y, tr), "calibration": support(y, ca),
                          "policy": support(y, po), "test": support(y, te)},
        "policy": policy,
        "reserved_benign_test_n": int(len(benign_test)),
        "reserved_benign_fpr": fpr,
        "event_n": int(len(event_rows)),
        "evaluable_event_n": int(len(evaluable)),
        "unsupported_event_n": int(len(event_rows) - len(evaluable)),
        "unseen_event_recall": float(len(detected) / max(1, len(evaluable))),
        "median_detection_delay_seconds": float(np.median(delays)) if delays else None,
        "mean_detection_delay_seconds": float(np.mean(delays)) if delays else None,
        "events": event_rows,
    }


def main():
    with tempfile.TemporaryDirectory(prefix="krishna-v41-") as tmp:
        td = Path(tmp); fp = td / "flowdata.zip"; ap = td / "annotations.zip"
        fm = v35.download(v35.FLOW_URL, fp); am = v35.download(v35.ANN_URL, ap)
        if fm["sha256"] != v35.EXPECTED_FLOW_SHA or am["sha256"] != v35.EXPECTED_ANN_SHA:
            raise RuntimeError("UNSW source hash mismatch")
        with zipfile.ZipFile(fp) as zf:
            flows, schema = v35.load_flows(zf)
        with zipfile.ZipFile(ap) as za:
            events = v35.load_events(za)

    samples, event_lookup = build_samples(flows, events)
    print(f"V41 samples={len(samples)} positives={sum(s['y'] for s in samples)} features={len(samples[0]['x'])}", flush=True)
    report = {
        "schema": "krishna-v41-unsw-unseen-family-early-progression-v1",
        "source_provenance": {"flow": fm, "annotations": am},
        "strict_network_only": True,
        "representation": "3x12 fraction derivatives flattened to 36D",
        "development_holdout_families": DEV_HOLDOUT,
        "locked_final_validation_families": sorted(LOCKED_FINAL),
        "results": {},
    }

    completed = []
    for family in DEV_HOLDOUT:
        report["results"][family] = {}
        try:
            for seed in SEEDS:
                print(f"V41 family={family} seed={seed}", flush=True)
                rr = fit_family(samples, event_lookup, family, seed)
                report["results"][family][str(seed)] = rr
                print(json.dumps({k: v for k, v in rr.items() if k != "events"}, indent=2), flush=True)
            completed.append(family)
        except RuntimeError as exc:
            report["results"][family]["skipped"] = str(exc)
            print(f"V41 SKIP {family}: {exc}", flush=True)

    if len(completed) != len(DEV_HOLDOUT):
        (OUT / "results.json").write_text(json.dumps(report, indent=2), encoding="utf-8")
        raise RuntimeError(f"V41 only {len(completed)}/{len(DEV_HOLDOUT)} families completed")

    per_family = {}
    for family in completed:
        vals = [report["results"][family][str(seed)] for seed in SEEDS]
        delays = [x["median_detection_delay_seconds"] for x in vals if x["median_detection_delay_seconds"] is not None]
        per_family[family] = {
            "fpr": float(np.mean([x["reserved_benign_fpr"] for x in vals])),
            "event_recall": float(np.mean([x["unseen_event_recall"] for x in vals])),
            "evaluable_event_n": int(min(x["evaluable_event_n"] for x in vals)),
            "median_detection_delay_seconds": float(np.mean(delays)) if delays else None,
        }
    macro_fpr = float(np.mean([v["fpr"] for v in per_family.values()]))
    macro_recall = float(np.mean([v["event_recall"] for v in per_family.values()]))
    all_delays = [v["median_detection_delay_seconds"] for v in per_family.values() if v["median_detection_delay_seconds"] is not None]
    macro_delay = float(np.mean(all_delays)) if all_delays else None
    gate = {
        "macro_fpr_pass": macro_fpr <= 0.01,
        "macro_unseen_event_recall_pass": macro_recall >= 0.80,
        "all_family_event_recall_pass": all(v["event_recall"] >= 0.70 for v in per_family.values()),
        "event_support_pass": all(v["evaluable_event_n"] >= 5 for v in per_family.values()),
        "detection_delay_pass": macro_delay is not None and macro_delay <= 120.0,
    }
    gate["pass"] = bool(all(gate.values()))
    report["per_family_mean"] = per_family
    report["macro_mean"] = {"fpr": macro_fpr, "unseen_event_recall": macro_recall,
                            "median_detection_delay_seconds": macro_delay}
    report["development_gate"] = gate
    report["claim_boundary"] = "Early-observed unseen-family progression forecast only; not pre-first-packet or universal zero-day prediction."
    (OUT / "results.json").write_text(json.dumps(report, indent=2), encoding="utf-8")
    (OUT / "REPORT.md").write_text(
        "# V41 unseen-family early-progression forecasting\n\n```json\n" +
        json.dumps({"macro_mean": report["macro_mean"], "per_family_mean": per_family,
                    "development_gate": gate}, indent=2) + "\n```\n",
        encoding="utf-8",
    )
    print(json.dumps({"macro_mean": report["macro_mean"], "per_family_mean": per_family,
                      "development_gate": gate}, indent=2), flush=True)
    if not gate["pass"]:
        raise RuntimeError("V41 unseen-family early-progression gate not met")


if __name__ == "__main__":
    main()
