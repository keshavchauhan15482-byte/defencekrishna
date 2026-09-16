from __future__ import annotations

"""V36 diagnostic: explain V35's cross-device clean-onset failure.

This is deliberately NOT another attack forecaster.  It reuses the exact V35
network-only representation and whole-device split, then asks two questions:

1. Are clean benign histories from the held-out devices distributionally easy
   to distinguish from clean benign histories on the training devices?
2. How many held-out clean-onset events have attack labels that were never
   present on the training devices?

No attack threshold or forecasting model is selected from this audit.
"""

import json
import sys
import tempfile
import zipfile
from collections import Counter
from pathlib import Path

import numpy as np
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import accuracy_score, roc_auc_score
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler

HERE = Path(__file__).resolve().parent
V35_DIR = HERE.parent / "v35"
if str(V35_DIR) not in sys.path:
    sys.path.insert(0, str(V35_DIR))
import v35_unsw_cross_device_forecast as v35

OUT = HERE / "artifacts" / "unsw_domain_shift_audit"
OUT.mkdir(parents=True, exist_ok=True)
RNG_SEED = 3601
MAX_BENIGN_PER_DEVICE = 20_000
MAX_DOMAIN_PER_CLASS = 20_000
OPS = ["last", "mean", "std", "max", "delta", "recent2", "recent4"]


def norm_label(x: str) -> str:
    return " ".join(str(x).strip().lower().split())


def sample_rows(X: np.ndarray, n: int, rng: np.random.Generator) -> np.ndarray:
    if len(X) <= n:
        return X
    idx = rng.choice(len(X), n, replace=False)
    return X[idx]


def shift_summary(values: np.ndarray) -> dict:
    v = np.asarray(values, float)
    return {
        "median": float(np.median(v)),
        "mean": float(np.mean(v)),
        "p90": float(np.quantile(v, 0.90)),
        "max": float(np.max(v)),
        "fraction_gt_1": float(np.mean(v > 1.0)),
        "fraction_gt_2": float(np.mean(v > 2.0)),
    }


def main():
    rng = np.random.default_rng(RNG_SEED)

    with tempfile.TemporaryDirectory(prefix="krishna-v36-") as tmp:
        td = Path(tmp)
        fp = td / "flowdata.zip"
        ap = td / "annotations.zip"
        flow_meta = v35.download(v35.FLOW_URL, fp)
        ann_meta = v35.download(v35.ANN_URL, ap)
        if flow_meta["sha256"] != v35.EXPECTED_FLOW_SHA:
            raise RuntimeError(f"flow archive hash mismatch: {flow_meta['sha256']}")
        if ann_meta["sha256"] != v35.EXPECTED_ANN_SHA:
            raise RuntimeError(f"annotation archive hash mismatch: {ann_meta['sha256']}")
        with zipfile.ZipFile(fp) as zf:
            flows, flow_schema = v35.load_flows(zf)
        with zipfile.ZipFile(ap) as za:
            events = v35.load_events(za)

    # Attack-label inventories are annotation-only diagnostics.
    labels_by_split: dict[str, Counter] = {k: Counter() for k in ["train", "calibration", "policy", "test"]}
    for device in v35.ALL_DEVICES:
        split = v35.split_name(device)
        for event in events[device]:
            labels_by_split[split][norm_label(event["label"])] += 1
    train_labels = set(labels_by_split["train"])

    # Build V35 samples one device at a time.  Keep only a fixed benign sample
    # cap for domain statistics to avoid changing the diagnostic with device size.
    benign_by_device: dict[str, np.ndarray] = {}
    evaluable_test_event_ids: set[str] = set()
    per_device_support = {}
    for device in v35.ALL_DEVICES:
        ds = v35.build_device_samples(device, flows[device], events[device])
        benign = [s["x"] for s in ds if int(s["y"]) == 0]
        if not benign:
            raise RuntimeError(f"{device}: no clean benign histories")
        bx = np.stack(benign).astype(np.float32)
        bx = sample_rows(bx, MAX_BENIGN_PER_DEVICE, rng)
        benign_by_device[device] = bx
        if device in v35.TEST_DEVICES:
            for s in ds:
                for eid in s["event_ids"]:
                    evaluable_test_event_ids.add(eid)
        per_device_support[device] = {
            "split": v35.split_name(device),
            "all_v35_samples": int(len(ds)),
            "benign_histories": int(sum(int(s["y"]) == 0 for s in ds)),
            "positive_histories": int(sum(int(s["y"]) == 1 for s in ds)),
            "benign_histories_used_for_shift_audit": int(len(bx)),
            "annotated_events": int(len(events[device])),
        }
        print(
            f"V36 {device} split={v35.split_name(device)} benign={per_device_support[device]['benign_histories']} "
            f"positive={per_device_support[device]['positive_histories']}",
            flush=True,
        )

    train_pool = np.concatenate([benign_by_device[d] for d in v35.TRAIN_DEVICES], axis=0)
    test_pool = np.concatenate([benign_by_device[d] for d in v35.TEST_DEVICES], axis=0)
    q25 = np.quantile(train_pool, 0.25, axis=0)
    q75 = np.quantile(train_pool, 0.75, axis=0)
    train_median = np.median(train_pool, axis=0)
    robust_scale = np.maximum(q75 - q25, 0.10)

    per_test_device_shift = {}
    for device in v35.TEST_DEVICES:
        med = np.median(benign_by_device[device], axis=0)
        shift = np.abs(med - train_median) / robust_scale
        per_test_device_shift[device] = shift_summary(shift)

    pooled_test_median = np.median(test_pool, axis=0)
    pooled_shift = np.abs(pooled_test_median - train_median) / robust_scale
    base_n = len(v35.BASE_FEATURE_NAMES)
    if len(pooled_shift) != len(OPS) * base_n:
        raise RuntimeError(f"unexpected V35 history feature width: {len(pooled_shift)}")

    by_operation = {}
    for i, op in enumerate(OPS):
        block = pooled_shift[i * base_n:(i + 1) * base_n]
        by_operation[op] = shift_summary(block)

    count_idx = []
    fraction_idx = []
    count_n = len(v35.COUNT_NAMES)
    for i in range(len(OPS)):
        start = i * base_n
        count_idx.extend(range(start, start + count_n))
        fraction_idx.extend(range(start + count_n, start + base_n))
    by_base_type = {
        "count_derived": shift_summary(pooled_shift[count_idx]),
        "fraction_derived": shift_summary(pooled_shift[fraction_idx]),
    }

    # Diagnostic-only domain classifier.  Both domains are clean benign histories;
    # target means source domain (train-device vs V35-test-device), not attack.
    tr_dom = sample_rows(train_pool, MAX_DOMAIN_PER_CLASS, rng)
    te_dom = sample_rows(test_pool, MAX_DOMAIN_PER_CLASS, rng)
    DX = np.concatenate([tr_dom, te_dom], axis=0)
    Dy = np.concatenate([np.zeros(len(tr_dom), int), np.ones(len(te_dom), int)])
    X_a, X_b, y_a, y_b = train_test_split(
        DX, Dy, test_size=0.30, random_state=RNG_SEED, stratify=Dy
    )
    scaler = StandardScaler().fit(X_a)
    clf = LogisticRegression(C=1.0, class_weight="balanced", max_iter=1200, random_state=RNG_SEED)
    clf.fit(scaler.transform(X_a), y_a)
    prob = clf.predict_proba(scaler.transform(X_b))[:, 1]
    pred = prob >= 0.5
    domain_diag = {
        "meaning": "1=test-device benign history; 0=train-device benign history",
        "train_domain_n": int(len(tr_dom)),
        "test_domain_n": int(len(te_dom)),
        "holdout_n": int(len(y_b)),
        "roc_auc": float(roc_auc_score(y_b, prob)),
        "accuracy": float(accuracy_score(y_b, pred)),
    }

    # Test event label overlap and evaluability under the exact V35 sample builder.
    test_event_rows = []
    for device in v35.TEST_DEVICES:
        for e in events[device]:
            label = norm_label(e["label"])
            test_event_rows.append({
                "event_id": e["id"],
                "device": device,
                "label": label,
                "label_seen_on_train_devices": bool(label in train_labels),
                "v35_evaluable_clean_onset": bool(e["id"] in evaluable_test_event_ids),
            })
    evaluable = [e for e in test_event_rows if e["v35_evaluable_clean_onset"]]
    evaluable_unseen = [e for e in evaluable if not e["label_seen_on_train_devices"]]
    annotated_unseen = [e for e in test_event_rows if not e["label_seen_on_train_devices"]]
    label_overlap = {
        "distinct_labels_by_split": {k: int(len(v)) for k, v in labels_by_split.items()},
        "train_distinct_labels": sorted(train_labels),
        "test_distinct_labels": sorted(labels_by_split["test"]),
        "test_labels_seen_on_train": sorted(set(labels_by_split["test"]) & train_labels),
        "test_labels_unseen_on_train": sorted(set(labels_by_split["test"]) - train_labels),
        "test_annotated_event_n": int(len(test_event_rows)),
        "test_annotated_unseen_label_event_n": int(len(annotated_unseen)),
        "test_evaluable_event_n": int(len(evaluable)),
        "test_evaluable_unseen_label_event_n": int(len(evaluable_unseen)),
        "test_evaluable_unseen_label_fraction": float(len(evaluable_unseen) / max(1, len(evaluable))),
        "events": test_event_rows,
    }

    pooled_shift_summary = shift_summary(pooled_shift)
    strong_domain_shift = bool(
        domain_diag["roc_auc"] >= 0.80 or pooled_shift_summary["median"] >= 1.0
    )
    label_shift_material = bool(label_overlap["test_evaluable_unseen_label_fraction"] >= 0.25)
    if strong_domain_shift and label_shift_material:
        next_step = "separate label-shift claims and develop scale-free device-invariant precursor features before another attack forecast"
    elif strong_domain_shift:
        next_step = "develop scale-free device-invariant precursor features on development devices; do not lower the V35 threshold"
    elif label_shift_material:
        next_step = "separate seen-label and unseen-label cross-device development protocols before retraining"
    else:
        next_step = "representation shift is not dominant; audit temporal target/annotation alignment and precursor availability"

    report = {
        "schema": "krishna-v36-unsw-domain-shift-audit-v1",
        "audit_only": True,
        "attack_forecast_model_training": False,
        "attack_threshold_selection": False,
        "source_provenance": {"flow": flow_meta, "annotations": ann_meta},
        "v35_device_split": {
            "train": v35.TRAIN_DEVICES,
            "calibration": v35.CAL_DEVICES,
            "policy": v35.POLICY_DEVICES,
            "test": v35.TEST_DEVICES,
        },
        "history_feature_count": int(len(pooled_shift)),
        "per_device_support": per_device_support,
        "benign_feature_shift": {
            "pooled_test_vs_train": pooled_shift_summary,
            "per_test_device": per_test_device_shift,
            "by_history_operation": by_operation,
            "by_base_feature_type": by_base_type,
        },
        "benign_domain_classifier": domain_diag,
        "attack_label_overlap": label_overlap,
        "decision": {
            "strong_domain_shift": strong_domain_shift,
            "label_shift_material": label_shift_material,
            "recommended_next_step": next_step,
        },
        "claim_boundary": "diagnostic only; V35 test devices are development data after V35 inspection",
    }
    (OUT / "results.json").write_text(json.dumps(report, indent=2), encoding="utf-8")
    summary = {
        "pooled_benign_shift": pooled_shift_summary,
        "domain_classifier": domain_diag,
        "label_overlap": {k: v for k, v in label_overlap.items() if k not in ("events", "train_distinct_labels", "test_distinct_labels")},
        "decision": report["decision"],
    }
    (OUT / "REPORT.md").write_text(
        "# V36 UNSW cross-device domain-shift diagnostic\n\n"
        "No attack forecaster or attack threshold is trained/selected in V36.\n\n"
        "```json\n" + json.dumps(summary, indent=2) + "\n```\n",
        encoding="utf-8",
    )
    print(json.dumps(summary, indent=2), flush=True)
    if len(evaluable) < 20:
        raise RuntimeError(f"unexpected loss of V35 evaluable support: {len(evaluable)}")


if __name__ == "__main__":
    main()
