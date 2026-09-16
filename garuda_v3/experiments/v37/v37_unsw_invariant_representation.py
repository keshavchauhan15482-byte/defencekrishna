from __future__ import annotations

"""V37: benign-only device-invariance ablation for the UNSW representation.

No attack forecaster is trained here. Attack annotations are used only to exclude
histories that are not clean/benign, exactly as in V35. Positive attack outcomes,
attack labels and V35 test devices do not select the representation.
"""

import json
import sys
import tempfile
import zipfile
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

OUT = HERE / "artifacts" / "unsw_invariant_representation"
OUT.mkdir(parents=True, exist_ok=True)
SEED = 3701
MAX_PER_DEVICE = 10_000
DEVICES = v35.TRAIN_DEVICES + v35.CAL_DEVICES + v35.POLICY_DEVICES
FOLDS = [
    ["00166cab6b88", "0017882b9a25"],
    ["44650d56ccd3", "50c7bf005639"],
    ["70ee50183443", "74c63b29d71d"],
    ["d073d5018308", "ec1a5979f489"],
]
OPS = ["last", "mean", "std", "max", "delta", "recent2", "recent4"]
BASE_N = len(v35.BASE_FEATURE_NAMES)
COUNT_N = len(v35.COUNT_NAMES)


def cap_rows(X: np.ndarray, n: int, rng: np.random.Generator) -> np.ndarray:
    if len(X) <= n:
        return X
    return X[rng.choice(len(X), n, replace=False)]


def anonymous_stats(A: np.ndarray) -> np.ndarray:
    abs_a = np.abs(A)
    return np.stack([
        A.mean(1),
        np.median(A, axis=1),
        A.std(1),
        abs_a.max(1),
        abs_a.mean(1),
        (A > 0).mean(1),
        (abs_a > 1.0).mean(1),
    ], axis=1).astype(np.float32)


def transform(X: np.ndarray, view: str) -> np.ndarray:
    B = X.reshape(len(X), len(OPS), BASE_N)
    if view == "v35_full":
        return X.astype(np.float32, copy=False)
    if view == "derivative_channels":
        return B[:, [4, 5, 6], :].reshape(len(X), -1).astype(np.float32)
    if view == "fraction_derivatives":
        return B[:, [4, 5, 6], COUNT_N:].reshape(len(X), -1).astype(np.float32)

    if view == "anonymous_dynamics":
        op_idx = [2, 4, 5, 6]
        groups = [(0, COUNT_N), (COUNT_N, BASE_N)]
    elif view == "anonymous_derivatives":
        op_idx = [4, 5, 6]
        groups = [(0, COUNT_N), (COUNT_N, BASE_N)]
    elif view == "anonymous_fraction_derivatives":
        op_idx = [4, 5, 6]
        groups = [(COUNT_N, BASE_N)]
    else:
        raise KeyError(view)

    parts = []
    for oi in op_idx:
        for lo, hi in groups:
            parts.append(anonymous_stats(B[:, oi, lo:hi]))
    return np.concatenate(parts, axis=1).astype(np.float32)


def evaluate_view(raw_by_device: dict[str, np.ndarray], view: str) -> dict:
    transformed = {d: transform(raw_by_device[d], view) for d in DEVICES}
    fold_rows = []
    for fi, heldout in enumerate(FOLDS):
        other = [d for d in DEVICES if d not in heldout]
        A = np.concatenate([transformed[d] for d in other], axis=0)
        B = np.concatenate([transformed[d] for d in heldout], axis=0)
        # Same deterministic row sampling for every candidate view in a fold.
        rng = np.random.default_rng(SEED + fi)
        n = min(20_000, len(A), len(B))
        ia = rng.choice(len(A), n, replace=False) if len(A) > n else np.arange(len(A))
        ib = rng.choice(len(B), n, replace=False) if len(B) > n else np.arange(len(B))
        DX = np.concatenate([A[ia], B[ib]], axis=0)
        Dy = np.concatenate([np.zeros(len(ia), int), np.ones(len(ib), int)])
        xa, xb, ya, yb = train_test_split(
            DX, Dy, test_size=0.30, random_state=SEED + fi, stratify=Dy
        )
        scaler = StandardScaler().fit(xa)
        clf = LogisticRegression(
            C=1.0, class_weight="balanced", max_iter=800, random_state=SEED + fi
        ).fit(scaler.transform(xa), ya)
        prob = clf.predict_proba(scaler.transform(xb))[:, 1]
        pred = prob >= 0.5
        fold_rows.append({
            "fold": fi,
            "heldout_devices": heldout,
            "other_devices": other,
            "domain_rows_per_class": int(n),
            "roc_auc": float(roc_auc_score(yb, prob)),
            "accuracy": float(accuracy_score(yb, pred)),
        })
    return {
        "view": view,
        "dimension": int(next(iter(transformed.values())).shape[1]),
        "mean_domain_roc_auc": float(np.mean([x["roc_auc"] for x in fold_rows])),
        "max_domain_roc_auc": float(np.max([x["roc_auc"] for x in fold_rows])),
        "mean_domain_accuracy": float(np.mean([x["accuracy"] for x in fold_rows])),
        "folds": fold_rows,
    }


def choose_view(rows: list[dict]) -> dict:
    best_auc = min(x["mean_domain_roc_auc"] for x in rows)
    close = [x for x in rows if x["mean_domain_roc_auc"] <= best_auc + 0.01]
    chosen = sorted(close, key=lambda x: (x["dimension"], x["mean_domain_roc_auc"], x["view"]))[0]
    return {
        "selection_rule": "lowest mean domain ROC-AUC; within 0.01 choose lower dimension",
        "best_auc": float(best_auc),
        "views_within_0_01": [x["view"] for x in close],
        "selected_view": chosen["view"],
        "selected_dimension": chosen["dimension"],
        "selected_mean_domain_roc_auc": chosen["mean_domain_roc_auc"],
        "preferred_invariance_target_pass": bool(chosen["mean_domain_roc_auc"] <= 0.70),
    }


def main():
    rng = np.random.default_rng(SEED)
    with tempfile.TemporaryDirectory(prefix="krishna-v37-") as tmp:
        td = Path(tmp)
        fp, ap = td / "flowdata.zip", td / "annotations.zip"
        flow_meta = v35.download(v35.FLOW_URL, fp)
        ann_meta = v35.download(v35.ANN_URL, ap)
        if flow_meta["sha256"] != v35.EXPECTED_FLOW_SHA:
            raise RuntimeError("flow archive hash mismatch")
        if ann_meta["sha256"] != v35.EXPECTED_ANN_SHA:
            raise RuntimeError("annotation archive hash mismatch")
        with zipfile.ZipFile(fp) as zf:
            flows, _ = v35.load_flows(zf)
        with zipfile.ZipFile(ap) as za:
            events = v35.load_events(za)

    raw_by_device = {}
    support = {}
    for device in DEVICES:
        ds = v35.build_device_samples(device, flows[device], events[device])
        benign = np.stack([s["x"] for s in ds if int(s["y"]) == 0]).astype(np.float32)
        benign = cap_rows(benign, MAX_PER_DEVICE, rng)
        raw_by_device[device] = benign
        support[device] = int(len(benign))
        print(f"V37 {device} benign_used={len(benign)}", flush=True)

    views = [
        "v35_full",
        "derivative_channels",
        "fraction_derivatives",
        "anonymous_dynamics",
        "anonymous_derivatives",
        "anonymous_fraction_derivatives",
    ]
    results = []
    for view in views:
        print(f"V37 view={view}", flush=True)
        r = evaluate_view(raw_by_device, view)
        results.append(r)
        print(json.dumps({k: v for k, v in r.items() if k != "folds"}, indent=2), flush=True)

    decision = choose_view(results)
    report = {
        "schema": "krishna-v37-unsw-invariant-representation-v1",
        "audit_only": True,
        "attack_forecaster_trained": False,
        "positive_attack_outcomes_used_for_selection": False,
        "v35_test_devices_used_for_selection": False,
        "source_provenance": {"flow": flow_meta, "annotations": ann_meta},
        "benign_support_used": support,
        "candidate_results": results,
        "decision": decision,
        "claim_boundary": "representation selection only; no attack forecasting accuracy claim",
    }
    (OUT / "results.json").write_text(json.dumps(report, indent=2), encoding="utf-8")
    (OUT / "REPORT.md").write_text(
        "# V37 invariant-representation ablation\n\n"
        "Attack forecasting outcomes were not used to select a view.\n\n"
        "```json\n" + json.dumps({
            "candidates": [{k: v for k, v in x.items() if k != "folds"} for x in results],
            "decision": decision,
        }, indent=2) + "\n```\n",
        encoding="utf-8",
    )
    print(json.dumps({"decision": decision}, indent=2), flush=True)


if __name__ == "__main__":
    main()
