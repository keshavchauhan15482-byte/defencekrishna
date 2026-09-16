"""Krishna V44 unknown/OOD risk head for held-out-family development evaluation.

The head deliberately ignores the supervised attack probability produced by GraphWorldModel.
It scores only history state novelty, predicted-future state novelty, service-graph topology
novelty, and LSTM/GNN forecast disagreement. References are fit on clean benign TRAIN
examples; the alert threshold is selected only from clean benign VALIDATION examples.
Held-out TEST family labels are used only after the threshold is frozen.

This is development evidence on reused IDS2018 campaigns, not a production/zero-day claim.
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path
import numpy as np

from garuda_v3.calibration import future_target, interval
from garuda_v3.data import campaign_examples, load_dataset
from garuda_v3.model import GraphWorldModel
from garuda_v3.train import batch, infer, metrics, pooled
from garuda_v3.experiments.v44.runtime_contract import (
    EVIDENCE_SCOPE, HISTORY, HORIZON, assert_runtime_dataset,
)

FPR_BUDGET = 0.01
SIGNAL_WEIGHTS = {
    "history_novelty": 0.30,
    "forecast_novelty": 0.35,
    "topology_novelty": 0.20,
    "model_disagreement": 0.15,
}


class RobustReference:
    """Independent robust per-dimension benign reference."""

    def __init__(self, median: np.ndarray, scale: np.ndarray):
        self.median = np.asarray(median, dtype=np.float64)
        self.scale = np.asarray(scale, dtype=np.float64)

    @classmethod
    def fit(cls, values: np.ndarray, floor: float = 0.01) -> "RobustReference":
        values = np.asarray(values, dtype=np.float64)
        if values.ndim != 2 or len(values) < 20 or not np.isfinite(values).all():
            raise ValueError("Robust benign reference needs >=20 finite rows")
        median = np.median(values, axis=0)
        mad = np.median(np.abs(values - median), axis=0) * 1.4826
        q25, q75 = np.quantile(values, [0.25, 0.75], axis=0)
        iqr_scale = (q75 - q25) / 1.349
        scale = np.maximum(np.maximum(mad, iqr_scale), floor)
        return cls(median, scale)

    def score(self, values: np.ndarray) -> np.ndarray:
        values = np.asarray(values, dtype=np.float64)
        z = np.abs((values - self.median) / self.scale)
        return np.mean(np.minimum(z, 25.0), axis=1)


def tail_score(reference_values: np.ndarray, values: np.ndarray) -> np.ndarray:
    """Empirical upper-tail novelty in [0,1], fit only from TRAIN benign scores."""
    ref = np.sort(np.asarray(reference_values, dtype=np.float64))
    values = np.asarray(values, dtype=np.float64)
    if ref.ndim != 1 or len(ref) < 20 or not np.isfinite(ref).all() or not np.isfinite(values).all():
        raise ValueError("Invalid empirical novelty reference")
    return np.searchsorted(ref, values, side="right") / float(len(ref))


def benign_threshold(scores: np.ndarray, budget: float = FPR_BUDGET) -> dict:
    """Choose threshold from benign VALIDATION scores only."""
    scores = np.asarray(scores, dtype=np.float64)
    if scores.ndim != 1 or len(scores) < 100 or not np.isfinite(scores).all():
        return {
            "threshold": None,
            "status": "insufficient_benign_validation_support",
            "benign_examples": int(len(scores)),
            "fpr_budget": budget,
        }
    q = float(np.quantile(scores, 1.0 - budget, method="higher"))
    threshold = float(np.nextafter(q, np.inf))
    fp = int((scores >= threshold).sum())
    fpr = fp / len(scores)
    ci = interval(fp, len(scores))
    return {
        "threshold": threshold,
        "status": "benign_validation_selected",
        "benign_examples": int(len(scores)),
        "false_positives": fp,
        "validation_fpr": float(fpr),
        "fpr_budget": budget,
        "fpr_95pct": ci,
        "confidence_gate_passed": bool(ci[1] <= budget),
        "selection": "99th-percentile-style threshold from clean benign validation only; no attack validation labels used",
    }


def clean_history_mask(datasets, indices, history=HISTORY) -> np.ndarray:
    return np.asarray([
        bool(np.all(datasets[source]["y"][start:start + history] == 0))
        for source, start in indices
    ], dtype=bool)


def feature_views(arrays, means_lstm, means_gnn):
    x, adj, mask = arrays[:3]
    state = pooled(x, mask)
    last = state[:, -1]
    history = np.concatenate([last, state.mean(axis=1), state.std(axis=1)], axis=1)
    forecast = np.concatenate([
        means_lstm.reshape(len(x), -1),
        means_gnn.reshape(len(x), -1),
    ], axis=1)
    edge_total = adj.sum(axis=(2, 3), keepdims=True)
    normalized_adj = adj / np.maximum(edge_total, 1.0)
    topology = np.concatenate([
        normalized_adj.mean(axis=1).reshape(len(x), -1),
        np.log1p(adj.sum(axis=(2, 3))).mean(axis=1, keepdims=True),
    ], axis=1)
    disagreement = np.mean(np.abs(means_lstm - means_gnn), axis=(1, 2))
    return history, forecast, topology, disagreement


def raw_signals(train_views, views, train_benign):
    train_history, train_forecast, train_topology, train_disagreement = train_views
    history, forecast, topology, disagreement = views
    refs = {
        "history_novelty": RobustReference.fit(train_history[train_benign], floor=0.01),
        "forecast_novelty": RobustReference.fit(train_forecast[train_benign], floor=0.01),
        "topology_novelty": RobustReference.fit(train_topology[train_benign], floor=0.005),
    }
    raw_train = {
        key: refs[key].score(train_values[train_benign])
        for key, train_values in (
            ("history_novelty", train_history),
            ("forecast_novelty", train_forecast),
            ("topology_novelty", train_topology),
        )
    }
    raw = {
        key: refs[key].score(value)
        for key, value in (
            ("history_novelty", history),
            ("forecast_novelty", forecast),
            ("topology_novelty", topology),
        )
    }
    raw_train["model_disagreement"] = np.asarray(train_disagreement[train_benign], dtype=np.float64)
    raw["model_disagreement"] = np.asarray(disagreement, dtype=np.float64)
    return raw_train, raw


def combine_scores(raw_train: dict, raw: dict) -> tuple[np.ndarray, dict]:
    parts = {}
    combined = None
    for name, weight in SIGNAL_WEIGHTS.items():
        score = tail_score(raw_train[name], raw[name])
        parts[name] = score
        combined = weight * score if combined is None else combined + weight * score
    return np.asarray(combined), parts


def evaluation(y: np.ndarray, score: np.ndarray, threshold: float | None) -> dict:
    y = np.asarray(y, dtype=int)
    known = y >= 0
    if threshold is None:
        return {"samples": int(known.sum()), "status": "policy_disabled"}
    return metrics(y[known], score[known], threshold)


def family_evaluation(datasets, indices, targets, scores, threshold):
    out = {}
    families = sorted({datasets[source]["metadata"].get("attack_family", "unspecified") for source, _ in indices})
    for family in families:
        ids = np.asarray([
            i for i, (source, _) in enumerate(indices)
            if datasets[source]["metadata"].get("attack_family", "unspecified") == family
        ], dtype=int)
        y = targets[ids]
        known = y >= 0
        yk = y[known]
        sk = scores[ids][known]
        if not len(yk):
            continue
        pred = sk >= threshold if threshold is not None else np.zeros(len(sk), dtype=bool)
        neg = yk == 0
        pos = yk == 1
        fp = int((pred & neg).sum())
        tp = int((pred & pos).sum())
        out[family] = {
            "examples": int(len(yk)),
            "positives": int(pos.sum()),
            "negatives": int(neg.sum()),
            "false_positives": fp,
            "true_positives": tp,
            "fpr": float(fp / neg.sum()) if neg.any() else None,
            "recall": float(tp / pos.sum()) if pos.any() else None,
            "fpr_95pct": interval(fp, int(neg.sum())),
            "recall_95pct": interval(tp, int(pos.sum())),
        }
    return out


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", default="datasets/v44_runtime")
    parser.add_argument("--model-root", default="garuda_v3/artifacts/v44_runtime_regression")
    parser.add_argument("--output", default="garuda_v3/artifacts/v44_unknown_head.json")
    parser.add_argument("--fpr-budget", type=float, default=FPR_BUDGET)
    args = parser.parse_args()
    if not 0 < args.fpr_budget < 0.1:
        raise SystemExit("V44 unknown-head FPR budget must be in (0, 0.1)")

    root = Path(args.root)
    manifest = json.loads((root / "split.json").read_text())
    ordered = [name for split in ("train", "validation", "test") for name in manifest[split]]
    datasets = [load_dataset(root / "labelled" / f"{name}.npz") for name in ordered]
    for d in datasets:
        assert_runtime_dataset(d)
        if d["metadata"].get("evidence_scope") != EVIDENCE_SCOPE:
            raise ValueError("V44 unknown head refuses non-development evidence scope")

    splits, _ = campaign_examples(
        datasets, manifest, history=HISTORY, horizon=HORIZON, stride=8, allow_unknown=True
    )
    arrays = [batch(datasets, split, HISTORY, HORIZON) for split in splits]
    targets = [future_target(a[4]) for a in arrays]
    clean = [clean_history_mask(datasets, split) for split in splits]

    model_root = Path(args.model_root)
    lstm, lstm_meta = GraphWorldModel.load(model_root / "lstm.npz")
    gnn, gnn_meta = GraphWorldModel.load(model_root / "gnn_lstm.npz")
    for meta in (lstm_meta, gnn_meta):
        if meta.get("window_seconds") != 10 or meta.get("history") != HISTORY or meta.get("horizon") != HORIZON:
            raise ValueError("Checkpoint does not match V44 decision-time contract")

    predictions = []
    for a in arrays:
        lstm_mu = infer(lstm, a, HORIZON)[0]
        gnn_mu = infer(gnn, a, HORIZON)[0]
        predictions.append((lstm_mu, gnn_mu))
    views = [feature_views(a, *pred) for a, pred in zip(arrays, predictions)]

    train_benign = (targets[0] == 0) & clean[0]
    validation_benign = (targets[1] == 0) & clean[1]
    if int(train_benign.sum()) < 100:
        raise ValueError("Need >=100 clean benign TRAIN examples for V44 unknown reference")

    raw_train, train_raw = raw_signals(views[0], views[0], train_benign)
    _, _ = combine_scores(raw_train, train_raw)
    _, validation_raw = raw_signals(views[0], views[1], train_benign)
    validation_score, validation_parts = combine_scores(raw_train, validation_raw)
    _, test_raw = raw_signals(views[0], views[2], train_benign)
    test_score, test_parts = combine_scores(raw_train, test_raw)

    policy = benign_threshold(validation_score[validation_benign], args.fpr_budget)
    threshold = policy["threshold"]
    test_eval = evaluation(targets[2], test_score, threshold)
    clean_test = (targets[2] >= 0) & clean[2]
    clean_eval = evaluation(targets[2][clean_test], test_score[clean_test], threshold)
    families = family_evaluation(datasets, splits[2], targets[2], test_score, threshold)

    report = {
        "version": "v44-krishna-unknown-head-1",
        "evidence_scope": EVIDENCE_SCOPE,
        "fresh_final_holdout": False,
        "runtime_schema_compatible": True,
        "network_only_feature_audit_passed": True,
        "supervised_attack_probability_used": False,
        "fit_scope": "robust signal references: clean benign TRAIN only; threshold: clean benign VALIDATION only",
        "weights": SIGNAL_WEIGHTS,
        "train_clean_benign_examples": int(train_benign.sum()),
        "validation_clean_benign_examples": int(validation_benign.sum()),
        "policy": policy,
        "test": test_eval,
        "clean_history_test": clean_eval,
        "per_family_test": families,
        "validation_signal_means": {name: float(np.mean(value[validation_benign])) for name, value in validation_parts.items()},
        "test_signal_means": {name: float(np.mean(value)) for name, value in test_parts.items()},
        "development_gate_point_estimate": bool(
            threshold is not None
            and test_eval.get("fpr") is not None and test_eval["fpr"] <= args.fpr_budget
            and test_eval.get("recall", 0.0) >= 0.80
        ),
        "release_approved": False,
        "automatic_unknown_containment_approved": False,
        "limitations": [
            "Test campaigns were already used in earlier project development; this is not a newly untouched final holdout.",
            "IDS2018 labels here are schedule-assisted weak supervision, not verified compromise ground truth.",
            "The state forecasters were trained jointly with known web-attack risk supervision; the unknown head itself does not use their supervised risk probabilities.",
            "Service graphs encode protocol/service incidence, not host lateral-movement topology.",
            "Residual after the future arrives is deliberately excluded from the forecast-time unknown score; only decision-time history and model-predicted future states are used.",
            "No verified clean-history compromise onset or supervised MITRE stage ground truth is available.",
            "Unknown/OOD alerting remains shadow/triage only.",
        ],
    }
    out = Path(args.output)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(report, indent=2))
    print(json.dumps(report, indent=2))


if __name__ == "__main__":
    main()
