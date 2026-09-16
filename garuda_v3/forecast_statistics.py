"""Campaign-level uncertainty and conservative distribution-support reporting.

The support envelope is a descriptive train/validation distribution-shift guard,
not a generic OOD detector. Test labels never fit it.
"""
from __future__ import annotations

from typing import Any, Sequence

import numpy as np

from .calibration import future_target


def fit_support_envelope(
    train_x: np.ndarray,
    train_mask: np.ndarray,
    validation_x: np.ndarray,
    validation_mask: np.ndarray,
    *,
    lower_quantile: float = 0.001,
    upper_quantile: float = 0.999,
    validation_score_quantile: float = 0.99,
) -> dict[str, Any]:
    if not 0 <= lower_quantile < upper_quantile <= 1:
        raise ValueError("Invalid envelope quantiles")
    if not 0 < validation_score_quantile <= 1:
        raise ValueError("Invalid validation score quantile")
    observed = np.asarray(train_x)[np.asarray(train_mask).astype(bool)]
    if observed.ndim != 2 or not len(observed):
        raise ValueError("Training envelope needs observed feature vectors")
    lower = np.quantile(observed, lower_quantile, axis=0)
    upper = np.quantile(observed, upper_quantile, axis=0)
    provisional = {
        "lower": lower,
        "upper": upper,
    }
    validation_scores = support_scores(validation_x, validation_mask, provisional)
    threshold = float(np.quantile(validation_scores, validation_score_quantile)) if len(validation_scores) else 0.0
    return {
        "lower": lower.tolist(),
        "upper": upper.tolist(),
        "lower_quantile": lower_quantile,
        "upper_quantile": upper_quantile,
        "validation_score_quantile": validation_score_quantile,
        "score_threshold": threshold,
        "scope": "feature bounds from training only; support threshold from validation only",
        "interpretation": "descriptive distribution-support envelope; not a calibrated generic OOD detector",
    }


def support_scores(x: np.ndarray, mask: np.ndarray, envelope: dict[str, Any]) -> np.ndarray:
    x = np.asarray(x, dtype=float)
    mask = np.asarray(mask).astype(bool)
    if x.ndim != 4 or mask.shape != x.shape[:3]:
        raise ValueError("Expected x=[examples,time,nodes,features] and aligned mask")
    lower = np.asarray(envelope["lower"], dtype=float)
    upper = np.asarray(envelope["upper"], dtype=float)
    if lower.shape != (x.shape[-1],) or upper.shape != lower.shape:
        raise ValueError("Envelope feature dimension mismatch")
    observed = mask[..., None]
    outside = ((x < lower) | (x > upper)) & observed
    denom = np.maximum(mask.sum(axis=(1, 2)) * x.shape[-1], 1)
    return outside.sum(axis=(1, 2, 3)) / denom


def support_report(x: np.ndarray, mask: np.ndarray, envelope: dict[str, Any]) -> dict[str, Any]:
    scores = support_scores(x, mask, envelope)
    threshold = float(envelope["score_threshold"])
    supported = scores <= threshold
    return {
        "supported": supported,
        "scores": scores,
        "summary": {
            "examples": int(len(scores)),
            "supported_examples": int(supported.sum()),
            "coverage": float(supported.mean()) if len(supported) else None,
            "abstention_rate": float((~supported).mean()) if len(supported) else None,
            "score_threshold": threshold,
            "interpretation": "unsupported examples should abstain/return insufficient evidence",
        },
    }


def _confusion(y: np.ndarray, pred: np.ndarray) -> dict[str, float | int | None]:
    y = np.asarray(y, dtype=bool)
    pred = np.asarray(pred, dtype=bool)
    tp = int((pred & y).sum())
    fp = int((pred & ~y).sum())
    fn = int((~pred & y).sum())
    tn = int((~pred & ~y).sum())
    precision = tp / (tp + fp) if tp + fp else None
    recall = tp / (tp + fn) if tp + fn else None
    fpr = fp / (fp + tn) if fp + tn else None
    f1 = (2 * precision * recall / (precision + recall)) if precision is not None and recall is not None and precision + recall else None
    return {"tp": tp, "fp": fp, "fn": fn, "tn": tn, "precision": precision, "recall": recall, "fpr": fpr, "f1": f1}


def campaign_bootstrap(
    datasets: Sequence[dict[str, Any]],
    indices: Sequence[tuple[int, int]],
    labels: np.ndarray,
    probabilities: np.ndarray,
    threshold: float | None,
    *,
    supported: np.ndarray | None = None,
    seed: int = 42,
    samples: int = 2000,
) -> dict[str, Any]:
    if threshold is None:
        return {"status": "policy_disabled", "campaigns": 0, "intervals": None}
    target = future_target(labels)
    probabilities = np.asarray(probabilities, dtype=float)
    if probabilities.shape != np.asarray(labels).shape:
        raise ValueError("Probability/label horizon mismatch")
    score = probabilities.max(axis=1)
    campaigns = np.asarray([datasets[s]["metadata"].get("campaign_id", "unannotated") for s, _ in indices], dtype=object)
    known = target >= 0
    if supported is not None:
        supported = np.asarray(supported, dtype=bool)
        if supported.shape != known.shape:
            raise ValueError("Support mask shape mismatch")
        known &= supported
    units = sorted(set(campaigns[known]))
    if len(units) < 3:
        return {
            "status": "insufficient_independent_campaigns",
            "campaigns": len(units),
            "intervals": None,
            "interpretation": "need at least three independent campaign units for a descriptive campaign bootstrap",
        }

    grouped = {}
    for unit in units:
        take = known & (campaigns == unit)
        grouped[unit] = (target[take].astype(bool), score[take] >= threshold)

    point_y = np.concatenate([grouped[u][0] for u in units])
    point_pred = np.concatenate([grouped[u][1] for u in units])
    point = _confusion(point_y, point_pred)
    rng = np.random.default_rng(seed)
    draws = {name: [] for name in ("fpr", "recall", "precision", "f1")}
    for _ in range(samples):
        chosen = rng.choice(units, size=len(units), replace=True)
        y = np.concatenate([grouped[u][0] for u in chosen])
        pred = np.concatenate([grouped[u][1] for u in chosen])
        row = _confusion(y, pred)
        for name in draws:
            if row[name] is not None:
                draws[name].append(row[name])
    intervals = {
        name: [float(np.quantile(values, 0.025)), float(np.quantile(values, 0.975))] if values else [None, None]
        for name, values in draws.items()
    }
    return {
        "status": "descriptive_campaign_bootstrap",
        "campaigns": len(units),
        "bootstrap_samples": samples,
        "point": point,
        "intervals_95pct": intervals,
        "bootstrap_unit": "campaign",
        "interpretation": "campaign resampling; seed repeats are not treated as independent campaigns",
    }
