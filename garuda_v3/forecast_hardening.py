"""Forecast-specific evidence gates for Krishna Defence.

This module is intentionally conservative. It does not improve model scores by
itself; it prevents unsupported data, exposed holdouts, persistence-level state
forecasts, weak family support, or unverified incident timing from being turned
into an actionable forecasting claim.

Runtime decisions remain network-only. Verified campaign timelines are ground
truth for training/evaluation only and are never model inputs.
"""
from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any, Iterable, Mapping, Sequence

import numpy as np

from .data import FEATURES, SCHEMA

CONTRACT_SCHEMA = "krishna-forecast-evidence-v45"
DEFAULT_HORIZONS_SECONDS = (10, 20, 30, 40)


def _is_sha256(value: Any) -> bool:
    if not isinstance(value, str) or len(value) != 64:
        return False
    try:
        int(value, 16)
        return True
    except ValueError:
        return False


def validate_network_dataset_contract(
    datasets: Sequence[Mapping[str, Any]],
    *,
    expected_window_seconds: int | None = None,
) -> dict[str, Any]:
    """Validate the common graph/data contract without inventing missing evidence."""
    if not datasets:
        raise ValueError("At least one dataset is required")

    contracts = set()
    hashes: list[str] = []
    campaigns: list[str] = []
    for d in datasets:
        meta = d.get("metadata", {})
        if meta.get("schema") != SCHEMA:
            raise ValueError("Feature schema mismatch")
        if list(meta.get("features", [])) != list(FEATURES):
            raise ValueError("Feature order mismatch")
        mode = meta.get("mode")
        if mode not in {"service", "host"}:
            raise ValueError("Graph mode must be service or host")
        window = meta.get("window_seconds")
        if not isinstance(window, int) or window <= 0:
            raise ValueError("window_seconds must be a positive integer")
        if expected_window_seconds is not None and window != expected_window_seconds:
            raise ValueError(
                f"Expected {expected_window_seconds}s windows, got {window}s"
            )
        max_nodes = meta.get("max_nodes")
        if not isinstance(max_nodes, int) or max_nodes <= 0:
            raise ValueError("max_nodes must be a positive integer")
        source_hash = meta.get("source_sha256")
        if not _is_sha256(source_hash):
            raise ValueError("Every capture needs a valid source_sha256")
        if source_hash in hashes:
            raise ValueError("Duplicate source capture hash")
        hashes.append(source_hash)
        campaign = meta.get("campaign_id")
        if not isinstance(campaign, str) or not campaign.strip():
            raise ValueError("Every capture needs an explicit campaign_id")
        campaigns.append(campaign)
        if "times" not in d or len(d["times"]) != len(d.get("y", [])):
            raise ValueError("Times and labels must be aligned")
        if not np.isin(np.asarray(d["y"]), [-1, 0, 1]).all():
            raise ValueError("Labels must use -1 unknown / 0 benign / 1 malicious")
        contracts.add((mode, window, max_nodes, tuple(meta.get("features", []))))

    if len(contracts) != 1:
        raise ValueError("Do not mix graph contracts in one training run")

    mode, window, max_nodes, _ = next(iter(contracts))
    return {
        "schema": CONTRACT_SCHEMA,
        "graph_schema": SCHEMA,
        "features": list(FEATURES),
        "mode": mode,
        "window_seconds": window,
        "max_nodes": max_nodes,
        "source_hashes": hashes,
        "campaigns": campaigns,
        "runtime_evidence": "network-only",
        "unknown_label_semantics": "unknown is never benign",
    }


def validate_campaign_split_manifest(
    manifest: Mapping[str, Any], datasets: Sequence[Mapping[str, Any]]
) -> dict[str, Any]:
    """Require disjoint campaign-level train/validation/test partitions.

    The test partition is the untouched final evaluation for this experiment.
    Thresholds, calibration, normalization and class weighting must be derived
    without using it.
    """
    required = ("train", "validation", "test")
    if any(not manifest.get(name) for name in required):
        raise ValueError("Forecast hardening requires train/validation/test campaigns")

    assignments: dict[str, str] = {}
    for name in required:
        for campaign in manifest[name]:
            if not isinstance(campaign, str) or not campaign.strip():
                raise ValueError("Invalid campaign ID")
            if campaign in assignments:
                raise ValueError("Campaign cannot appear in multiple partitions")
            assignments[campaign] = name

    actual = {d["metadata"].get("campaign_id") for d in datasets}
    if set(assignments) != actual:
        raise ValueError("Split manifest must assign every and only supplied campaign")

    return {
        "schema": CONTRACT_SCHEMA,
        "method": "campaign-level predeclared holdout",
        "assignment": {name: list(manifest[name]) for name in required},
        "test_is_final_holdout": True,
        "test_used_for_fit": False,
    }


def reserve_final_holdout(
    path: str | Path,
    *,
    campaign_ids: Iterable[str],
    source_hashes: Iterable[str],
) -> dict[str, Any]:
    """Freeze a final holdout reservation once; refuse silent replacement."""
    p = Path(path)
    campaigns = sorted(set(campaign_ids))
    hashes = sorted(set(source_hashes))
    if not campaigns or not hashes or not all(_is_sha256(h) for h in hashes):
        raise ValueError("Valid final-holdout campaigns and hashes are required")
    payload = {
        "schema": CONTRACT_SCHEMA,
        "final_test_campaigns": campaigns,
        "source_hashes": hashes,
    }
    encoded = json.dumps(payload, indent=2, sort_keys=True) + "\n"
    payload["reservation_sha256"] = hashlib.sha256(encoded.encode()).hexdigest()
    if p.exists():
        existing = json.loads(p.read_text())
        if existing != payload:
            raise FileExistsError("Final holdout already frozen with different evidence")
        return existing
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n")
    return payload


def multi_horizon_targets(labels: np.ndarray, horizons: Sequence[int] | None = None) -> np.ndarray:
    """Build any-attack targets while preserving unknown future coverage.

    1 = at least one known malicious window in the horizon.
    0 = every window in the horizon is explicitly known benign.
    -1 = otherwise (missing/unknown evidence).
    """
    labels = np.asarray(labels)
    if labels.ndim != 2 or not np.isin(labels, [-1, 0, 1]).all():
        raise ValueError("Expected [examples, future_windows] labels in {-1,0,1}")
    horizons = tuple(horizons or range(1, labels.shape[1] + 1))
    if not horizons or any(not isinstance(h, (int, np.integer)) or h < 1 or h > labels.shape[1] for h in horizons):
        raise ValueError("Invalid horizon steps")
    out = []
    for h in horizons:
        part = labels[:, : int(h)]
        out.append(np.where((part == 1).any(axis=1), 1, np.where((part == 0).all(axis=1), 0, -1)))
    return np.stack(out, axis=1).astype(np.int8)


def persistence_gate(
    learned_validation_mse: float,
    persistence_validation_mse: float,
    *,
    minimum_relative_improvement: float = 0.0,
) -> dict[str, Any]:
    """Reject a state forecaster that does not beat persistence on validation."""
    learned = float(learned_validation_mse)
    baseline = float(persistence_validation_mse)
    if not np.isfinite([learned, baseline]).all() or baseline <= 0:
        raise ValueError("Finite positive validation MSE values required")
    relative = (baseline - learned) / baseline
    passed = relative > float(minimum_relative_improvement)
    return {
        "passed": bool(passed),
        "learned_validation_mse": learned,
        "persistence_validation_mse": baseline,
        "relative_improvement": float(relative),
        "minimum_relative_improvement": float(minimum_relative_improvement),
        "status": "accepted" if passed else "rejected_not_better_than_persistence",
    }


def family_release_gate(
    family_report: Mapping[str, Mapping[str, Any]],
    *,
    fpr_limit: float = 0.01,
    recall_floor: float = 0.80,
    min_positives: int = 20,
    min_negatives: int = 20,
) -> dict[str, Any]:
    """Evaluate, never tune, the frozen policy on each held-out family."""
    if not 0 <= fpr_limit < 1 or not 0 < recall_floor <= 1:
        raise ValueError("Invalid release limits")
    if min(min_positives, min_negatives) < 1:
        raise ValueError("Minimum support must be positive")
    per_family: dict[str, Any] = {}
    for family, report in family_report.items():
        pos = int(report.get("positives", 0))
        neg = int(report.get("negatives", 0))
        fpr = report.get("fpr")
        recall = report.get("recall")
        support = pos >= min_positives and neg >= min_negatives
        passed = bool(
            support
            and report.get("policy_enabled")
            and fpr is not None
            and recall is not None
            and float(fpr) <= fpr_limit
            and float(recall) >= recall_floor
        )
        per_family[family] = {
            "passed": passed,
            "support_passed": support,
            "positives": pos,
            "negatives": neg,
            "fpr": fpr,
            "recall": recall,
            "reason": "passed" if passed else (
                "insufficient_support" if not support else "metric_gate_failed"
            ),
        }
    all_passed = bool(per_family) and all(v["passed"] for v in per_family.values())
    return {
        "passed": all_passed,
        "fpr_limit": fpr_limit,
        "recall_floor": recall_floor,
        "min_positives": min_positives,
        "min_negatives": min_negatives,
        "per_family": per_family,
    }


def lead_time_summary(
    compromise_epochs: Sequence[float],
    first_warning_epochs: Sequence[float | None],
    *,
    seed: int = 42,
    bootstrap_samples: int = 2000,
) -> dict[str, Any]:
    """Summarize verified pre-compromise lead time at incident/campaign level."""
    if len(compromise_epochs) != len(first_warning_epochs):
        raise ValueError("Compromise and warning arrays must align")
    lead = []
    warned = 0
    for compromise, warning in zip(compromise_epochs, first_warning_epochs):
        compromise = float(compromise)
        if warning is None:
            continue
        warning = float(warning)
        if warning < compromise:
            warned += 1
            lead.append(compromise - warning)
    total = len(compromise_epochs)
    result: dict[str, Any] = {
        "verified_incidents": total,
        "warned_before_compromise": warned,
        "pre_compromise_warning_rate": warned / total if total else None,
        "lead_seconds": lead,
        "median_lead_seconds": float(np.median(lead)) if lead else None,
        "q25_lead_seconds": float(np.quantile(lead, 0.25)) if lead else None,
        "q75_lead_seconds": float(np.quantile(lead, 0.75)) if lead else None,
        "minimum_lead_seconds": float(min(lead)) if lead else None,
        "interpretation": "verified compromise timestamps only; missing warnings remain misses",
    }
    if len(lead) >= 5 and bootstrap_samples > 0:
        rng = np.random.default_rng(seed)
        medians = [float(np.median(rng.choice(lead, size=len(lead), replace=True))) for _ in range(bootstrap_samples)]
        result["median_lead_95pct_bootstrap_interval"] = [
            float(np.quantile(medians, 0.025)),
            float(np.quantile(medians, 0.975)),
        ]
        result["bootstrap_unit"] = "verified incident"
    else:
        result["median_lead_95pct_bootstrap_interval"] = None
    return result


def abstention_status(
    *,
    contract_valid: bool,
    policy_enabled: bool,
    persistence_passed: bool,
    supported_family: bool,
    in_distribution: bool = True,
) -> dict[str, Any]:
    reasons = []
    if not contract_valid:
        reasons.append("data_contract_failed")
    if not policy_enabled:
        reasons.append("policy_not_validated")
    if not persistence_passed:
        reasons.append("state_forecast_not_better_than_persistence")
    if not supported_family:
        reasons.append("family_support_insufficient")
    if not in_distribution:
        reasons.append("out_of_distribution")
    return {
        "status": "forecast_supported" if not reasons else "insufficient_evidence",
        "abstain": bool(reasons),
        "reasons": reasons,
    }
