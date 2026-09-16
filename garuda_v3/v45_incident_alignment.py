"""Align frozen V45 network forecasts to independently verified compromise events.

The verified timeline is used only after inference as evaluation ground truth. It
is never passed to the model. First-warning timestamps come from saved calibrated
network-only probabilities and the validation-selected threshold.
"""
from __future__ import annotations

import argparse
import json
import math
from pathlib import Path
from typing import Any, Sequence

import numpy as np

from .data import load_dataset
from .verified_campaigns import benign_covers, load_manifest

SCHEMA = "krishna-v45-verified-incident-alignment-v1"


def align_one_event(
    *,
    dataset: dict[str, Any],
    source_index: int,
    example_indices: np.ndarray,
    probabilities: np.ndarray,
    history_clean: np.ndarray,
    threshold: float | None,
    history: int,
    horizon: int,
    manifest: dict[str, Any],
    event: dict[str, Any],
) -> dict[str, Any]:
    compromise = float(event["epoch"])
    window = int(dataset["metadata"]["window_seconds"])
    eligible = []
    alerts = []
    for row, (source, start) in enumerate(example_indices):
        if int(source) != source_index or not bool(history_clean[row]):
            continue
        start = int(start)
        cutoff = float(dataset["times"][start + history - 1]) + window
        lead = compromise - cutoff
        if not (0 < lead <= horizon * window):
            continue
        history_start = cutoff - history * window
        if not benign_covers(manifest, history_start, cutoff):
            continue
        steps = min(horizon, max(1, int(math.ceil(lead / window))))
        score = float(np.max(probabilities[row, :steps]))
        eligible.append({"cutoff_epoch": cutoff, "lead_seconds": lead, "score": score, "horizon_steps": steps})
        if threshold is not None and score >= threshold:
            alerts.append(cutoff)
    first_warning = min(alerts) if alerts else None
    return {
        "campaign_id": manifest["campaign_id"],
        "event_id": event["event_id"],
        "stage": event["stage"],
        "outcome": event["outcome"],
        "establishes_compromise": True,
        "evidence": event["evidence"],
        "compromise_epoch": compromise,
        "first_warning_epoch": first_warning,
        "lead_seconds": compromise - first_warning if first_warning is not None else None,
        "eligible_clean_history_forecasts": len(eligible),
        "threshold": threshold,
        "warning_source": "saved calibrated network-only forecast probabilities",
        "timeline_role": "post-hoc evaluation ground truth only",
    }


def align(
    *,
    datasets: Sequence[dict[str, Any]],
    predictions: dict[str, np.ndarray],
    metrics: dict[str, Any],
    architecture: str,
    manifests: Sequence[dict[str, Any]],
) -> dict[str, Any]:
    if architecture not in {"lstm", "gnn_lstm"}:
        raise ValueError("Unsupported architecture")
    model = metrics.get("models", {}).get(architecture, {})
    policy = model.get("validation_alert_selection", {})
    threshold = policy.get("threshold")
    if threshold is not None:
        threshold = float(threshold)
    probabilities = np.asarray(predictions["probabilities"], dtype=float)
    example_indices = np.asarray(predictions["example_indices"], dtype=int)
    history_clean = np.asarray(predictions["history_clean"], dtype=bool)
    if probabilities.ndim != 2 or example_indices.shape != (len(probabilities), 2) or len(history_clean) != len(probabilities):
        raise ValueError("Prediction artifact shapes do not align")
    if not np.isfinite(probabilities).all() or np.any((probabilities < 0) | (probabilities > 1)):
        raise ValueError("Invalid forecast probabilities")

    history = int(metrics.get("config", {}).get("history", 8))
    horizon = int(metrics.get("config", {}).get("horizon", probabilities.shape[1]))
    if probabilities.shape[1] != horizon:
        raise ValueError("Prediction horizon differs from metrics protocol")

    by_identity = {}
    for index, dataset in enumerate(datasets):
        meta = dataset["metadata"]
        key = (meta.get("campaign_id"), meta.get("source_sha256"))
        if key in by_identity:
            raise ValueError("Duplicate campaign/hash identity")
        by_identity[key] = index

    incidents = []
    for manifest in manifests:
        key = (manifest["campaign_id"], manifest["capture_sha256"])
        if key not in by_identity:
            raise ValueError("Verified manifest does not match a supplied graph capture")
        source_index = by_identity[key]
        dataset = datasets[source_index]
        for event in manifest["events"]:
            if event.get("outcome") != "success" or not event.get("establishes_compromise"):
                continue
            incidents.append(
                align_one_event(
                    dataset=dataset,
                    source_index=source_index,
                    example_indices=example_indices,
                    probabilities=probabilities,
                    history_clean=history_clean,
                    threshold=threshold,
                    history=history,
                    horizon=horizon,
                    manifest=manifest,
                    event=event,
                )
            )
    return {
        "schema": SCHEMA,
        "architecture": architecture,
        "threshold": threshold,
        "threshold_source": "validation only",
        "runtime_evidence": "network-only",
        "verified_timeline_used_as_model_input": False,
        "incidents": incidents,
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--graphs", nargs="+", required=True)
    parser.add_argument("--predictions", required=True)
    parser.add_argument("--metrics", required=True)
    parser.add_argument("--verified-manifests", nargs="+", required=True)
    parser.add_argument("--architecture", choices=["lstm", "gnn_lstm"], required=True)
    parser.add_argument("--output", required=True)
    args = parser.parse_args()

    datasets = [load_dataset(path) for path in args.graphs]
    with np.load(args.predictions, allow_pickle=False) as z:
        predictions = {name: z[name] for name in ("probabilities", "example_indices", "history_clean")}
    metrics = json.loads(Path(args.metrics).read_text())
    manifests = [load_manifest(path) for path in args.verified_manifests]
    result = align(
        datasets=datasets,
        predictions=predictions,
        metrics=metrics,
        architecture=args.architecture,
        manifests=manifests,
    )
    out = Path(args.output)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n")
    print(json.dumps(result, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
