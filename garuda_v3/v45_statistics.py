"""Build V45 coverage/abstention and campaign-bootstrap statistics.

This report is descriptive and does not retune a model. The feature envelope is
fitted on training traffic, its support threshold on validation traffic, and test
is evaluated once. Both unconditional and supported-coverage metrics are kept.
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path

import numpy as np

from .calibration import future_target
from .data import campaign_examples, load_dataset
from .forecast_statistics import campaign_bootstrap, fit_support_envelope, support_report
from .train import batch, metrics


def build_report(graphs, split_manifest, predictions_path, metrics_path, architecture):
    datasets = [load_dataset(path) for path in graphs]
    manifest = json.loads(Path(split_manifest).read_text())
    training_report = json.loads(Path(metrics_path).read_text())
    config = training_report.get("config", {})
    history = int(config.get("history", 8))
    horizon = int(config.get("horizon", 4))
    stride = int(config.get("stride", 2))
    if history != 8 or horizon != 4 or stride < 1:
        raise ValueError("Metrics do not describe the frozen V45 sequence protocol")
    splits, _ = campaign_examples(
        datasets, manifest, history, horizon, stride, allow_unknown=True
    )
    train, valid, test = [
        batch(datasets, split, history, horizon) for split in splits
    ]
    envelope = fit_support_envelope(train[0], train[2], valid[0], valid[2])
    support = support_report(test[0], test[2], envelope)

    with np.load(predictions_path, allow_pickle=False) as z:
        probabilities = z["probabilities"]
        labels = z["labels"]
        saved_indices = z["example_indices"]
    expected_indices = np.asarray(splits[2], dtype=int)
    if saved_indices.shape != expected_indices.shape or not np.array_equal(saved_indices, expected_indices):
        raise ValueError("Prediction examples do not match the frozen test split")

    model = training_report["models"][architecture]
    threshold = model.get("validation_alert_selection", {}).get("threshold")
    target = future_target(labels)
    known = target >= 0
    scores = probabilities.max(axis=1)
    supported_known = known & support["supported"]
    threshold_for_metrics = threshold if threshold is not None else 1.000001

    return {
        "architecture": architecture,
        "sequence_protocol": {
            "history": history,
            "horizon": horizon,
            "stride": stride,
        },
        "support_envelope": envelope,
        "coverage": support["summary"],
        "unconditional_known_test": metrics(target[known], scores[known], threshold_for_metrics),
        "supported_known_test": metrics(target[supported_known], scores[supported_known], threshold_for_metrics),
        "campaign_bootstrap_all_known": campaign_bootstrap(
            datasets,
            splits[2],
            labels,
            probabilities,
            threshold,
            seed=int(config.get("seed", 42)),
        ),
        "campaign_bootstrap_supported": campaign_bootstrap(
            datasets,
            splits[2],
            labels,
            probabilities,
            threshold,
            supported=support["supported"],
            seed=int(config.get("seed", 42)),
        ),
        "runtime_fallback": "unsupported distribution-support examples => insufficient evidence / abstain",
        "caveat": "support envelope is a descriptive distribution-shift guard, not a generic OOD detector",
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--graphs", nargs="+", required=True)
    parser.add_argument("--split-manifest", required=True)
    parser.add_argument("--predictions", required=True)
    parser.add_argument("--metrics", required=True)
    parser.add_argument("--architecture", choices=["lstm", "gnn_lstm"], required=True)
    parser.add_argument("--output", required=True)
    args = parser.parse_args()
    result = build_report(
        args.graphs,
        args.split_manifest,
        args.predictions,
        args.metrics,
        args.architecture,
    )
    Path(args.output).write_text(json.dumps(result, indent=2, sort_keys=True) + "\n")
    print(json.dumps(result, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
