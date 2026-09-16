"""Run the strict V45 protocol across predeclared seeds without best-seed promotion.

Seed repeats measure initialization sensitivity only; they are not independent
campaign evidence. The same frozen split/reservation is reused for every seed.
"""
from __future__ import annotations

import argparse
import json
import subprocess
import sys
from pathlib import Path

import numpy as np

DEFAULT_SEEDS = (42, 43, 44)


def _mean_sd(values):
    values = [float(v) for v in values if v is not None]
    return {
        "mean": float(np.mean(values)) if values else None,
        "sample_sd": float(np.std(values, ddof=1)) if len(values) > 1 else None,
        "values": values,
    }


def summarize(output: Path, seeds: list[int]):
    runs = {}
    for seed in seeds:
        folder = output / f"seed_{seed}"
        metrics = json.loads((folder / "metrics.json").read_text())
        release = json.loads((folder / "v45_release_gate.json").read_text())
        runs[str(seed)] = {"metrics": metrics, "release": release}

    summary = {
        "seeds": seeds,
        "interpretation": "seed sensitivity only; not independent campaign confidence",
        "best_seed_selected": False,
        "models": {},
    }
    for architecture in ("lstm", "gnn_lstm"):
        models = [runs[str(seed)]["metrics"]["models"][architecture] for seed in seeds]
        release_models = [runs[str(seed)]["release"]["models"][architecture] for seed in seeds]
        test_fpr = [m.get("test", {}).get("fpr") for m in models]
        test_recall = [m.get("test", {}).get("recall") for m in models]
        test_precision = [m.get("test", {}).get("precision") for m in models]
        test_f1 = [m.get("test", {}).get("f1") for m in models]
        summary["models"][architecture] = {
            "validation_state_mse": _mean_sd([m.get("validation_state_mse") for m in models]),
            "test_state_mse": _mean_sd([m.get("state_mse") for m in models]),
            "test_fpr": _mean_sd(test_fpr),
            "test_recall": _mean_sd(test_recall),
            "test_precision": _mean_sd(test_precision),
            "test_f1": _mean_sd(test_f1),
            "persistence_gate_passed_all_seeds": all(m.get("state_gate_passed", False) for m in models),
            "release_gate_passed_all_seeds": all(m.get("passed", False) for m in release_models),
            "per_seed_release_status": [m.get("status") for m in release_models],
        }
    return summary


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--graphs", nargs="+", required=True)
    parser.add_argument("--split-manifest", required=True)
    parser.add_argument("--reservation", required=True)
    parser.add_argument("--output", required=True)
    parser.add_argument("--seeds", nargs="+", type=int, default=list(DEFAULT_SEEDS))
    parser.add_argument("--state-epochs", type=int, default=40)
    parser.add_argument("--risk-epochs", type=int, default=30)
    parser.add_argument("--stage-epochs", type=int, default=30)
    parser.add_argument("--patience", type=int, default=10)
    parser.add_argument("--stride", type=int, default=2)
    parser.add_argument("--stage-supervision", action="store_true")
    parser.add_argument("--verified-manifests", nargs="+")
    args = parser.parse_args()
    if len(args.seeds) < 3 or len(set(args.seeds)) != len(args.seeds):
        parser.error("V45 multiseed requires at least three distinct predeclared seeds")

    output = Path(args.output)
    if output.exists() and any(output.iterdir()):
        parser.error("Output must be empty; multiseed evidence is immutable")
    output.mkdir(parents=True, exist_ok=True)
    config = {
        "seeds": args.seeds,
        "graphs": args.graphs,
        "split_manifest": args.split_manifest,
        "reservation": args.reservation,
        "best_seed_selection": False,
    }
    (output / "multiseed_protocol.json").write_text(json.dumps(config, indent=2, sort_keys=True) + "\n")

    for seed in args.seeds:
        command = [
            sys.executable,
            "-m",
            "garuda_v3.train_v45",
            "--graphs",
            *args.graphs,
            "--split-manifest",
            args.split_manifest,
            "--reservation",
            args.reservation,
            "--output",
            str(output / f"seed_{seed}"),
            "--state-epochs",
            str(args.state_epochs),
            "--risk-epochs",
            str(args.risk_epochs),
            "--stage-epochs",
            str(args.stage_epochs),
            "--patience",
            str(args.patience),
            "--stride",
            str(args.stride),
            "--seed",
            str(seed),
        ]
        if args.stage_supervision:
            command.append("--stage-supervision")
        if args.verified_manifests:
            command.extend(["--verified-manifests", *args.verified_manifests])
        subprocess.run(command, check=True)

    result = summarize(output, args.seeds)
    (output / "multiseed_summary.json").write_text(json.dumps(result, indent=2, sort_keys=True) + "\n")
    print(json.dumps(result, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
