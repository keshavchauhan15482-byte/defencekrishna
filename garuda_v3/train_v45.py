"""Strict forecasting entrypoint for the V45 evidence protocol.

The legacy/reproduction trainer remains available as ``garuda_v3.train``.
This entrypoint is the SIH forecasting path: common 10-second graph contract,
predeclared campaign split, untouched final test, validation-only calibration and
policy selection, four 10-second future horizons, residual decoding, state-first
training, unknown-label masking and no aggressive risk balancing.

CTU-13 is intentionally kept as a separate within-source evaluation path and may
not be mixed with CIC-IDS/CICAPT fitting in this entrypoint.
"""
from __future__ import annotations

import argparse
import json
import subprocess
import sys
from pathlib import Path
from typing import Any

from .data import load_dataset
from .forecast_hardening import (
    DEFAULT_HORIZONS_SECONDS,
    reserve_final_holdout,
    validate_campaign_split_manifest,
    validate_network_dataset_contract,
)


def preflight(graphs: list[str], split_manifest: str, reservation: str) -> dict[str, Any]:
    datasets = [load_dataset(path) for path in graphs]
    contract = validate_network_dataset_contract(datasets, expected_window_seconds=10)
    dataset_ids = [d["metadata"].get("dataset_id") for d in datasets]
    if "CTU-13" in dataset_ids and any(dataset_id != "CTU-13" for dataset_id in dataset_ids):
        raise ValueError("CTU-13 must remain a separate evaluation/training pipeline; do not mix it with CIC sources")
    manifest = json.loads(Path(split_manifest).read_text())
    split = validate_campaign_split_manifest(manifest, datasets)
    final_ids = set(manifest["test"])
    final_hashes = [
        d["metadata"]["source_sha256"]
        for d in datasets
        if d["metadata"]["campaign_id"] in final_ids
    ]
    frozen = reserve_final_holdout(
        reservation,
        campaign_ids=final_ids,
        source_hashes=final_hashes,
    )
    return {
        "contract": contract,
        "split": split,
        "dataset_ids": dataset_ids,
        "ctu13_policy": "separate_pipeline_only",
        "final_holdout_reservation": frozen,
        "horizons_seconds": list(DEFAULT_HORIZONS_SECONDS),
    }


def build_train_command(args: argparse.Namespace) -> list[str]:
    command = [
        sys.executable,
        "-m",
        "garuda_v3.train_v45_core",
        "--graphs",
        *args.graphs,
        "--output",
        args.output,
        "--state-epochs",
        str(args.state_epochs),
        "--risk-epochs",
        str(args.risk_epochs),
        "--stage-epochs",
        str(args.stage_epochs),
        "--patience",
        str(args.patience),
        "--history",
        "8",
        "--horizon",
        "4",
        "--stride",
        str(args.stride),
        "--seed",
        str(args.seed),
        "--fpr-budget",
        "0.01",
        "--split-manifest",
        args.split_manifest,
    ]
    if args.stage_supervision:
        command.append("--stage-supervision")
    return command


def _post_training_statistics(args: argparse.Namespace, out: Path) -> None:
    for architecture in ("lstm", "gnn_lstm"):
        prediction_path = out / f"{architecture}_test_predictions.npz"
        if not prediction_path.exists():
            continue
        command = [
            sys.executable,
            "-m",
            "garuda_v3.v45_statistics",
            "--graphs",
            *args.graphs,
            "--split-manifest",
            args.split_manifest,
            "--predictions",
            str(prediction_path),
            "--metrics",
            str(out / "metrics.json"),
            "--architecture",
            architecture,
            "--output",
            str(out / f"{architecture}_statistics.json"),
        ]
        subprocess.run(command, check=True)


def _align_verified_incidents(args: argparse.Namespace, out: Path) -> dict[str, str]:
    if not args.verified_manifests:
        return {}
    aligned = {}
    for architecture, cli_name in (("lstm", "lstm"), ("gnn_lstm", "gnn")):
        prediction_path = out / f"{architecture}_test_predictions.npz"
        if not prediction_path.exists():
            continue
        destination = out / f"{architecture}_verified_incidents.json"
        command = [
            sys.executable,
            "-m",
            "garuda_v3.v45_incident_alignment",
            "--graphs",
            *args.graphs,
            "--predictions",
            str(prediction_path),
            "--metrics",
            str(out / "metrics.json"),
            "--verified-manifests",
            *args.verified_manifests,
            "--architecture",
            architecture,
            "--output",
            str(destination),
        ]
        subprocess.run(command, check=True)
        aligned[cli_name] = str(destination)
    return aligned


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--graphs", nargs="+", required=True)
    parser.add_argument("--split-manifest", required=True)
    parser.add_argument("--reservation", required=True, help="Immutable final-holdout reservation JSON")
    parser.add_argument("--output", required=True)
    parser.add_argument("--state-epochs", type=int, default=40)
    parser.add_argument("--risk-epochs", type=int, default=30)
    parser.add_argument("--stage-epochs", type=int, default=30)
    parser.add_argument("--patience", type=int, default=10)
    parser.add_argument("--stride", type=int, default=2)
    parser.add_argument("--seed", type=int, default=42)
    parser.add_argument("--stage-supervision", action="store_true")
    parser.add_argument("--verified-manifests", nargs="+", help="Independent verified campaign manifests used only after inference")
    args = parser.parse_args()
    for name in ("state_epochs", "risk_epochs", "stage_epochs", "patience"):
        if not 1 <= getattr(args, name) <= 300:
            parser.error(f"{name.replace('_', '-')} must be 1..300")
    if args.stride < 1:
        parser.error("stride must be positive")

    out = Path(args.output)
    if out.exists() and any(out.iterdir()):
        parser.error("Output must be empty; V45 never overwrites training evidence")

    protocol = preflight(args.graphs, args.split_manifest, args.reservation)
    subprocess.run(build_train_command(args), check=True)

    protocol_path = out / "v45_protocol.json"
    protocol_path.write_text(json.dumps(protocol, indent=2, sort_keys=True) + "\n")
    _post_training_statistics(args, out)
    aligned = _align_verified_incidents(args, out)

    audit_command = [
        sys.executable,
        "-m",
        "garuda_v3.v45_forecast_audit",
        "--metrics",
        str(out / "metrics.json"),
        "--output",
        str(out / "v45_release_gate.json"),
        "--fpr-limit",
        "0.01",
        "--recall-floor",
        "0.80",
    ]
    if "lstm" in aligned:
        audit_command.extend(["--lstm-incidents", aligned["lstm"]])
    if "gnn" in aligned:
        audit_command.extend(["--gnn-incidents", aligned["gnn"]])
    subprocess.run(audit_command, check=True)


if __name__ == "__main__":
    main()
