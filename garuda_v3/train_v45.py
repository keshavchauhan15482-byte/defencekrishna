"""Strict forecasting entrypoint for the V45 evidence protocol.

The legacy/reproduction trainer remains available as ``garuda_v3.train``.
This entrypoint is the SIH forecasting path: common 10-second graph contract,
predeclared campaign split, untouched final test, validation-only calibration and
policy selection, four 10-second future horizons, residual decoder, unknown-label
masking and no aggressive risk balancing.
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
        "final_holdout_reservation": frozen,
        "horizons_seconds": list(DEFAULT_HORIZONS_SECONDS),
    }


def build_train_command(args: argparse.Namespace) -> list[str]:
    command = [
        sys.executable,
        "-m",
        "garuda_v3.train",
        "--graphs",
        *args.graphs,
        "--output",
        args.output,
        "--epochs",
        str(args.epochs),
        "--history",
        "8",
        "--horizon",
        "4",
        "--stride",
        str(args.stride),
        "--seed",
        str(args.seed),
        "--decoder",
        "residual",
        "--allow-unknown-labels",
        "--calibrate",
        "--fpr-budget",
        "0.01",
        "--split-manifest",
        args.split_manifest,
        "--evaluation-scope",
        "new_predeclared_holdout",
    ]
    if args.stage_supervision:
        command.append("--stage-supervision")
    return command


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--graphs", nargs="+", required=True)
    parser.add_argument("--split-manifest", required=True)
    parser.add_argument("--reservation", required=True, help="Immutable final-holdout reservation JSON")
    parser.add_argument("--output", required=True)
    parser.add_argument("--epochs", type=int, default=40)
    parser.add_argument("--stride", type=int, default=2)
    parser.add_argument("--seed", type=int, default=42)
    parser.add_argument("--stage-supervision", action="store_true")
    parser.add_argument("--verified-incidents", help="Optional independently verified incident JSON for post-training audit")
    args = parser.parse_args()
    if not 1 <= args.epochs <= 300:
        parser.error("epochs must be 1..300")
    if args.stride < 1:
        parser.error("stride must be positive")

    out = Path(args.output)
    if out.exists() and any(out.iterdir()):
        parser.error("Output must be empty; V45 never overwrites training evidence")

    protocol = preflight(args.graphs, args.split_manifest, args.reservation)
    subprocess.run(build_train_command(args), check=True)

    # Write the immutable preflight protocol only after the underlying trainer has
    # created its evidence directory; writing it before training would violate the
    # trainer's intentional empty-output guard.
    protocol_path = out / "v45_protocol.json"
    protocol_path.write_text(json.dumps(protocol, indent=2, sort_keys=True) + "\n")

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
    if args.verified_incidents:
        audit_command.extend(["--verified-incidents", args.verified_incidents])
    subprocess.run(audit_command, check=True)


if __name__ == "__main__":
    main()
