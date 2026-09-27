"""Leakage-safe runtime provenance export for Garuda training runs.

This module records the exact example identities used by the trainer and fits the
runtime-support gate using train histories for robust statistics and validation
histories for the cutoff.  Test/replay arrays are never accepted by the support-fit
function, which makes the intended provenance explicit in code and in the emitted
artifact.
"""
from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any

from .support_gate import fit as fit_support_gate

SPLIT_NAMES = ("train", "validation", "test")


def _source_hash(dataset: dict[str, Any], source_index: int) -> str:
    metadata = dataset.get("metadata", {})
    value = metadata.get("source_sha256")
    return str(value) if value else f"source-index:{source_index}"


def example_identity(dataset: dict[str, Any], source_index: int, start: int, history: int, horizon: int) -> str:
    """Return a stable, non-secret identity for one sequence example."""
    metadata = dataset.get("metadata", {})
    times = dataset.get("times")
    cutoff = None
    if times is not None and len(times) > start + history - 1:
        cutoff = int(times[start + history - 1])
    payload = {
        "source_sha256": _source_hash(dataset, source_index),
        "campaign_id": str(metadata.get("campaign_id", "unannotated")),
        "start_index": int(start),
        "history": int(history),
        "horizon": int(horizon),
        "cutoff_unix": cutoff,
    }
    raw = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(raw).hexdigest()


def split_identities(datasets, splits, history: int, horizon: int) -> dict[str, list[str]]:
    if len(splits) != 3:
        raise ValueError("Expected exactly train/validation/test splits")
    result: dict[str, list[str]] = {}
    for name, rows in zip(SPLIT_NAMES, splits):
        ids = [example_identity(datasets[source], int(source), int(start), history, horizon) for source, start in rows]
        if len(ids) != len(set(ids)):
            raise ValueError(f"Duplicate example identities inside {name}")
        result[name] = ids
    for a, b in (("train", "validation"), ("train", "test"), ("validation", "test")):
        overlap = set(result[a]) & set(result[b])
        if overlap:
            raise ValueError(f"Split identity overlap between {a} and {b}: {len(overlap)}")
    return result


def write_runtime_provenance(out: Path, datasets, splits, arrays, history: int, horizon: int) -> dict[str, Any]:
    """Fit support from train/validation only and persist auditable lineage artifacts."""
    out = Path(out)
    if len(arrays) != 3:
        raise ValueError("Expected exactly train/validation/test arrays")
    train, validation, _test = arrays
    identities = split_identities(datasets, splits, history, horizon)

    gate = fit_support_gate(train[0], train[2], validation[0], validation[2])
    gate["schema_version"] = 1
    gate["fit_provenance"] = {
        "support_statistics_fit_splits": ["train"],
        "support_threshold_selection_splits": ["validation"],
        "excluded_from_support_fit": ["test", "replay"],
    }
    support_path = out / "support_gate.json"
    support_path.write_text(json.dumps(gate, indent=2, allow_nan=False) + "\n", encoding="utf-8")

    payload = {
        "schema_version": 1,
        "protocol": "Garuda runtime lineage provenance",
        "split_counts": {name: len(identities[name]) for name in SPLIT_NAMES},
        "split_identities": identities,
        "split_identity_sha256": {
            name: hashlib.sha256("\n".join(identities[name]).encode("utf-8")).hexdigest()
            for name in SPLIT_NAMES
        },
        "fit_provenance": {
            "support_statistics_fit_splits": ["train"],
            "support_threshold_selection_splits": ["validation"],
            "excluded_from_support_fit": ["test", "replay"],
            "support_gate_artifact": "support_gate.json",
        },
        "support_gate_sha256": hashlib.sha256(support_path.read_bytes()).hexdigest(),
        "claim_boundary": (
            "This artifact proves split identity and support-fit provenance only. It does not make a fresh-holdout, "
            "attack/OOD-detection, MITRE-stage, or verified pre-compromise claim."
        ),
    }
    (out / "lineage_provenance.json").write_text(
        json.dumps(payload, indent=2, allow_nan=False) + "\n", encoding="utf-8"
    )
    return payload
