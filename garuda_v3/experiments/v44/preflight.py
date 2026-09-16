"""Fail-closed V44 runtime dataset and split audit."""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import numpy as np

from garuda_v3.data import campaign_examples, load_dataset
from garuda_v3.experiments.v44.runtime_contract import (
    EVIDENCE_SCOPE, FEATURES, HISTORY, HORIZON, SCHEMA, WINDOW_SECONDS,
    assert_runtime_dataset,
)


def sha256(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def audit(root: Path) -> dict:
    split_path = root / "split.json"
    manifest = json.loads(split_path.read_text())
    expected = {"train", "validation", "test"}
    if set(manifest) != expected or any(not manifest[k] for k in expected):
        raise ValueError("V44 requires explicit non-empty train/validation/test campaign split")
    names = [name for key in ("train", "validation", "test") for name in manifest[key]]
    if len(names) != len(set(names)):
        raise ValueError("Campaign appears in more than one V44 split")

    paths = [root / "labelled" / f"{name}.npz" for name in names]
    if not all(path.exists() for path in paths):
        raise ValueError("Missing V44 labelled graph")
    datasets = [load_dataset(path) for path in paths]
    for d in datasets:
        assert_runtime_dataset(d)
        if d["metadata"].get("evidence_scope") != EVIDENCE_SCOPE:
            raise ValueError("Evidence scope must stay development_reused_holdout")
        if d["metadata"].get("campaign_id") not in names:
            raise ValueError("Missing/unknown campaign_id")
        if not np.isin(d["y"], [-1, 0, 1]).all():
            raise ValueError("Invalid label value")

    source_hashes = [d["metadata"]["source_sha256"] for d in datasets]
    if len(source_hashes) != len(set(source_hashes)):
        raise ValueError("Duplicate packet capture hash")

    examples, _ = campaign_examples(
        datasets, manifest, history=HISTORY, horizon=HORIZON, stride=8, allow_unknown=True
    )
    counts = []
    for split_examples in examples:
        known = positive = negative = 0
        for source, start in split_examples:
            future = datasets[source]["y"][start + HISTORY:start + HISTORY + HORIZON]
            target = 1 if (future == 1).any() else (0 if (future == 0).all() else -1)
            known += target >= 0
            positive += target == 1
            negative += target == 0
        counts.append({"examples": len(split_examples), "known_targets": known,
                       "positive_targets": positive, "negative_targets": negative})
    if counts[0]["positive_targets"] == 0 or counts[0]["negative_targets"] == 0:
        raise ValueError("Training split lacks both known target classes")
    if counts[1]["positive_targets"] == 0 or counts[1]["negative_targets"] == 0:
        raise ValueError("Validation split lacks both known target classes")

    return {
        "status": "pass",
        "schema": SCHEMA,
        "features": FEATURES,
        "window_seconds": WINDOW_SECONDS,
        "history_windows": HISTORY,
        "horizon_windows": HORIZON,
        "evidence_scope": EVIDENCE_SCOPE,
        "fresh_final_holdout": False,
        "runtime_schema_compatible": True,
        "network_only_feature_audit_passed": True,
        "automatic_containment_approved": False,
        "split": manifest,
        "split_counts": dict(zip(("train", "validation", "test"), counts)),
        "files": [{"path": str(p), "sha256": sha256(p)} for p in paths],
        "limitations": [
            "IDS2018 campaigns were used in earlier development; this is runtime-compatibility regression evidence, not a newly untouched final test.",
            "Labels are schedule-assisted weak supervision, not independently verified packet truth.",
            "No verified compromise timestamps; compromise lead time remains unmeasured.",
            "No supervised MITRE stage ground truth.",
        ],
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", default="datasets/v44_runtime")
    parser.add_argument("--output", default="garuda_v3/artifacts/v44_preflight.json")
    args = parser.parse_args()
    report = audit(Path(args.root))
    out = Path(args.output)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(report, indent=2))
    print(json.dumps(report, indent=2))


if __name__ == "__main__":
    main()
