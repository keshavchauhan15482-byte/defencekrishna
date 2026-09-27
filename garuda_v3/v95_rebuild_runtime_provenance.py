"""Reconstruct and pin V95 runtime-support provenance from the exact active graph inputs.

This is intentionally a provenance/support rebuild, not a model retrain and not a new
evaluation.  It replays the deterministic split configuration already recorded in the
active metrics, verifies source hashes and split counts, fits the support gate from
train + validation only, then integrity-pins the resulting support/provenance files.
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path

from .bundle_manifest import git_blob_sha1
from .data import build_examples, campaign_examples, development_examples, load_dataset
from .runtime_provenance import write_runtime_provenance


def _batch(datasets, indices, history, horizon):
    import numpy as np

    xs = []
    adjs = []
    masks = []
    ys = []
    targets = []
    ongoing = []
    for source, start in indices:
        d = datasets[source]
        stop = start + history
        xs.append(d["x"][start:stop])
        adjs.append(d["adj"][start:stop])
        masks.append(d["mask"][start:stop])
        future = d["x"][stop:stop + horizon]
        fm = d["mask"][stop:stop + horizon]
        targets.append((future * fm[:, :, None]).sum(axis=1) / np.maximum(fm.sum(axis=1, keepdims=True), 1))
        ys.append(d["y"][stop:stop + horizon])
        ongoing.append(bool(d["y"][start:stop].any()))
    return tuple(np.asarray(a, dtype=np.float32) for a in (xs, adjs, masks, targets, ys, ongoing))


def _load_json(path: Path) -> dict:
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise ValueError(f"Expected JSON object: {path}")
    return value


def rebuild(root: Path) -> dict:
    root = Path(root).resolve()
    runtime_path = root / "garuda_v3" / "active_runtime_bundle.json"
    runtime = _load_json(runtime_path)
    artifact_rel = runtime.get("artifact_directory")
    if artifact_rel != "garuda_v3/artifacts/residual_run":
        raise RuntimeError(f"Unexpected active artifact directory: {artifact_rel!r}")
    out = root / artifact_rel
    metrics_path = out / "metrics.json"
    metrics = _load_json(metrics_path)
    config = metrics.get("config")
    if not isinstance(config, dict):
        raise RuntimeError("Active metrics contain no training config")
    if config.get("evaluation_scope") != "development_reused_holdout":
        raise RuntimeError("V95 active-runtime provenance rebuild is only for the declared reused-development runtime")

    graph_paths = config.get("graphs")
    if not isinstance(graph_paths, list) or not graph_paths:
        raise RuntimeError("Active metrics do not declare graph inputs")
    datasets = [load_dataset(root / str(path)) for path in graph_paths]
    expected_hashes = [str(row.get("source_sha256")) for row in metrics.get("sources", [])]
    actual_hashes = [str(d["metadata"].get("source_sha256")) for d in datasets]
    if expected_hashes != actual_hashes:
        raise RuntimeError(f"Graph source lineage mismatch: expected={expected_hashes} actual={actual_hashes}")

    history = int(config["history"])
    horizon = int(config["horizon"])
    stride = int(config["stride"])
    split_manifest = config.get("split_manifest")
    allow_unknown = bool(config.get("allow_unknown_labels", False))
    if split_manifest:
        split_path = root / str(split_manifest)
        manifest = _load_json(split_path)
        splitter = development_examples if manifest.get("development") else campaign_examples
        splits, _boundaries = splitter(datasets, manifest, history, horizon, stride, allow_unknown=allow_unknown)
    else:
        splits, _boundaries = build_examples(datasets, history, horizon, stride)

    arrays = [_batch(datasets, split, history, horizon) for split in splits]
    reconstructed = [len(a[0]) for a in arrays]
    recorded = [int(row["examples"]) for row in metrics.get("split_counts", [])]
    if reconstructed != recorded:
        raise RuntimeError(f"Reconstructed split counts differ from active metrics: {reconstructed} != {recorded}")

    provenance = write_runtime_provenance(out, datasets, splits, arrays, history, horizon)
    expected_v95 = [456, 158, 160]
    if reconstructed != expected_v95:
        raise RuntimeError(f"Active split counts do not match V95 contract: {reconstructed} != {expected_v95}")

    files = runtime.get("files")
    if not isinstance(files, dict):
        raise RuntimeError("Active runtime manifest has no files map")
    files["support_gate.json"] = git_blob_sha1((out / "support_gate.json").read_bytes()) if False else None
    # bundle_manifest.git_blob_sha1 accepts raw bytes; keep hashing local to avoid path/bytes ambiguity.
    import hashlib
    def blob_sha(path: Path) -> str:
        raw = path.read_bytes()
        return hashlib.sha1(f"blob {len(raw)}\0".encode("ascii") + raw).hexdigest()
    files["support_gate.json"] = blob_sha(out / "support_gate.json")
    files["lineage_provenance.json"] = blob_sha(out / "lineage_provenance.json")
    runtime["files"] = files
    runtime["v95_runtime_support_provenance"] = {
        "status": "generated-from-recorded-active-split-config",
        "lineage_provenance": f"{artifact_rel}/lineage_provenance.json",
        "support_gate": f"{artifact_rel}/support_gate.json",
        "claim_boundary": "Runtime support provenance only; not a fresh holdout or pre-compromise certification.",
    }
    runtime_path.write_text(json.dumps(runtime, indent=2, allow_nan=False) + "\n", encoding="utf-8")

    certification_path = root / "garuda_v3" / "artifacts" / "certification" / "v95" / "runtime_lineage_manifest.json"
    certification_path.parent.mkdir(parents=True, exist_ok=True)
    certification = {
        "schema_version": 1,
        "runtime_bundle_manifest": "garuda_v3/active_runtime_bundle.json",
        "metrics": f"{artifact_rel}/metrics.json",
        "split_identities": provenance["split_identities"],
        "fit_provenance": {
            "support_statistics_fit_splits": ["train"],
            "support_threshold_selection_splits": ["validation"],
            "excluded_from_support_fit": ["test", "replay"],
            "support_gate_artifact": f"{artifact_rel}/support_gate.json",
            "lineage_provenance_artifact": f"{artifact_rel}/lineage_provenance.json",
        },
        "reconstruction": {
            "graph_inputs": graph_paths,
            "source_sha256": actual_hashes,
            "history": history,
            "horizon": horizon,
            "stride": stride,
            "split_manifest": split_manifest,
            "recorded_split_counts": recorded,
            "reconstructed_split_counts": reconstructed,
        },
        "claim_boundary": (
            "This certifies reproducible active-runtime split/support provenance only. The underlying evaluation remains "
            "a reused development holdout; this is not fresh external validation and not verified pre-compromise evidence."
        ),
    }
    certification_path.write_text(json.dumps(certification, indent=2, allow_nan=False) + "\n", encoding="utf-8")
    return certification


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", default=str(Path(__file__).resolve().parents[1]))
    args = parser.parse_args()
    result = rebuild(Path(args.root))
    print(json.dumps(result["reconstruction"], indent=2, allow_nan=False))


if __name__ == "__main__":
    main()
