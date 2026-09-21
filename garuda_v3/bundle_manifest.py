"""Fail-closed resolver for the runtime artifact bundle.

The demo/runtime must never silently fall back to whichever artifact directory happens
to exist.  The checked-in manifest pins the active directory and the Git blob hashes of
all files needed by the integrated console.  ForecastService performs an additional
SHA-256 checkpoint verification from metrics.json after this directory-level gate.
"""
from __future__ import annotations

import hashlib
import json
from pathlib import Path

MANIFEST_NAME = "active_runtime_bundle.json"
MANIFEST_SCHEMA = 1


def git_blob_sha1(raw: bytes) -> str:
    header = f"blob {len(raw)}\0".encode("ascii")
    return hashlib.sha1(header + raw).hexdigest()


def load_manifest(root: Path) -> dict:
    root = Path(root).resolve()
    path = root / "garuda_v3" / MANIFEST_NAME
    if not path.is_file():
        raise RuntimeError(f"Active Garuda bundle manifest is missing: {path}")
    try:
        manifest = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise RuntimeError("Active Garuda bundle manifest is unreadable") from exc
    if manifest.get("schema_version") != MANIFEST_SCHEMA:
        raise RuntimeError("Unsupported Garuda runtime-bundle manifest schema")
    if manifest.get("status") != "validated-runtime-input":
        raise RuntimeError("Garuda bundle is not marked as validated runtime input")
    return manifest


def resolve_active_bundle(root: Path) -> Path:
    """Resolve and integrity-check the only bundle the runtime is allowed to use."""
    root = Path(root).resolve()
    manifest = load_manifest(root)
    relative = manifest.get("artifact_directory")
    if not isinstance(relative, str) or not relative:
        raise RuntimeError("Garuda bundle manifest has no artifact_directory")
    artifacts_root = (root / "garuda_v3" / "artifacts").resolve()
    bundle = (root / relative).resolve()
    try:
        bundle.relative_to(artifacts_root)
    except ValueError as exc:
        raise RuntimeError("Garuda artifact_directory escapes garuda_v3/artifacts") from exc
    if not bundle.is_dir():
        raise RuntimeError(f"Pinned Garuda artifact directory is missing: {bundle}")

    files = manifest.get("files")
    if not isinstance(files, dict) or not files:
        raise RuntimeError("Garuda bundle manifest contains no pinned files")
    required = {"gnn_lstm.npz", "metrics.json", "replay.json", "alert_replay.json"}
    if not required.issubset(files):
        missing = sorted(required - set(files))
        raise RuntimeError(f"Garuda bundle manifest is missing required files: {missing}")

    for name, expected in sorted(files.items()):
        if not isinstance(name, str) or Path(name).name != name:
            raise RuntimeError(f"Unsafe Garuda bundle file name: {name!r}")
        if not isinstance(expected, str) or len(expected) != 40:
            raise RuntimeError(f"Invalid Git blob hash for {name}")
        path = bundle / name
        if not path.is_file():
            raise RuntimeError(f"Pinned Garuda bundle file is missing: {name}")
        actual = git_blob_sha1(path.read_bytes())
        if actual != expected.lower():
            raise RuntimeError(f"Pinned Garuda bundle integrity mismatch: {name}")
    return bundle


def bundle_public_metadata(root: Path) -> dict:
    manifest = load_manifest(root)
    return {
        "bundle_id": manifest.get("bundle_id"),
        "model_lineage": manifest.get("model_lineage"),
        "artifact_directory": manifest.get("artifact_directory"),
        "claim_scope": manifest.get("claim_scope"),
        "manifest_schema": manifest.get("schema_version"),
    }
