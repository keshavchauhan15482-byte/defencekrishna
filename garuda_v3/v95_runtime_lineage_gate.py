"""V95 fail-closed certification gate for the active Garuda runtime lineage.

This module does not manufacture missing provenance.  It verifies the evidence needed
before a fitted runtime-support gate may be treated as certified:

* the active residual runtime has exactly 456/158/160 train/validation/test examples;
* concrete split identities exist and are pairwise disjoint;
* support statistics are fitted from train only;
* the support cutoff is selected from validation only;
* test/replay are absent from fitting and calibration provenance;
* an integrity-pinned support_gate.json is present in the active runtime bundle.

Any missing or contradictory evidence is SHADOW_UNRESOLVED.  Synthetic fixtures are
useful for unit-testing this verifier but are never certification evidence.
"""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
from typing import Any

EXPECTED_SPLIT_COUNTS = {"train": 456, "validation": 158, "test": 160}
FORBIDDEN_FIT_SPLITS = {"test", "replay"}
STATUS_PASS = "PASS"
STATUS_UNRESOLVED = "SHADOW_UNRESOLVED"


def _load_json(path: Path) -> dict[str, Any]:
    if not path.is_file():
        raise FileNotFoundError(str(path))
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise ValueError(f"Expected JSON object: {path}")
    return value


def git_blob_sha1(path: Path) -> str:
    raw = path.read_bytes()
    return hashlib.sha1(f"blob {len(raw)}\0".encode("ascii") + raw).hexdigest()


def _normalise_split_names(values: Any) -> list[str] | None:
    if not isinstance(values, list) or not all(isinstance(x, str) for x in values):
        return None
    return [x.strip().lower() for x in values]


def _extract_metric_counts(metrics: dict[str, Any]) -> dict[str, int] | None:
    rows = metrics.get("split_counts")
    if not isinstance(rows, list) or len(rows) != 3:
        return None
    try:
        return {
            "train": int(rows[0]["examples"]),
            "validation": int(rows[1]["examples"]),
            "test": int(rows[2]["examples"]),
        }
    except (KeyError, TypeError, ValueError):
        return None


def _identity_sets(raw: Any) -> tuple[dict[str, set[str]] | None, str | None]:
    if not isinstance(raw, dict):
        return None, "Concrete split identities are missing."
    out: dict[str, set[str]] = {}
    for split, expected in EXPECTED_SPLIT_COUNTS.items():
        ids = raw.get(split)
        if not isinstance(ids, list) or len(ids) != expected:
            return None, f"Split identities for {split} must contain exactly {expected} entries."
        as_text = [str(x) for x in ids]
        if len(set(as_text)) != len(as_text):
            return None, f"Duplicate identities exist inside {split}."
        out[split] = set(as_text)
    for a, b in (("train", "validation"), ("train", "test"), ("validation", "test")):
        overlap = out[a] & out[b]
        if overlap:
            return None, f"Split identity overlap detected between {a} and {b}: {len(overlap)} entries."
    return out, None


def evaluate(root: Path, certification: dict[str, Any]) -> dict[str, Any]:
    """Evaluate V95 evidence. Missing evidence is unresolved, never inferred."""
    root = Path(root).resolve()
    reasons: list[str] = []
    checks: dict[str, Any] = {}

    if certification.get("schema_version") != 1:
        reasons.append("Unsupported or missing V95 certification schema_version=1.")

    runtime_rel = certification.get("runtime_bundle_manifest", "garuda_v3/active_runtime_bundle.json")
    metrics_rel = certification.get("metrics", "garuda_v3/artifacts/residual_run/metrics.json")
    runtime_path = root / str(runtime_rel)
    metrics_path = root / str(metrics_rel)

    try:
        runtime = _load_json(runtime_path)
    except Exception as exc:
        runtime = {}
        reasons.append(f"Runtime bundle manifest unavailable: {type(exc).__name__}: {exc}")
    try:
        metrics = _load_json(metrics_path)
    except Exception as exc:
        metrics = {}
        reasons.append(f"Runtime metrics unavailable: {type(exc).__name__}: {exc}")

    counts = _extract_metric_counts(metrics)
    checks["split_counts"] = counts
    if counts != EXPECTED_SPLIT_COUNTS:
        reasons.append(f"Runtime split counts differ from required {EXPECTED_SPLIT_COUNTS}: {counts}")

    scope = metrics.get("evaluation_scope") or metrics.get("config", {}).get("evaluation_scope")
    checks["evaluation_scope"] = scope
    if scope != "development_reused_holdout":
        reasons.append(f"Unexpected active-runtime evaluation scope: {scope!r}")

    identities, identity_error = _identity_sets(certification.get("split_identities"))
    checks["split_identities_present_and_disjoint"] = identity_error is None
    if identity_error:
        reasons.append(identity_error)

    provenance = certification.get("fit_provenance")
    if not isinstance(provenance, dict):
        provenance = {}
    stats_splits = _normalise_split_names(provenance.get("support_statistics_fit_splits"))
    threshold_splits = _normalise_split_names(provenance.get("support_threshold_selection_splits"))
    checks["support_statistics_fit_splits"] = stats_splits
    checks["support_threshold_selection_splits"] = threshold_splits

    if stats_splits != ["train"]:
        reasons.append("Support-statistics provenance must explicitly be train-only.")
    if threshold_splits != ["validation"]:
        reasons.append("Support-threshold provenance must explicitly be validation-only.")
    for label, values in (("support statistics", stats_splits), ("support threshold", threshold_splits)):
        if values is not None and FORBIDDEN_FIT_SPLITS.intersection(values):
            reasons.append(f"Forbidden test/replay leakage declared in {label} provenance.")

    files = runtime.get("files") if isinstance(runtime, dict) else None
    pinned_gate = isinstance(files, dict) and isinstance(files.get("support_gate.json"), str)
    checks["support_gate_pinned"] = bool(pinned_gate)
    artifact_dir = runtime.get("artifact_directory") if isinstance(runtime, dict) else None
    gate_path = root / str(artifact_dir) / "support_gate.json" if isinstance(artifact_dir, str) else None
    if not pinned_gate:
        reasons.append("active_runtime_bundle.json does not integrity-pin support_gate.json.")
    elif gate_path is None or not gate_path.is_file():
        reasons.append("Pinned support_gate.json is missing from the active artifact directory.")
    else:
        expected_blob = str(files["support_gate.json"]).lower()
        actual_blob = git_blob_sha1(gate_path)
        checks["support_gate_git_blob_sha1"] = actual_blob
        if expected_blob != actual_blob:
            reasons.append("support_gate.json Git-blob integrity mismatch.")

    declared_gate_path = provenance.get("support_gate_artifact")
    if not isinstance(declared_gate_path, str) or not declared_gate_path:
        reasons.append("Fitted support-gate artifact provenance is not declared.")
    else:
        declared = (root / declared_gate_path).resolve()
        checks["declared_support_gate_artifact"] = str(declared.relative_to(root)) if root in declared.parents else str(declared)
        if gate_path is None or declared != gate_path.resolve():
            reasons.append("Declared support-gate provenance does not point to the active pinned runtime gate.")

    # The legacy metrics selection statement is useful corroboration for the model
    # checkpoint/decision threshold but does not substitute for support-gate provenance.
    selection = metrics.get("selection")
    checks["legacy_model_selection_statement"] = selection
    if not isinstance(selection, str) or "test not used" not in selection.lower():
        reasons.append("Active metrics do not explicitly state that test was excluded from model selection.")

    status = STATUS_PASS if not reasons else STATUS_UNRESOLVED
    return {
        "protocol": "V95 active-runtime lineage and support-fit certification",
        "status": status,
        "certified_for_autonomous_forecast_response": status == STATUS_PASS,
        "expected_split_counts": EXPECTED_SPLIT_COUNTS,
        "checks": checks,
        "reasons": reasons,
        "claim_boundary": (
            "PASS certifies provenance of the runtime support gate only; it is not attack/OOD detection, "
            "not a fresh-holdout result, and not verified pre-compromise evidence."
        ),
    }


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--root", default=str(Path(__file__).resolve().parents[1]))
    ap.add_argument(
        "--certification",
        default="garuda_v3/artifacts/certification/v95/runtime_lineage_manifest.json",
    )
    ap.add_argument("--output", default=None)
    ap.add_argument("--require-pass", action="store_true", help="Exit non-zero unless the real evidence is PASS")
    args = ap.parse_args()

    root = Path(args.root).resolve()
    certification = _load_json(root / args.certification)
    report = evaluate(root, certification)
    text = json.dumps(report, indent=2, allow_nan=False) + "\n"
    if args.output:
        out = Path(args.output)
        if not out.is_absolute():
            out = root / out
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(text, encoding="utf-8")
    print(text, end="")
    if args.require_pass and report["status"] != STATUS_PASS:
        raise SystemExit(2)


if __name__ == "__main__":
    main()
