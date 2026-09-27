"""Strict validator for evidence-backed warning-before-successful-compromise claims.

This validator never infers compromise from attack onset, attack step, tactic, or a
positive class label. PASS requires a model-emitted warning, an explicitly objective
successful-compromise event for the same campaign, complete campaign-disjointness
provenance, timezone-aware timestamps, raw artifact hashes, and positive lead time.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

SHA256_RE = re.compile(r"^[0-9a-f]{64}$")


class EvidenceError(ValueError):
    pass


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for block in iter(lambda: f.read(1024 * 1024), b""):
            h.update(block)
    return h.hexdigest()


def load_json(path: Path) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except Exception as exc:
        raise EvidenceError(f"Invalid JSON: {path}: {exc}") from exc
    if not isinstance(value, dict):
        raise EvidenceError(f"Top-level JSON object required: {path}")
    return value


def parse_time(value: Any, field: str) -> datetime:
    if not isinstance(value, str) or not value.strip():
        raise EvidenceError(f"{field} must be a non-empty ISO-8601 string")
    text = value.strip().replace("Z", "+00:00")
    try:
        dt = datetime.fromisoformat(text)
    except ValueError as exc:
        raise EvidenceError(f"{field} is not valid ISO-8601: {value}") from exc
    if dt.tzinfo is None or dt.utcoffset() is None:
        raise EvidenceError(f"{field} must include timezone/UTC offset")
    return dt.astimezone(timezone.utc)


def require_campaign(value: Any, field: str = "campaign_id") -> str:
    if not isinstance(value, str) or not value.strip():
        raise EvidenceError(f"{field} must be a non-empty string")
    return value.strip()


def validate_warning(event: dict[str, Any]) -> tuple[str, datetime, str]:
    if event.get("event_type") != "model_warning":
        raise EvidenceError("warning event_type must equal 'model_warning'")
    if event.get("emitted_by_model") is not True:
        raise EvidenceError("warning must set emitted_by_model=true")
    campaign = require_campaign(event.get("campaign_id"))
    when = parse_time(event.get("timestamp"), "warning.timestamp")
    model_hash = str(event.get("model_sha256", "")).lower()
    if not SHA256_RE.fullmatch(model_hash):
        raise EvidenceError("warning.model_sha256 must be a lowercase 64-hex SHA-256")
    if event.get("warning_id") in (None, ""):
        raise EvidenceError("warning.warning_id is required")
    return campaign, when, model_hash


def validate_compromise(event: dict[str, Any]) -> tuple[str, datetime, str]:
    if event.get("event_type") != "successful_compromise":
        raise EvidenceError("compromise event_type must equal 'successful_compromise'")
    if event.get("establishes_successful_compromise") is not True:
        raise EvidenceError("compromise must set establishes_successful_compromise=true")
    campaign = require_campaign(event.get("campaign_id"))
    when = parse_time(event.get("timestamp"), "compromise.timestamp")
    marker = event.get("objective_success_marker")
    if not isinstance(marker, str) or not marker.strip():
        raise EvidenceError("compromise.objective_success_marker is required")
    source = event.get("source_reference")
    if not isinstance(source, str) or not source.strip():
        raise EvidenceError("compromise.source_reference is required")
    semantics = str(event.get("event_semantics", "")).casefold()
    forbidden_only = {
        "attack_start", "attack_onset", "attack_step", "tactic_onset",
        "malicious_flow_start", "future_positive_window"
    }
    if semantics in forbidden_only:
        raise EvidenceError(
            "attack/onset semantics alone cannot establish successful compromise"
        )
    return campaign, when, marker.strip()


def _string_set(prov: dict[str, Any], key: str) -> set[str]:
    value = prov.get(key, [])
    if not isinstance(value, list) or any(not isinstance(x, str) for x in value):
        raise EvidenceError(f"provenance.{key} must be a list of strings")
    return {x.strip() for x in value if x.strip()}


def validate_provenance(prov: dict[str, Any], campaign: str) -> dict[str, list[str]]:
    if prov.get("identity_proof_complete") is not True:
        raise EvidenceError("provenance.identity_proof_complete must be true")
    evidence = _string_set(prov, "evidence_campaign_ids")
    if campaign not in evidence:
        raise EvidenceError("campaign_id must be listed in provenance.evidence_campaign_ids")
    groups = {
        "train_campaign_ids": _string_set(prov, "train_campaign_ids"),
        "validation_campaign_ids": _string_set(prov, "validation_campaign_ids"),
        "calibration_campaign_ids": _string_set(prov, "calibration_campaign_ids"),
        "development_reused_campaign_ids": _string_set(prov, "development_reused_campaign_ids"),
    }
    overlap = [name for name, values in groups.items() if campaign in values]
    if overlap:
        raise EvidenceError(
            "evidence campaign is not disjoint from: " + ", ".join(sorted(overlap))
        )
    return {name: sorted(values) for name, values in groups.items()}


def verify(warning_path: Path, compromise_path: Path, provenance_path: Path) -> dict[str, Any]:
    warning = load_json(warning_path)
    compromise = load_json(compromise_path)
    provenance = load_json(provenance_path)

    warning_campaign, warning_time, model_hash = validate_warning(warning)
    compromise_campaign, compromise_time, marker = validate_compromise(compromise)
    if warning_campaign != compromise_campaign:
        raise EvidenceError("warning and compromise campaign_id values differ")
    groups = validate_provenance(provenance, warning_campaign)

    lead = (compromise_time - warning_time).total_seconds()
    if lead <= 0:
        raise EvidenceError(
            f"lead time must be strictly positive; observed {lead:.6f} seconds"
        )

    return {
        "schema_version": "v107-precompromise-verification.1",
        "status": "PASS",
        "campaign_id": warning_campaign,
        "warning_event": {
            "timestamp_utc": warning_time.isoformat(),
            "warning_id": warning["warning_id"],
            "emitted_by_model": True,
            "model_sha256": model_hash,
            "raw_json_sha256": sha256_file(warning_path),
        },
        "compromise_event": {
            "timestamp_utc": compromise_time.isoformat(),
            "establishes_successful_compromise": True,
            "objective_success_marker": marker,
            "source_reference": compromise["source_reference"],
            "raw_json_sha256": sha256_file(compromise_path),
        },
        "provenance": {
            "identity_proof_complete": True,
            "evidence_campaign_ids": sorted(_string_set(provenance, "evidence_campaign_ids")),
            **groups,
            "raw_json_sha256": sha256_file(provenance_path),
        },
        "lead_time_seconds": lead,
        "claim": (
            "For this exact campaign only, the recorded model warning preceded the "
            "objective successful-compromise event by the reported positive lead time."
        ),
    }


def main() -> int:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--warning", required=True, type=Path)
    p.add_argument("--compromise", required=True, type=Path)
    p.add_argument("--provenance", required=True, type=Path)
    p.add_argument("--output", required=True, type=Path)
    args = p.parse_args()

    if args.output.exists():
        p.error("output already exists; verification artifacts are immutable")
    try:
        result = verify(args.warning, args.compromise, args.provenance)
    except EvidenceError as exc:
        result = {
            "schema_version": "v107-precompromise-verification.1",
            "status": "FAIL",
            "reason": str(exc),
            "warning_raw_json_sha256": sha256_file(args.warning) if args.warning.exists() else None,
            "compromise_raw_json_sha256": sha256_file(args.compromise) if args.compromise.exists() else None,
            "provenance_raw_json_sha256": sha256_file(args.provenance) if args.provenance.exists() else None,
        }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(result, indent=2, allow_nan=False) + "\n", encoding="utf-8")
    print(json.dumps(result, indent=2, allow_nan=False))
    return 0 if result["status"] == "PASS" else 2


if __name__ == "__main__":
    raise SystemExit(main())
