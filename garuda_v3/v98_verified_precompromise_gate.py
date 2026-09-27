"""V98 verified pre-compromise evidence gate.

This verifier deliberately distinguishes attack-onset lead time from verified
lead time to an objective successful-compromise event.  A PASS is possible
only when an integrity-pinned model warning precedes an integrity-pinned
successful-compromise event for the same explicitly isolated campaign.

The verifier is fail closed: missing provenance, ambiguous event semantics,
unknown campaign overlap, hash mismatch, or a non-positive lead time all
produce SHADOW_UNRESOLVED.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

STATUS_PASS = "PASS"
STATUS_UNRESOLVED = "SHADOW_UNRESOLVED"

FORBIDDEN_COMPROMISE_KINDS = {
    "attack_onset",
    "attack_start",
    "intrusion_start",
    "attack_step",
    "attack_activity",
    "exploitation_start",
}

PROVENANCE_ID_LISTS = (
    "evidence_campaign_ids",
    "train_campaign_ids",
    "validation_campaign_ids",
    "calibration_campaign_ids",
    "development_reused_campaign_ids",
)

SHA256_RE = re.compile(r"^[0-9a-f]{64}$")


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def parse_timestamp(value: Any) -> datetime:
    text = str(value).strip()
    if not text:
        raise ValueError("timestamp is empty")
    if text.endswith("Z"):
        text = text[:-1] + "+00:00"
    parsed = datetime.fromisoformat(text)
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise ValueError("timestamp must be timezone-aware")
    return parsed.astimezone(timezone.utc)


def _safe_artifact_path(repo_root: Path, relative_path: str) -> Path:
    candidate = Path(relative_path)
    if candidate.is_absolute():
        raise ValueError("artifact path must be repository-relative")
    root = repo_root.resolve()
    resolved = (root / candidate).resolve()
    try:
        resolved.relative_to(root)
    except ValueError as exc:
        raise ValueError("artifact path escapes repository root") from exc
    return resolved


def _read_json(path: Path) -> Dict[str, Any]:
    with path.open("r", encoding="utf-8") as handle:
        value = json.load(handle)
    if not isinstance(value, dict):
        raise ValueError("event artifact must contain a JSON object")
    return value


def _load_event(
    spec: Any,
    repo_root: Path,
    label: str,
    reasons: List[str],
) -> Optional[Dict[str, Any]]:
    if not isinstance(spec, dict):
        reasons.append(f"{label}: event specification is missing")
        return None

    artifact = spec.get("artifact")
    if not isinstance(artifact, dict):
        reasons.append(f"{label}: artifact specification is missing")
        return None

    relative_path = artifact.get("path")
    expected_sha = str(artifact.get("sha256", "")).lower()
    if not isinstance(relative_path, str) or not relative_path.strip():
        reasons.append(f"{label}: artifact path is missing")
        return None
    if not SHA256_RE.fullmatch(expected_sha):
        reasons.append(f"{label}: artifact SHA-256 is missing or invalid")
        return None

    try:
        path = _safe_artifact_path(repo_root, relative_path)
    except ValueError as exc:
        reasons.append(f"{label}: {exc}")
        return None
    if not path.is_file():
        reasons.append(f"{label}: artifact does not exist: {relative_path}")
        return None

    actual_sha = sha256_file(path)
    if actual_sha != expected_sha:
        reasons.append(
            f"{label}: SHA-256 mismatch for {relative_path}; "
            f"expected {expected_sha}, got {actual_sha}"
        )
        return None

    try:
        event = _read_json(path)
    except (OSError, json.JSONDecodeError, ValueError) as exc:
        reasons.append(f"{label}: cannot load event artifact: {exc}")
        return None

    timestamp_field = str(spec.get("timestamp_field", "timestamp"))
    kind_field = str(spec.get("kind_field", "event_type"))
    campaign_field = str(spec.get("campaign_field", "campaign_id"))

    if timestamp_field not in event:
        reasons.append(f"{label}: timestamp field '{timestamp_field}' is missing")
    if kind_field not in event:
        reasons.append(f"{label}: event-kind field '{kind_field}' is missing")
    if campaign_field not in event:
        reasons.append(f"{label}: campaign field '{campaign_field}' is missing")

    return {
        "event": event,
        "timestamp_field": timestamp_field,
        "kind_field": kind_field,
        "campaign_field": campaign_field,
        "path": relative_path,
        "sha256": actual_sha,
    }


def _validate_id_list(provenance: Dict[str, Any], key: str, reasons: List[str]) -> List[str]:
    value = provenance.get(key)
    if not isinstance(value, list):
        reasons.append(f"provenance.{key} must be an explicit list")
        return []
    if any(not isinstance(item, str) or not item.strip() for item in value):
        reasons.append(f"provenance.{key} contains an invalid campaign identity")
        return []
    cleaned = [item.strip() for item in value]
    if len(set(cleaned)) != len(cleaned):
        reasons.append(f"provenance.{key} contains duplicate campaign identities")
    return cleaned


def verify_manifest(manifest: Dict[str, Any], repo_root: Path) -> Dict[str, Any]:
    reasons: List[str] = []
    campaign_raw = manifest.get("campaign_id")
    campaign_id = campaign_raw.strip() if isinstance(campaign_raw, str) else ""
    if not campaign_id:
        reasons.append("campaign_id is missing")

    provenance = manifest.get("provenance")
    if not isinstance(provenance, dict):
        reasons.append("provenance object is missing")
        provenance = {}

    if provenance.get("identity_proof_complete") is not True:
        reasons.append("campaign identity proof is not explicitly complete")

    identity_sets: Dict[str, List[str]] = {
        key: _validate_id_list(provenance, key, reasons) for key in PROVENANCE_ID_LISTS
    }

    evidence_ids = identity_sets["evidence_campaign_ids"]
    if campaign_id and evidence_ids != [campaign_id]:
        reasons.append(
            "provenance.evidence_campaign_ids must contain exactly the certified campaign_id"
        )

    protected_sets = (
        "train_campaign_ids",
        "validation_campaign_ids",
        "calibration_campaign_ids",
        "development_reused_campaign_ids",
    )
    if campaign_id:
        for key in protected_sets:
            if campaign_id in set(identity_sets[key]):
                reasons.append(f"evidence campaign overlaps provenance.{key}")

    warning = _load_event(manifest.get("warning_event"), repo_root, "warning_event", reasons)
    compromise = _load_event(
        manifest.get("compromise_event"), repo_root, "compromise_event", reasons
    )

    warning_time: Optional[datetime] = None
    compromise_time: Optional[datetime] = None

    if warning is not None:
        event = warning["event"]
        warning_campaign = event.get(warning["campaign_field"])
        if warning_campaign != campaign_id:
            reasons.append("warning_event campaign_id does not match manifest campaign_id")
        warning_kind = event.get(warning["kind_field"])
        required_warning_kind = manifest.get("warning_event", {}).get(
            "required_kind", "model_warning"
        )
        if required_warning_kind != "model_warning":
            reasons.append("warning_event.required_kind must be exactly 'model_warning'")
        if warning_kind != "model_warning":
            reasons.append("warning_event must have event_type 'model_warning'")
        if event.get("emitted_by_model") is not True:
            reasons.append("warning_event must explicitly set emitted_by_model=true")
        try:
            warning_time = parse_timestamp(event.get(warning["timestamp_field"]))
        except (TypeError, ValueError) as exc:
            reasons.append(f"warning_event timestamp is invalid: {exc}")

    if compromise is not None:
        event = compromise["event"]
        compromise_campaign = event.get(compromise["campaign_field"])
        if compromise_campaign != campaign_id:
            reasons.append("compromise_event campaign_id does not match manifest campaign_id")
        compromise_kind = event.get(compromise["kind_field"])
        required_compromise_kind = manifest.get("compromise_event", {}).get(
            "required_kind", "successful_compromise"
        )
        if required_compromise_kind != "successful_compromise":
            reasons.append(
                "compromise_event.required_kind must be exactly 'successful_compromise'"
            )
        if compromise_kind in FORBIDDEN_COMPROMISE_KINDS:
            reasons.append(
                f"compromise_event kind '{compromise_kind}' is attack activity/onset, "
                "not successful compromise"
            )
        if compromise_kind != "successful_compromise":
            reasons.append("compromise_event must have event_type 'successful_compromise'")
        if event.get("establishes_successful_compromise") is not True:
            reasons.append(
                "compromise_event must explicitly set establishes_successful_compromise=true"
            )
        try:
            compromise_time = parse_timestamp(event.get(compromise["timestamp_field"]))
        except (TypeError, ValueError) as exc:
            reasons.append(f"compromise_event timestamp is invalid: {exc}")

    lead_time_seconds: Optional[float] = None
    if warning_time is not None and compromise_time is not None:
        lead_time_seconds = (compromise_time - warning_time).total_seconds()
        if lead_time_seconds <= 0:
            reasons.append("model warning does not precede successful compromise")

    status = STATUS_PASS if not reasons else STATUS_UNRESOLVED
    exact_claim = (
        f"For campaign {campaign_id}, the integrity-pinned model warning preceded the "
        f"objective successful-compromise event by {lead_time_seconds:.3f} seconds."
        if status == STATUS_PASS and lead_time_seconds is not None
        else "No successful-compromise lead-time claim is certified by V98."
    )

    return {
        "schema_version": "v98.1-report",
        "status": status,
        "campaign_id": campaign_id or None,
        "lead_time_seconds": lead_time_seconds,
        "warning_timestamp_utc": warning_time.isoformat() if warning_time else None,
        "compromise_timestamp_utc": compromise_time.isoformat() if compromise_time else None,
        "claim_boundary": exact_claim,
        "v93_attack_step_lead_time_is_successful_compromise_evidence": False,
        "reasons": reasons,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--manifest", required=True, type=Path)
    parser.add_argument("--repo-root", default=Path("."), type=Path)
    parser.add_argument("--output", type=Path)
    parser.add_argument("--require-declared-match", action="store_true")
    parser.add_argument("--require-pass", action="store_true")
    args = parser.parse_args()

    try:
        with args.manifest.open("r", encoding="utf-8") as handle:
            manifest = json.load(handle)
        if not isinstance(manifest, dict):
            raise ValueError("manifest must contain a JSON object")
    except (OSError, json.JSONDecodeError, ValueError) as exc:
        print(json.dumps({"status": STATUS_UNRESOLVED, "fatal_error": str(exc)}, indent=2))
        return 2

    report = verify_manifest(manifest, args.repo_root)
    rendered = json.dumps(report, indent=2, sort_keys=True) + "\n"
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(rendered, encoding="utf-8")
    print(rendered, end="")

    if args.require_declared_match and manifest.get("declared_status") != report["status"]:
        print(
            "declared_status does not match independently verified status",
        )
        return 3
    if args.require_pass and report["status"] != STATUS_PASS:
        return 4
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
