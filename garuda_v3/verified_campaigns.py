"""Verified campaign manifests for honest pre-compromise evaluation.

A manifest records only externally evidenced facts. Missing annotations remain
unknown; they are never converted into benign supervision.
"""
from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any, Dict, Iterable, List

CANONICAL_STAGES = {
    "Reconnaissance", "Resource Development", "Initial Access", "Execution",
    "Persistence", "Privilege Escalation", "Defense Evasion", "Credential Access",
    "Discovery", "Lateral Movement", "Collection", "Command and Control",
    "Exfiltration", "Impact",
}
ROLES = {"train", "calibration", "policy", "final_test", "attack", "benign"}
OUTCOMES = {"success", "failure", "unknown"}


def sha256_file(path: str | Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for block in iter(lambda: f.read(1024 * 1024), b""):
            h.update(block)
    return h.hexdigest()


def _epoch(v: Any, name: str) -> float:
    if isinstance(v, bool) or not isinstance(v, (int, float)):
        raise ValueError(f"{name} must be numeric epoch seconds")
    return float(v)


def validate_manifest(m: Dict[str, Any]) -> Dict[str, Any]:
    required = ["campaign_id", "role", "domain", "capture_sha256", "graph_path", "start_epoch", "end_epoch", "timezone", "evidence_source", "benign_intervals", "events"]
    missing = [k for k in required if k not in m]
    if missing:
        raise ValueError("Missing manifest fields: " + ", ".join(missing))
    if not isinstance(m["campaign_id"], str) or not m["campaign_id"].strip():
        raise ValueError("campaign_id required")
    if m["role"] not in ROLES:
        raise ValueError("Unsupported campaign role")
    if not isinstance(m["timezone"], str) or not m["timezone"].strip():
        raise ValueError("Explicit timezone required")
    if not isinstance(m["evidence_source"], str) or len(m["evidence_source"].strip()) < 4:
        raise ValueError("Evidence source required")
    if not isinstance(m["capture_sha256"], str) or len(m["capture_sha256"]) != 64:
        raise ValueError("capture_sha256 must be a SHA-256 hex digest")
    start, end = _epoch(m["start_epoch"], "start_epoch"), _epoch(m["end_epoch"], "end_epoch")
    if end <= start:
        raise ValueError("Campaign end must be after start")

    intervals = []
    for item in m["benign_intervals"]:
        a, b = _epoch(item.get("start_epoch"), "benign start"), _epoch(item.get("end_epoch"), "benign end")
        if not start <= a < b <= end:
            raise ValueError("Benign interval outside campaign or reversed")
        if not isinstance(item.get("evidence"), str) or len(item["evidence"].strip()) < 4:
            raise ValueError("Benign interval requires evidence")
        intervals.append((a, b))
    intervals.sort()
    for (_, prev_end), (next_start, _) in zip(intervals, intervals[1:]):
        if next_start < prev_end:
            raise ValueError("Benign intervals overlap")

    seen = set()
    for event in m["events"]:
        event_id = event.get("event_id")
        if not isinstance(event_id, str) or not event_id.strip() or event_id in seen:
            raise ValueError("Events require unique event_id")
        seen.add(event_id)
        t = _epoch(event.get("epoch"), "event epoch")
        if not start <= t <= end:
            raise ValueError("Event outside campaign")
        if event.get("stage") not in CANONICAL_STAGES:
            raise ValueError("Unsupported MITRE stage")
        if event.get("outcome") not in OUTCOMES:
            raise ValueError("Unsupported event outcome")
        if not isinstance(event.get("evidence"), str) or len(event["evidence"].strip()) < 4:
            raise ValueError("Event requires external evidence")
        establishes = bool(event.get("establishes_compromise", False))
        if establishes and event.get("outcome") != "success":
            raise ValueError("Compromise can only be established by a successful event")
    return m


def new_manifest(*, campaign_id: str, role: str, domain: str, capture_path: str | Path, graph_path: str, start_epoch: float, end_epoch: float, timezone: str, evidence_source: str) -> Dict[str, Any]:
    m = {
        "schema": "krishna-verified-campaign-v1",
        "campaign_id": campaign_id,
        "role": role,
        "domain": domain,
        "capture_sha256": sha256_file(capture_path),
        "graph_path": graph_path,
        "start_epoch": float(start_epoch),
        "end_epoch": float(end_epoch),
        "timezone": timezone,
        "evidence_source": evidence_source,
        "benign_intervals": [],
        "events": [],
    }
    return validate_manifest(m)


def add_benign_interval(m: Dict[str, Any], start_epoch: float, end_epoch: float, evidence: str) -> Dict[str, Any]:
    m = json.loads(json.dumps(m))
    m["benign_intervals"].append({"start_epoch": float(start_epoch), "end_epoch": float(end_epoch), "evidence": evidence})
    return validate_manifest(m)


def add_event(m: Dict[str, Any], *, event_id: str, epoch: float, stage: str, outcome: str, evidence: str, establishes_compromise: bool = False, source_host: str | None = None, target_host: str | None = None) -> Dict[str, Any]:
    m = json.loads(json.dumps(m))
    m["events"].append({
        "event_id": event_id,
        "epoch": float(epoch),
        "stage": stage,
        "outcome": outcome,
        "establishes_compromise": bool(establishes_compromise),
        "source_host": source_host,
        "target_host": target_host,
        "evidence": evidence,
    })
    return validate_manifest(m)


def verified_compromise_epoch(m: Dict[str, Any]) -> float | None:
    validate_manifest(m)
    times = [float(e["epoch"]) for e in m["events"] if e.get("outcome") == "success" and e.get("establishes_compromise")]
    return min(times) if times else None


def benign_covers(m: Dict[str, Any], start_epoch: float, end_epoch: float) -> bool:
    """True only when one explicitly evidenced benign interval covers the full range."""
    validate_manifest(m)
    a, b = float(start_epoch), float(end_epoch)
    return any(float(x["start_epoch"]) <= a and float(x["end_epoch"]) >= b for x in m["benign_intervals"])


def clean_history_eligible(m: Dict[str, Any], cutoff_epoch: float, history_minutes: int = 8) -> bool:
    return benign_covers(m, float(cutoff_epoch) - history_minutes * 60, float(cutoff_epoch))


def future_binary_target(m: Dict[str, Any], cutoff_epoch: float, horizon_minutes: int = 4) -> int | None:
    """Return 1 for evidenced attack event, 0 only for complete benign coverage, else None."""
    validate_manifest(m)
    a, b = float(cutoff_epoch), float(cutoff_epoch) + horizon_minutes * 60
    if any(a < float(e["epoch"]) <= b for e in m["events"] if e.get("outcome") == "success"):
        return 1
    if benign_covers(m, a, b):
        return 0
    return None


def freeze_campaign_split(path: str | Path, assignment: Dict[str, List[str]], manifest_ids: Iterable[str]) -> Dict[str, Any]:
    p = Path(path)
    if p.exists():
        raise FileExistsError("Frozen campaign split already exists")
    required = {"train", "calibration", "policy", "final_test"}
    if set(assignment) != required:
        raise ValueError("Split requires train/calibration/policy/final_test")
    flat = [cid for k in ("train", "calibration", "policy", "final_test") for cid in assignment[k]]
    if len(flat) != len(set(flat)):
        raise ValueError("Campaign IDs cannot appear in multiple partitions")
    expected = set(manifest_ids)
    if set(flat) != expected:
        raise ValueError("Campaign split must be exhaustive")
    payload = {"schema": "krishna-campaign-split-v1", "assignment": assignment}
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(json.dumps(payload, indent=2, sort_keys=True))
    return payload


def load_manifest(path: str | Path) -> Dict[str, Any]:
    return validate_manifest(json.loads(Path(path).read_text()))


def save_manifest(path: str | Path, m: Dict[str, Any], *, refuse_overwrite: bool = False) -> None:
    validate_manifest(m)
    p = Path(path)
    if refuse_overwrite and p.exists():
        raise FileExistsError("Manifest already exists")
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(json.dumps(m, indent=2, sort_keys=True))
