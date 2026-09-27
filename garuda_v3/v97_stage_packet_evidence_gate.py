"""V97 fail-closed supervised-stage + packet-provenance evidence gate.

This verifier is intentionally about evidence integrity, not about declaring that a
model is good enough for deployment.  It accepts a candidate only when:

* all five SIH/MITRE stage classes have genuinely supervised labels and complete
  per-stage metrics;
* unknown labels are masked/ignored rather than silently treated as benign;
* stage-head fitting/calibration provenance excludes test/replay data;
* packet telemetry is tied to an actual PCAP/PCAPNG source hash and a hash-pinned
  extraction/evaluation artifact; and
* the candidate explicitly records that the world model consumed packet features.

No minimum recall/F1 threshold is invented here.  A PASS means the evidence contract
is complete and internally verifiable; performance values must still be read as-is.
It does not certify a fresh external holdout or pre-compromise warning.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import math
import re
from pathlib import Path
from typing import Any

REQUIRED_STAGES = (
    "reconnaissance",
    "initial_access",
    "lateral_movement",
    "command_and_control",
    "exfiltration",
)

PACKET_FEATURE_SLOTS = (
    "ttl_variance",
    "tcp_window",
    "fragmentation",
    "payload_distribution",
    "port_scan_patterns",
    "retransmission",
)

ACCEPTED_LABEL_SOURCES = {
    "native",
    "timeline_backed",
    "native_timeline_backed",
}
ACCEPTED_UNKNOWN_POLICIES = {
    "mask",
    "masked",
    "ignore_unknown",
    "masked_unknown",
}
ACCEPTED_PACKET_ORIGINS = {"pcap", "pcapng", "pcap+pcapng"}

_STAGE_ALIASES = {
    "recon": "reconnaissance",
    "reconnaissance": "reconnaissance",
    "reconnaissance_discovery": "reconnaissance",
    "discovery": "reconnaissance",
    "initial_access": "initial_access",
    "initialaccess": "initial_access",
    "exploitation": "initial_access",
    "lateral_movement": "lateral_movement",
    "lateralmovement": "lateral_movement",
    "command_control": "command_and_control",
    "command_and_control": "command_and_control",
    "commandandcontrol": "command_and_control",
    "c2": "command_and_control",
    "candc": "command_and_control",
    "exfiltration": "exfiltration",
}


def _norm_token(value: Any) -> str:
    text = str(value or "").strip().lower()
    text = text.replace("&", " and ")
    text = re.sub(r"[^a-z0-9]+", "_", text).strip("_")
    return text


def canonical_stage(value: Any) -> str | None:
    return _STAGE_ALIASES.get(_norm_token(value))


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            h.update(block)
    return h.hexdigest()


def _valid_sha256(value: Any) -> bool:
    return bool(re.fullmatch(r"[0-9a-fA-F]{64}", str(value or "")))


def _resolve_repo_path(repo_root: Path, raw: Any) -> Path | None:
    if not isinstance(raw, str) or not raw.strip():
        return None
    candidate = (repo_root / raw).resolve()
    root = repo_root.resolve()
    try:
        candidate.relative_to(root)
    except ValueError:
        return None
    return candidate


def _check_artifact(repo_root: Path, spec: Any, label: str, reasons: list[str]) -> None:
    if not isinstance(spec, dict):
        reasons.append(f"{label}: missing artifact specification")
        return
    path = _resolve_repo_path(repo_root, spec.get("path"))
    expected = spec.get("sha256")
    if path is None:
        reasons.append(f"{label}: artifact path missing or escapes repository root")
        return
    if not _valid_sha256(expected):
        reasons.append(f"{label}: artifact sha256 missing/invalid")
        return
    if not path.is_file():
        reasons.append(f"{label}: artifact not found: {spec.get('path')}")
        return
    actual = sha256_file(path)
    if actual.lower() != str(expected).lower():
        reasons.append(f"{label}: sha256 mismatch")


def _finite_unit(value: Any) -> bool:
    if isinstance(value, bool):
        return False
    try:
        number = float(value)
    except (TypeError, ValueError):
        return False
    return math.isfinite(number) and 0.0 <= number <= 1.0


def _positive_support(value: Any) -> bool:
    if isinstance(value, bool):
        return False
    try:
        number = int(value)
    except (TypeError, ValueError):
        return False
    return number > 0 and float(value) == float(number)


def _contains_forbidden_fit_source(value: Any) -> bool:
    token = _norm_token(value)
    parts = set(token.split("_"))
    return "test" in parts or "replay" in parts


def verify_manifest(repo_root: Path, manifest: dict[str, Any]) -> dict[str, Any]:
    reasons: list[str] = []

    requested = manifest.get("required_stages", list(REQUIRED_STAGES))
    canonical_requested = {canonical_stage(x) for x in requested}
    canonical_requested.discard(None)
    if canonical_requested != set(REQUIRED_STAGES):
        reasons.append("required_stages must cover exactly the five SIH stage classes")

    stage = manifest.get("stage_evidence")
    if not isinstance(stage, dict):
        stage = {}
        reasons.append("stage_evidence: missing object")

    label_source = _norm_token(stage.get("label_source"))
    if label_source not in ACCEPTED_LABEL_SOURCES:
        reasons.append(
            "stage_evidence: label_source is not native/timeline-backed supervised evidence"
        )

    if _norm_token(stage.get("unknown_label_policy")) not in ACCEPTED_UNKNOWN_POLICIES:
        reasons.append("stage_evidence: unknown labels are not explicitly masked/ignored")

    provenance = stage.get("provenance")
    if not isinstance(provenance, dict):
        reasons.append("stage_evidence: missing fit/calibration provenance")
        provenance = {}
    for key in ("training_sources", "validation_sources", "calibration_sources"):
        values = provenance.get(key, [])
        if not isinstance(values, list):
            reasons.append(f"stage_evidence: {key} must be a list")
            continue
        if any(_contains_forbidden_fit_source(v) for v in values):
            reasons.append(f"stage_evidence: {key} includes forbidden test/replay data")

    raw_metrics = stage.get("metrics")
    metrics: dict[str, Any] = {}
    if not isinstance(raw_metrics, dict):
        reasons.append("stage_evidence: missing per-stage metrics")
    else:
        for raw_name, row in raw_metrics.items():
            name = canonical_stage(raw_name)
            if name in REQUIRED_STAGES:
                if name in metrics:
                    reasons.append(f"stage_evidence: duplicate metric alias for {name}")
                metrics[name] = row

    for name in REQUIRED_STAGES:
        row = metrics.get(name)
        if not isinstance(row, dict):
            reasons.append(f"stage_evidence: missing metrics for {name}")
            continue
        for metric_name in ("precision", "recall", "f1", "fpr"):
            if not _finite_unit(row.get(metric_name)):
                reasons.append(
                    f"stage_evidence: {name}.{metric_name} missing/non-finite/out-of-range"
                )
        if not _positive_support(row.get("support")):
            reasons.append(f"stage_evidence: {name}.support must be a positive integer")

    _check_artifact(repo_root, stage.get("artifact"), "stage_evidence", reasons)

    packet = manifest.get("packet_evidence")
    if not isinstance(packet, dict):
        packet = {}
        reasons.append("packet_evidence: missing object")

    if _norm_token(packet.get("origin")) not in ACCEPTED_PACKET_ORIGINS:
        reasons.append("packet_evidence: origin must be actual PCAP/PCAPNG telemetry")

    source_capture_sha256 = packet.get("source_capture_sha256")
    if not _valid_sha256(source_capture_sha256):
        reasons.append("packet_evidence: source_capture_sha256 missing/invalid")

    if packet.get("world_model_consumes_packet_features") is not True:
        reasons.append("packet_evidence: world-model packet-feature consumption not proven")

    features = packet.get("supported_features")
    if not isinstance(features, dict):
        reasons.append("packet_evidence: supported_features must explicitly record packet slots")
    else:
        missing_slots = [slot for slot in PACKET_FEATURE_SLOTS if slot not in features]
        if missing_slots:
            reasons.append(
                "packet_evidence: feature support not explicitly recorded for "
                + ", ".join(missing_slots)
            )
        invalid_slots = [
            slot for slot in PACKET_FEATURE_SLOTS
            if slot in features and not isinstance(features.get(slot), bool)
        ]
        if invalid_slots:
            reasons.append(
                "packet_evidence: feature support values must be boolean for "
                + ", ".join(invalid_slots)
            )
        if features and not any(features.get(slot) is True for slot in PACKET_FEATURE_SLOTS):
            reasons.append("packet_evidence: no packet feature is evidenced as supported")

    _check_artifact(repo_root, packet.get("artifact"), "packet_evidence", reasons)

    status = "PASS" if not reasons else "SHADOW_UNRESOLVED"
    return {
        "protocol": "V97 supervised MITRE-stage + packet provenance evidence gate",
        "candidate_id": manifest.get("candidate_id"),
        "status": status,
        "reason_count": len(reasons),
        "reasons": reasons,
        "checks": {
            "required_stages": list(REQUIRED_STAGES),
            "accepted_label_sources": sorted(ACCEPTED_LABEL_SOURCES),
            "packet_feature_slots": list(PACKET_FEATURE_SLOTS),
            "performance_threshold_applied": False,
        },
        "claim_boundary": (
            "PASS certifies only completeness/integrity of supervised five-stage evidence "
            "and packet-origin provenance for this candidate. It does not certify fresh "
            "external generalisation, production zero-day performance, or warning before "
            "successful compromise. Metric quality must be reported without hiding weak values."
        ),
    }


def main() -> None:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--manifest", required=True)
    p.add_argument("--repo-root", default=".")
    p.add_argument("--output")
    p.add_argument("--require-pass", action="store_true")
    args = p.parse_args()

    root = Path(args.repo_root).resolve()
    manifest_path = Path(args.manifest)
    if not manifest_path.is_absolute():
        manifest_path = (root / manifest_path).resolve()
    manifest = json.loads(manifest_path.read_text())
    report = verify_manifest(root, manifest)
    rendered = json.dumps(report, indent=2, allow_nan=False) + "\n"
    if args.output:
        out = Path(args.output)
        if not out.is_absolute():
            out = (root / out).resolve()
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(rendered)
    print(rendered, end="")
    if args.require_pass and report["status"] != "PASS":
        raise SystemExit(2)


if __name__ == "__main__":
    main()
