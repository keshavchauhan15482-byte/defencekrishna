"""V109 fail-closed audit for the SIH five-stage certification gate.

This does not train or score a new stage model. It converts the evidence boundary into
machine-verifiable form so packet-feature completeness cannot be confused with a
five-stage supervised PASS.
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path

REQUIRED_STAGES = [
    "reconnaissance",
    "initial_access",
    "lateral_movement",
    "command_and_control",
    "exfiltration",
]
REQUIRED_METRICS = {"precision", "recall", "f1", "fpr", "support"}


class StageCertificationError(RuntimeError):
    pass


def audit(manifest: dict) -> dict:
    if manifest.get("schema_version") != "v97.3":
        raise StageCertificationError("V109 requires the V97.3 post-V108 manifest")
    if manifest.get("required_stages") != REQUIRED_STAGES:
        raise StageCertificationError("Required SIH five-stage contract drift")

    packet = manifest.get("packet_evidence", {})
    supported = packet.get("supported_features", {})
    mandatory_packet_checks = {
        "world_model_consumes_packet_features": packet.get("world_model_consumes_packet_features") is True,
        "packet_features_trained": packet.get("packet_features_trained") is True,
        "ps_complete_features_trained": packet.get("ps_complete_features_trained") is True,
        "payload_distribution": supported.get("payload_distribution") is True,
        "port_scan_patterns": supported.get("port_scan_patterns") is True,
        "port_scan_sequencing": supported.get("port_scan_sequencing") is True,
        "ttl_variance": supported.get("ttl_variance") is True,
        "tcp_window": supported.get("tcp_window") is True,
        "fragmentation": supported.get("fragmentation") is True,
        "retransmission_count": supported.get("retransmission_count") is True,
        "psh_urg": supported.get("psh_urg") is True,
        "iat_variance": supported.get("iat_variance") is True,
        "iat_max": supported.get("iat_max") is True,
    }
    packet_gate = all(mandatory_packet_checks.values())

    stage = manifest.get("stage_evidence", {})
    metrics = stage.get("metrics", {})
    validated = stage.get("all_five_independently_network_validated") is True
    artifact_present = bool(stage.get("artifact"))
    per_stage_checks = {}
    for name in REQUIRED_STAGES:
        row = metrics.get(name, {}) if isinstance(metrics, dict) else {}
        per_stage_checks[name] = {
            "metrics_present": REQUIRED_METRICS.issubset(set(row)),
            "support_positive": isinstance(row.get("support"), (int, float)) and row.get("support", 0) > 0,
        }
    stage_metrics_complete = all(
        row["metrics_present"] and row["support_positive"] for row in per_stage_checks.values()
    )
    stage_gate = bool(validated and artifact_present and stage_metrics_complete)

    return {
        "schema_version": "v109.1",
        "packet_feature_gate": {
            "status": "PASS" if packet_gate else "FAIL",
            "checks": mandatory_packet_checks,
            "schema": packet.get("schema"),
            "feature_count": packet.get("feature_count"),
            "model_sha256": packet.get("model_sha256"),
            "support_gate_sha256": packet.get("support_gate_sha256"),
        },
        "five_stage_gate": {
            "status": "PASS" if stage_gate else "UNRESOLVED",
            "independently_network_validated": validated,
            "artifact_present": artifact_present,
            "metrics_complete_for_all_five": stage_metrics_complete,
            "per_stage": per_stage_checks,
        },
        "combined_v97_gate": "PASS" if packet_gate and stage_gate else "SHADOW_UNRESOLVED",
        "claim_boundary": (
            "Packet-feature completeness and five-stage supervised validity are separate gates. "
            "V108 may close the packet-feature gate while V97 remains unresolved until all five stages "
            "have independently validated labels and frozen per-stage precision/recall/F1/FPR/support."
        ),
    }


def main() -> int:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--manifest", required=True, type=Path)
    p.add_argument("--output", required=True, type=Path)
    args = p.parse_args()
    result = audit(json.loads(args.manifest.read_text()))
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(result, indent=2, allow_nan=False) + "\n")
    print(json.dumps(result, indent=2, allow_nan=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
