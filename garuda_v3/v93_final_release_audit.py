"""Final SIH release-integrity audit through V94.

This is not a new accuracy benchmark. It verifies that the active runtime bundle is
fail-closed and usable, that judge-facing evidence points to the current authoritative
numbers, and that preserved external failures/claim boundaries cannot silently disappear
from the release pack.
"""
from __future__ import annotations

import argparse
import csv
import hashlib
import json
from pathlib import Path

from .bundle_manifest import load_manifest, resolve_active_bundle
from .inference import ForecastService

ROOT = Path(__file__).resolve().parents[1]


def sha256(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for block in iter(lambda: f.read(1024 * 1024), b""):
            h.update(block)
    return h.hexdigest()


def require_text(path: Path, *needles: str):
    text = path.read_text(encoding="utf-8")
    missing = [x for x in needles if x not in text]
    if missing:
        raise RuntimeError(f"{path}: missing authoritative text {missing}")
    return text


def load_claim_matrix(path: Path) -> dict[str, dict]:
    with path.open(newline="", encoding="utf-8") as f:
        rows = list(csv.DictReader(f))
    if not rows or "claim_id" not in rows[0]:
        raise RuntimeError("SIH claim matrix is empty or malformed")
    by_id = {r["claim_id"]: r for r in rows}
    required = {
        "state_v70", "attack_v88", "progression_v89_1", "leadtime_v93",
        "precompromise", "runtime_v94", "support_detection", "mitre_stage",
        "autonomous_enterprise",
    }
    missing = required - set(by_id)
    if missing:
        raise RuntimeError(f"SIH claim matrix missing rows: {sorted(missing)}")
    expected = {
        "progression_v89_1": "NOT_APPROVED",
        "leadtime_v93": "APPROVED_DIAGNOSTIC",
        "precompromise": "NOT_APPROVED",
        "runtime_v94": "APPROVED",
        "support_detection": "PROHIBITED",
        "mitre_stage": "NOT_APPROVED",
        "autonomous_enterprise": "NOT_APPROVED",
    }
    for claim_id, status in expected.items():
        if by_id[claim_id]["status"] != status:
            raise RuntimeError(f"Claim status drift for {claim_id}: {by_id[claim_id]['status']} != {status}")
    return by_id


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--output", required=True)
    args = ap.parse_args()
    out = Path(args.output)
    if out.exists():
        ap.error("Output exists; release-audit evidence is immutable")
    out.parent.mkdir(parents=True, exist_ok=True)

    manifest_path = ROOT / "garuda_v3" / "active_runtime_bundle.json"
    manifest = load_manifest(ROOT)
    artifact_dir = resolve_active_bundle(ROOT)
    service = ForecastService(artifact_dir)
    replay_path = artifact_dir / "replay.json"
    replay = json.loads(replay_path.read_text())
    prediction = service.predict(replay, explain=True)
    if prediction["model_sha256"] != service.model_hash:
        raise RuntimeError("Prediction/runtime checkpoint hash mismatch")
    if prediction.get("automatic_containment") is not False:
        raise RuntimeError("Submission runtime must not silently enable automatic containment")
    if prediction.get("measured_compromise_lead_time_seconds") is not None:
        raise RuntimeError("Runtime must not fabricate measured compromise lead time")
    if prediction.get("explanation", {}).get("method") != "gradient_x_input":
        raise RuntimeError("Runtime explanation method drift")

    # Current V94 contract: the checked-in active bundle has no pinned support gate,
    # therefore the integrated runtime must fail closed to SHADOW_UNRESOLVED for
    # forecast-driven autonomous response. This is an abstention/safety boundary,
    # not an attack/OOD detector claim.
    support_gate_pinned = "support_gate.json" in manifest.get("files", {})
    if support_gate_pinned or service.support_gate is not None:
        raise RuntimeError("Audit expectation changed: update V94 support-gate evidence before enabling a pinned gate")

    release = ROOT / "RELEASE_EVIDENCE.md"
    final = ROOT / "docs/release/FINAL_SIH_EVIDENCE.md"
    claims = ROOT / "docs/release/SIH_CLAIM_MATRIX.csv"
    v88 = ROOT / "docs/release/v88_final_independent_source/RESULTS.md"
    v90 = ROOT / "docs/release/v90_runtime_performance/RESULTS.md"
    v92doc = ROOT / "docs/release/v92_toniot_first_test/RESULTS.md"
    v92record = ROOT / "garuda_v3/v92_toniot_first_test_result_record.json"
    for p in (release, final, claims, v88, v90, v92doc, v92record):
        if not p.exists():
            raise RuntimeError(f"Required release evidence missing: {p}")

    require_text(
        release,
        "98.6772%", "0.2871%", "0.4291%", "37.8880%", "27.489%",
        "26.7018%", "22.6667%", "SHADOW_UNRESOLVED", "35567112947",
    )
    require_text(
        final,
        "98.6772%", "94.7874%", "2.86–3.01 ms", "26.7018%", "22.6667%",
        "SHADOW_UNRESOLVED", "support abstention is NOT attack detection", "35567112947",
    )
    require_text(v88, "98.6772%", "0.2871%", "94.7874%")
    require_text(v90, "2.862 ms", "3.012 ms", "44.99 MiB")
    require_text(v92doc, "0.4291%", "37.8880%", "0.32841")
    claim_rows = load_claim_matrix(claims)

    record = json.loads(v92record.read_text())
    if record["external_gate"]["passed"] is not False:
        raise RuntimeError("V92 first-test failure was altered")
    if record["external_source"]["file_sha256"] != "26ddc513552de36de6428b2e578efaed2b57504c716dfba847cc0109a64e1974":
        raise RuntimeError("V92 source provenance drift")
    m = record["external_metrics"]
    if [m["tp"], m["fn"], m["fp"], m["tn"]] != [691, 160352, 18944, 31056]:
        raise RuntimeError("V92 immutable confusion counts drift")

    report = {
        "protocol": "Final SIH release-integrity audit through V94",
        "accuracy_benchmark": False,
        "active_bundle": {
            "bundle_id": manifest["bundle_id"],
            "artifact_dir": str(artifact_dir.relative_to(ROOT)),
            "manifest_sha256": sha256(manifest_path),
            "runtime_checkpoint_sha256": service.model_hash,
            "replay_sha256": sha256(replay_path),
            "prediction_horizons": int(len(prediction["trajectory"])),
            "automatic_containment": prediction["automatic_containment"],
            "measured_compromise_lead_time_seconds": prediction["measured_compromise_lead_time_seconds"],
            "explanation_method": prediction["explanation"]["method"],
            "runtime_support_gate_pinned": support_gate_pinned,
            "forecast_response_without_pinned_support_gate": "SHADOW_UNRESOLVED",
        },
        "claim_matrix": {
            "rows": len(claim_rows),
            "progression_release_status": claim_rows["progression_v89_1"]["status"],
            "precompromise_status": claim_rows["precompromise"]["status"],
            "runtime_v94_status": claim_rows["runtime_v94"]["status"],
        },
        "evidence_files": {
            str(p.relative_to(ROOT)): sha256(p) for p in (release, final, claims, v88, v90, v92doc, v92record)
        },
        "immutable_external_failure_preserved": True,
        "authoritative_numbers_consistent": True,
        "runtime_bundle_resolved_fail_closed": True,
        "runtime_support_fail_closed": True,
        "claim_boundary_checks_passed": True,
    }
    out.write_text(json.dumps(report, indent=2, allow_nan=False) + "\n")
    print(json.dumps(report, indent=2))


if __name__ == "__main__":
    main()
