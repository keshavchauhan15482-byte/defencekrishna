"""V93 final SIH release-integrity audit.

This is not a new accuracy benchmark. It verifies that the active runtime bundle is
fail-closed and usable, that judge-facing evidence points to the current authoritative
numbers, and that preserved external failures cannot silently disappear from the release
pack. It is intended to prevent packaging/integration mistakes before submission.
"""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path

from .bundle_manifest import resolve_runtime_bundle
from .inference import ForecastService


def sha256(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for block in iter(lambda: f.read(1024 * 1024), b""):
            h.update(block)
    return h.hexdigest()


def require_text(path: Path, *needles: str):
    text = path.read_text()
    missing = [x for x in needles if x not in text]
    if missing:
        raise RuntimeError(f"{path}: missing authoritative text {missing}")
    return text


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--output", required=True)
    args = ap.parse_args()
    out = Path(args.output)
    if out.exists():
        ap.error("Output exists; V93 audit evidence is immutable")
    out.parent.mkdir(parents=True, exist_ok=True)

    bundle = resolve_runtime_bundle()
    service = ForecastService(bundle.artifact_dir)
    replay_path = bundle.artifact_dir / "replay.json"
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

    release = Path("RELEASE_EVIDENCE.md")
    final = Path("docs/release/FINAL_SIH_EVIDENCE.md")
    v88 = Path("docs/release/v88_final_independent_source/RESULTS.md")
    v90 = Path("docs/release/v90_runtime_performance/RESULTS.md")
    v92doc = Path("docs/release/v92_toniot_first_test/RESULTS.md")
    v92record = Path("garuda_v3/v92_toniot_first_test_result_record.json")
    for p in (release, final, v88, v90, v92doc, v92record):
        if not p.exists():
            raise RuntimeError(f"Required release evidence missing: {p}")

    require_text(release, "98.6772%", "0.2871%", "0.4291%", "37.8880%", "27.489%")
    require_text(final, "98.6772%", "94.7874%", "2.86–3.01 ms", "universal cross-domain portability is not proven")
    require_text(v88, "98.6772%", "0.2871%", "94.7874%")
    require_text(v90, "2.862 ms", "3.012 ms", "44.99 MiB")
    require_text(v92doc, "0.4291%", "37.8880%", "0.32841")

    record = json.loads(v92record.read_text())
    if record["external_gate"]["passed"] is not False:
        raise RuntimeError("V92 first-test failure was altered")
    if record["external_source"]["file_sha256"] != "26ddc513552de36de6428b2e578efaed2b57504c716dfba847cc0109a64e1974":
        raise RuntimeError("V92 source provenance drift")
    m = record["external_metrics"]
    if [m["tp"], m["fn"], m["fp"], m["tn"]] != [691, 160352, 18944, 31056]:
        raise RuntimeError("V92 immutable confusion counts drift")

    report = {
        "protocol": "V93 final SIH release-integrity audit",
        "accuracy_benchmark": False,
        "active_bundle": {
            "bundle_id": bundle.manifest["bundle_id"],
            "artifact_dir": str(bundle.artifact_dir),
            "manifest_sha256": sha256(bundle.manifest_path),
            "runtime_checkpoint_sha256": service.model_hash,
            "replay_sha256": sha256(replay_path),
            "prediction_horizons": int(len(prediction["trajectory"])),
            "automatic_containment": prediction["automatic_containment"],
            "measured_compromise_lead_time_seconds": prediction["measured_compromise_lead_time_seconds"],
            "explanation_method": prediction["explanation"]["method"],
        },
        "evidence_files": {
            str(p): sha256(p) for p in (release, final, v88, v90, v92doc, v92record)
        },
        "immutable_external_failure_preserved": True,
        "authoritative_numbers_consistent": True,
        "runtime_bundle_resolved_fail_closed": True,
        "claim_boundary_checks_passed": True,
    }
    out.write_text(json.dumps(report, indent=2, allow_nan=False) + "\n")
    print(json.dumps(report, indent=2))


if __name__ == "__main__":
    main()
