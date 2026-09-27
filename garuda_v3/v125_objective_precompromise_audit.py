"""V125 objective pre-compromise evidence source audit.

Fail-closed audit only. It never synthesizes a compromise timestamp and never converts an
attack-start/onset label into successful-compromise evidence. The audit records whether the
currently frozen external evidence contains a real objective successful-compromise marker
that can be paired with a model-emitted warning under the strict V107/V110 contract.
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--repo-root", type=Path, default=Path(__file__).resolve().parents[1])
    ap.add_argument("--output", type=Path, required=True)
    args = ap.parse_args()

    root = args.repo_root
    v98 = json.loads((root / "garuda_v3/artifacts/certification/v98/verified_precompromise_manifest.json").read_text())
    v123 = json.loads((root / "garuda_v3/artifacts/certification/v123/acquisition_manifest.json").read_text())

    names = [f.get("name") for f in v123.get("files", [])]
    attack_files = [n for n in names if n and ("Flooding Attack" in n or "Nmap" in n)]

    result = {
        "schema_version": "v125-precompromise-source-audit.1",
        "status": "UNRESOLVED_NO_OBJECTIVE_SUCCESS_MARKER",
        "engineering_validator_ready": v98.get("engineering_gate") == "PASS",
        "v98_evidence_gate_before_v125": v98.get("evidence_gate"),
        "audited_external_campaign": {
            "source": "ZeroSWARM / Zenodo record 15082260",
            "v123_file_names": names,
            "attack_pcaps": attack_files,
            "finding": "The frozen V123 evidence contains attack-labelled PCAP identities but no publisher-side event declaring a successful compromise, no objective success marker, and no same-campaign compromise timestamp. Attack type or PCAP filename is not accepted as proof of successful compromise."
        },
        "strict_rejections": [
            "attack_start",
            "attack_onset",
            "attack_step",
            "tactic_onset",
            "malicious_flow_start",
            "future_positive_window",
            "attack-labelled PCAP filename without an objective successful-compromise event"
        ],
        "pass_requires": [
            "one explicitly identified campaign disjoint from train/validation/calibration/development-reused identities",
            "an actual model-emitted warning event with timezone-aware timestamp and immutable model identity",
            "an objective successful-compromise event for the same campaign",
            "establishes_successful_compromise=true",
            "non-empty objective_success_marker and source_reference",
            "positive compromise_timestamp - warning_timestamp",
            "raw warning/compromise/provenance JSON objects hash-pinned and accepted by v110_precompromise_evidence_bundle.py"
        ],
        "claim_boundary": "V125 closes the source-audit question only: current frozen V123 PCAPs cannot honestly certify successful-compromise lead time. The pre-compromise evidence gate remains unresolved until a real objective success event is paired with a model warning under V107/V110."
    }

    args.output.parent.mkdir(parents=True, exist_ok=True)
    if args.output.exists():
        raise RuntimeError(f"immutable output already exists: {args.output}")
    args.output.write_text(json.dumps(result, indent=2) + "\n")
    print(json.dumps(result, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
