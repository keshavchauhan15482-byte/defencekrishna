"""Fail-closed V45 forecasting evidence audit.

Consumes an existing Garuda training metrics.json and independently aligned
incident files. It never refits a threshold and never reads test labels for model
selection. A failed audit leaves the checkpoint research-only.

Verified incident timelines are evaluation truth only. They are never runtime
features or model inputs; runtime evidence remains network-only.
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any, Mapping

from .forecast_hardening import (
    CONTRACT_SCHEMA,
    abstention_status,
    family_release_gate,
    lead_time_summary,
    persistence_gate,
)


def _verified_lead_time(path: str | None, *, min_incidents: int) -> dict[str, Any]:
    if not path:
        return {
            "passed": False,
            "reason": "verified_incident_timeline_not_supplied",
            "verified_incidents": 0,
            "summary": None,
        }
    payload = json.loads(Path(path).read_text())
    incidents = payload.get("incidents", [])
    compromise = []
    warning = []
    for item in incidents:
        if item.get("outcome") != "success" or not item.get("establishes_compromise"):
            continue
        if not item.get("evidence"):
            raise ValueError("Every verified incident needs external evidence")
        compromise.append(float(item["compromise_epoch"]))
        first = item.get("first_warning_epoch")
        warning.append(None if first is None else float(first))
    summary = lead_time_summary(compromise, warning)
    positive_lead = (summary.get("median_lead_seconds") or 0) > 0
    support = len(compromise) >= min_incidents
    return {
        "passed": bool(support and positive_lead and summary["warned_before_compromise"] > 0),
        "reason": "passed" if support and positive_lead and summary["warned_before_compromise"] > 0 else (
            "insufficient_verified_incidents" if not support else "no_verified_positive_lead_time"
        ),
        "verified_incidents": len(compromise),
        "minimum_verified_incidents": min_incidents,
        "summary": summary,
    }


def audit_model(
    report: dict[str, Any],
    name: str,
    *,
    fpr_limit: float,
    recall_floor: float,
    min_family_positives: int,
    min_family_negatives: int,
    lead_gate: dict[str, Any],
) -> dict[str, Any]:
    model = report["models"].get(name)
    if not model:
        return {"model": name, "passed": False, "reason": "model_missing"}

    state = persistence_gate(
        model["validation_state_mse"], model["validation_persistence_mse"]
    )
    families = family_release_gate(
        model.get("per_family_alert_metrics", {}),
        fpr_limit=fpr_limit,
        recall_floor=recall_floor,
        min_positives=min_family_positives,
        min_negatives=min_family_negatives,
    )
    calibration = model.get("calibration", {})
    calibration_passed = calibration.get("status") == "fitted"
    policy = model.get("validation_alert_selection", {})
    policy_passed = policy.get("threshold") is not None and policy.get("status") == "validation_selected"

    clean = model.get("clean_history_warning_policy", {}).get("test", {})
    clean_samples = int(clean.get("samples", 0) or 0)
    clean_positives = int(clean.get("positives", 0) or 0)
    clean_negatives = clean_samples - clean_positives
    clean_support = clean_positives > 0 and clean_negatives > 0

    final_scope = report.get("evaluation_scope") == "new_predeclared_holdout"
    passed = bool(
        final_scope
        and state["passed"]
        and families["passed"]
        and calibration_passed
        and policy_passed
        and clean_support
        and lead_gate["passed"]
    )
    abstention = abstention_status(
        contract_valid=True,
        policy_enabled=policy_passed and calibration_passed,
        persistence_passed=state["passed"],
        supported_family=families["passed"],
    )
    reasons = []
    if not final_scope:
        reasons.append("evaluation_is_not_new_predeclared_holdout")
    if not state["passed"]:
        reasons.append(state["status"])
    if not calibration_passed:
        reasons.append("calibration_not_fitted")
    if not policy_passed:
        reasons.append("validation_policy_not_supported")
    if not families["passed"]:
        reasons.append("per_family_release_gate_failed")
    if not clean_support:
        reasons.append("clean_history_test_lacks_both_classes")
    if not lead_gate["passed"]:
        reasons.append(lead_gate["reason"])

    return {
        "model": name,
        "passed": passed,
        "status": "forecast_evidence_candidate" if passed else "research_only_insufficient_evidence",
        "reasons": reasons,
        "state_vs_persistence": state,
        "calibration_passed": calibration_passed,
        "validation_policy_passed": policy_passed,
        "per_family_gate": families,
        "clean_history_support": {
            "passed": clean_support,
            "samples": clean_samples,
            "positives": clean_positives,
            "negatives": clean_negatives,
        },
        "verified_lead_time_gate": lead_gate,
        "runtime_decision": abstention if not passed else {
            "status": "forecast_supported",
            "abstain": False,
            "reasons": [],
        },
        "automatic_containment_approved": False,
    }


def audit(
    report: dict[str, Any],
    *,
    incident_file: str | None = None,
    incident_files: Mapping[str, str | None] | None = None,
    fpr_limit: float = 0.01,
    recall_floor: float = 0.80,
    min_family_positives: int = 20,
    min_family_negatives: int = 20,
    min_verified_incidents: int = 5,
) -> dict[str, Any]:
    if not 0 <= fpr_limit < 1 or not 0 < recall_floor <= 1:
        raise ValueError("Invalid FPR/recall release thresholds")
    if incident_file and incident_files:
        raise ValueError("Use either incident_file or model-specific incident_files")
    paths = dict(incident_files or {})
    if incident_file:
        # Backward-compatible convenience for tests/manual diagnostics only.
        paths = {"lstm": incident_file, "gnn_lstm": incident_file}
    lead_gates = {
        name: _verified_lead_time(paths.get(name), min_incidents=min_verified_incidents)
        for name in ("lstm", "gnn_lstm")
    }
    models = {
        name: audit_model(
            report,
            name,
            fpr_limit=fpr_limit,
            recall_floor=recall_floor,
            min_family_positives=min_family_positives,
            min_family_negatives=min_family_negatives,
            lead_gate=lead_gates[name],
        )
        for name in ("lstm", "gnn_lstm")
    }
    return {
        "schema": CONTRACT_SCHEMA,
        "evaluation_scope": report.get("evaluation_scope"),
        "release_targets": {
            "fpr_limit": fpr_limit,
            "recall_floor": recall_floor,
            "min_family_positives": min_family_positives,
            "min_family_negatives": min_family_negatives,
            "min_verified_incidents": min_verified_incidents,
        },
        "models": models,
        "any_model_passed": any(m.get("passed") for m in models.values()),
        "automatic_containment_approved": False,
        "notes": [
            "test/final holdout is evaluation-only and never tunes thresholds",
            "seed repeats do not replace independent campaign evidence",
            "verified timelines are evaluation truth only; runtime remains network-only",
            "model-specific warning timestamps are required for model-specific lead-time claims",
            "a passed forecasting audit still does not authorize automatic enterprise blocking",
        ],
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--metrics", required=True, help="Garuda metrics.json")
    parser.add_argument("--output", required=True)
    parser.add_argument("--verified-incidents", help="Shared incident/evidence JSON (diagnostic compatibility)")
    parser.add_argument("--lstm-incidents", help="LSTM-aligned verified incident JSON")
    parser.add_argument("--gnn-incidents", help="GNN+LSTM-aligned verified incident JSON")
    parser.add_argument("--fpr-limit", type=float, default=0.01)
    parser.add_argument("--recall-floor", type=float, default=0.80)
    parser.add_argument("--min-family-positives", type=int, default=20)
    parser.add_argument("--min-family-negatives", type=int, default=20)
    parser.add_argument("--min-verified-incidents", type=int, default=5)
    args = parser.parse_args()
    if args.verified_incidents and (args.lstm_incidents or args.gnn_incidents):
        parser.error("Do not combine shared and model-specific incident files")
    report = json.loads(Path(args.metrics).read_text())
    specific = None
    if args.lstm_incidents or args.gnn_incidents:
        specific = {"lstm": args.lstm_incidents, "gnn_lstm": args.gnn_incidents}
    result = audit(
        report,
        incident_file=args.verified_incidents,
        incident_files=specific,
        fpr_limit=args.fpr_limit,
        recall_floor=args.recall_floor,
        min_family_positives=args.min_family_positives,
        min_family_negatives=args.min_family_negatives,
        min_verified_incidents=args.min_verified_incidents,
    )
    Path(args.output).parent.mkdir(parents=True, exist_ok=True)
    Path(args.output).write_text(json.dumps(result, indent=2, sort_keys=True) + "\n")
    print(json.dumps(result, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
