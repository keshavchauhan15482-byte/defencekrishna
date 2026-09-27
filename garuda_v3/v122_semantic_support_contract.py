"""V122 development-only semantic runtime support contract.

V120's robust behavior envelope remains useful as a distribution-shift diagnostic, but
its own artifact explicitly says support abstention is not attack/OOD detection. V122
therefore separates two concepts before selecting any new external holdout:

1. hard runtime support = the frozen 34-feature graph contract is numerically valid,
   every history window has observed nodes, required packet telemetry is present, and
   the frozen V116 relative transform yields finite model input;
2. behavior-envelope distance = advisory diagnostic only, never an attack label and
   never a hard compatibility veto.

No consumed external capture, including V121 Honeynet FC09, is read or used to set any
threshold in this module. V121 remains an immutable FAIL under its preregistered gate.
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path

import numpy as np

from .ps_complete import FEATURES
from .v101_packet_graph_recovery import (
    PHASE1_NAME, PHASE2_NAME, PHASE1_SHA256, PHASE2_SHA256,
    verify_development_capture, build_sequences, chronological_phase1_split, file_hash,
)
from .v112_tolerant_ps_complete_runtime import tolerant_packet_service_graphs
from .v115_relative_state_world_model import apply_transform, RELATIVE_SCHEMA, RAW_SCHEMA
from .v120_robust_support_envelope import summary_row as behavior_summary, presence_coverage

MODEL_SHA256 = "1c326e66f487f5947f526c68469025ffb3410b6f0e63bfc3ee0e9f72ba81031c"
TRANSFORM_SHA256 = "6d5dee6ce930ed041e9921e5f5d1e8281838eb3799c96f338ed3a9d8a7e37643"
CALIBRATION_SHA256 = "c130d235cfcc59803cc27b29cfe67b6e8245b1b8296f98dd3acfe922d023b701"
ROBUST_GATE_SHA256 = "3218ff33b0ada393b1a6aa16c9d5948a848a2d6648a9f900c07bd9c91c8028c4"
MAX_PACKETS = 2_000_000
PRESENCE_START = 29
PRESENCE_NAMES = tuple(FEATURES[PRESENCE_START:])
REQUIRED_CAPABILITY = "packet_features_present"
MIN_PACKET_CAPABILITY = 0.95


class V122ContractError(RuntimeError):
    pass


def semantic_decisions(raw_x: np.ndarray, model_x: np.ndarray, mask: np.ndarray):
    if raw_x.ndim != 4 or model_x.shape != raw_x.shape or mask.shape != raw_x.shape[:3]:
        raise V122ContractError("Unexpected sequence/mask shape")
    if raw_x.shape[-1] != len(FEATURES):
        raise V122ContractError("Feature-count mismatch")

    finite_raw = np.isfinite(raw_x).all(axis=(1, 2, 3))
    finite_model = np.isfinite(model_x).all(axis=(1, 2, 3))
    finite_mask = np.isfinite(mask).all(axis=(1, 2))
    binary_mask = ((mask >= -1e-6) & (mask <= 1.0 + 1e-6)).all(axis=(1, 2))
    history_has_observation = (mask.sum(axis=2) > 0.0).all(axis=1)

    presence = presence_coverage(raw_x, mask)
    bounded_presence = (
        np.isfinite(presence).all(axis=1)
        & (presence >= -1e-6).all(axis=1)
        & (presence <= 1.0 + 1e-6).all(axis=1)
    )
    req_idx = PRESENCE_NAMES.index(REQUIRED_CAPABILITY)
    packet_capability = presence[:, req_idx]
    packet_ok = packet_capability >= MIN_PACKET_CAPABILITY

    supported = (
        finite_raw & finite_model & finite_mask & binary_mask
        & history_has_observation & bounded_presence & packet_ok
    )
    return {
        "supported": supported,
        "finite_raw": finite_raw,
        "finite_model": finite_model,
        "finite_mask": finite_mask,
        "binary_mask": binary_mask,
        "history_has_observation": history_has_observation,
        "bounded_presence": bounded_presence,
        "packet_ok": packet_ok,
        "presence": presence,
    }


def semantic_summary(raw_x: np.ndarray, model_x: np.ndarray, mask: np.ndarray) -> dict:
    d = semantic_decisions(raw_x, model_x, mask)
    n = len(d["supported"])
    presence = d["presence"]
    req_idx = PRESENCE_NAMES.index(REQUIRED_CAPABILITY)
    def frac(v):
        return float(v.mean()) if len(v) else 0.0
    means = presence.mean(axis=0) if len(presence) else np.zeros(len(PRESENCE_NAMES), dtype=np.float64)
    return {
        "supported_sequences": int(d["supported"].sum()),
        "total_sequences": int(n),
        "supported_fraction": frac(d["supported"]),
        "finite_raw_fraction": frac(d["finite_raw"]),
        "finite_model_input_fraction": frac(d["finite_model"]),
        "valid_mask_fraction": frac(d["finite_mask"] & d["binary_mask"]),
        "complete_history_observation_fraction": frac(d["history_has_observation"]),
        "bounded_presence_fraction": frac(d["bounded_presence"]),
        "packet_capability_compatible_fraction": frac(d["packet_ok"]),
        "required_packet_capability_mean": float(means[req_idx]),
        "presence_feature_means": {name: float(means[i]) for i, name in enumerate(PRESENCE_NAMES)},
    }


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--phase1", required=True, type=Path)
    ap.add_argument("--phase2", required=True, type=Path)
    ap.add_argument("--model", required=True, type=Path)
    ap.add_argument("--relative-transform", required=True, type=Path)
    ap.add_argument("--calibration", required=True, type=Path)
    ap.add_argument("--robust-support-gate", required=True, type=Path)
    ap.add_argument("--output-dir", required=True, type=Path)
    ap.add_argument("--packet-limit", type=int, default=MAX_PACKETS)
    args = ap.parse_args()

    if len(FEATURES) != 34 or tuple(PRESENCE_NAMES) != (
        "packet_features_present", "iat_present", "tcp_window_present",
        "payload_present", "scan_sequence_present",
    ):
        raise V122ContractError("V122 requires the frozen 34-feature PS-complete schema")
    for path, expected, label in (
        (args.model, MODEL_SHA256, "V116 model"),
        (args.relative_transform, TRANSFORM_SHA256, "V116 transform"),
        (args.calibration, CALIBRATION_SHA256, "V118 calibration"),
        (args.robust_support_gate, ROBUST_GATE_SHA256, "V120 robust gate"),
    ):
        if file_hash(path) != expected:
            raise V122ContractError(f"{label} hash mismatch")

    transform = json.loads(args.relative_transform.read_text())
    calibration = json.loads(args.calibration.read_text())
    behavior_gate = json.loads(args.robust_support_gate.read_text())
    if calibration.get("external_used_for_fit") is not False:
        raise V122ContractError("Calibration provenance is not external-clean")
    if behavior_gate.get("fit_provenance", {}).get("all_consumed_external_holdouts_excluded_from_fit") is not True:
        raise V122ContractError("V120 gate provenance is not external-clean")

    p1sha = verify_development_capture(args.phase1, PHASE1_NAME, PHASE1_SHA256)
    p2sha = verify_development_capture(args.phase2, PHASE2_NAME, PHASE2_SHA256)
    t1,x1,a1,m1,n1,audit1 = tolerant_packet_service_graphs(args.phase1,args.packet_limit)
    t2,x2,a2,m2,n2,audit2 = tolerant_packet_service_graphs(args.phase2,args.packet_limit)
    sx1,sa1,sm1,sy1,_ = build_sequences(t1,x1,a1,m1)
    sx2,sa2,sm2,sy2,_ = build_sequences(t2,x2,a2,m2)
    del sa1, sa2
    train_ids,val_ids = chronological_phase1_split(len(sx1))
    del train_ids

    rel1,_,_ = apply_transform(sx1,sy1,sm1,transform)
    rel2,_,_ = apply_transform(sx2,sy2,sm2,transform)
    val_sem = semantic_summary(sx1[val_ids],rel1[val_ids],sm1[val_ids])
    p2_sem = semantic_summary(sx2,rel2,sm2)
    val_behavior = behavior_summary(behavior_gate,rel1[val_ids],sm1[val_ids])
    p2_behavior = behavior_summary(behavior_gate,rel2,sm2)

    gates = {
        "validation_semantic_support_at_least_0_99": bool(val_sem["supported_fraction"] >= 0.99),
        "phase2_semantic_support_at_least_0_99": bool(p2_sem["supported_fraction"] >= 0.99),
        "validation_finite_model_input_is_1": bool(val_sem["finite_model_input_fraction"] >= 0.999999),
        "phase2_finite_model_input_is_1": bool(p2_sem["finite_model_input_fraction"] >= 0.999999),
        "validation_packet_capability_at_least_0_95": bool(val_sem["required_packet_capability_mean"] >= 0.95),
        "phase2_packet_capability_at_least_0_95": bool(p2_sem["required_packet_capability_mean"] >= 0.95),
        "behavior_envelope_is_advisory_not_attack_or_compatibility_label": True,
        "all_consumed_external_holdouts_excluded_from_design_fit_and_thresholding": True,
    }
    passed = all(gates.values())

    args.output_dir.mkdir(parents=True,exist_ok=True)
    contract = {
        "schema_version":"v122-semantic-support.1",
        "status":"FROZEN" if passed else "NOT_FROZEN",
        "hard_support_definition":{
            "raw_graph_values_finite":True,
            "relative_model_input_values_finite":True,
            "mask_finite_and_bounded_0_1":True,
            "each_history_window_has_at_least_one_observed_node":True,
            "presence_flags_finite_and_bounded_0_1":True,
            "required_packet_capability":REQUIRED_CAPABILITY,
            "minimum_required_packet_capability":MIN_PACKET_CAPABILITY,
        },
        "behavior_shift_diagnostic":{
            "source":"V120 robust validation envelope",
            "gate_sha256":ROBUST_GATE_SHA256,
            "hard_veto":False,
            "attack_or_ood_label":False,
            "purpose":"Report distribution shift without conflating it with input-contract incompatibility.",
        },
        "frozen_runtime":{
            "model_sha256":MODEL_SHA256,
            "relative_transform_sha256":TRANSFORM_SHA256,
            "innovation_calibration_sha256":CALIBRATION_SHA256,
            "robust_behavior_gate_sha256":ROBUST_GATE_SHA256,
            "alpha":float(calibration["alpha"]),
            "raw_schema":RAW_SCHEMA,
            "model_schema":RELATIVE_SCHEMA,
            "feature_count":len(FEATURES),
        },
        "provenance":{
            "semantic_thresholds_fixed_by_schema_capability_not_external_statistics":True,
            "v121_bytes_read":False,
            "v121_metrics_used_for_fit_or_thresholding":False,
            "all_consumed_external_holdouts_excluded":True,
            "new_external_holdout_selected":False,
        },
    }
    contract_path=args.output_dir/'semantic_support_contract.json'
    contract_path.write_text(json.dumps(contract,indent=2,allow_nan=False)+'\n')

    report={
        "schema_version":"v122.1",
        "status":"DEV_SEMANTIC_SUPPORT_PASS" if passed else "DEV_SEMANTIC_SUPPORT_FAIL",
        "recovery_gate_passed":passed,
        "claim_boundary":"Development-only support-semantics recovery. V121 remains FAIL under its original preregistration; no consumed external is rescored or upgraded.",
        "development_sources":{
            "phase1":{"capture":PHASE1_NAME,"sha256":p1sha,"decoded_ipv4_packets":int(n1),"parser_audit":audit1,"validation_sequences":int(len(val_ids))},
            "phase2":{"capture":PHASE2_NAME,"sha256":p2sha,"decoded_ipv4_packets":int(n2),"parser_audit":audit2,"sequences":int(len(sx2)),"used_for_fit":False},
        },
        "semantic_support":{"validation":val_sem,"phase2":p2_sem},
        "behavior_shift_diagnostic":{"validation":val_behavior,"phase2":p2_behavior,"hard_veto":False},
        "gates":gates,
        "freeze":{
            "semantic_support_contract_file":contract_path.name,
            "semantic_support_contract_sha256":file_hash(contract_path),
            "candidate_runtime_frozen_before_new_external_selection":bool(passed),
            "new_external_holdout_selected":False,
        },
        "external_quarantine":["V99 HIKARI","V102 MAWI","V104 CTU-IDSEVAL-6","V106 USTC Miuref","V111 CTU 327-1","V113 CTU 111-1","V114 CTU 326-1","V117 Kitsune Mirai","V119 MTA FormBook","V121 Honeynet FC09"],
    }
    (args.output_dir/'summary.json').write_text(json.dumps(report,indent=2,allow_nan=False)+'\n')
    print(json.dumps({'status':report['status'],'semantic_support':report['semantic_support'],'behavior_shift_diagnostic':report['behavior_shift_diagnostic'],'gates':gates,'freeze':report['freeze']},indent=2))
    return 0


if __name__=='__main__':
    raise SystemExit(main())
