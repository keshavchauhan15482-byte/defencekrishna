"""V120 development-only robust runtime-support envelope for the frozen V118 runtime.

The earlier support gate used the maximum standardized deviation over all summary
coordinates, so one unusual feature could veto an otherwise valid forecast. V120 keeps
fail-closed telemetry checks but replaces that single-coordinate maximum with a robust
multi-coordinate envelope: train-only robust center/scale, validation-only per-component
99th-percentile envelopes, and a validation-only 99th-percentile exceedance-fraction
cutoff. Phase-2 is evaluation-only. Every consumed external holdout through V119 is
quarantined and is never read by this module.
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path

import numpy as np

from .ps_complete import FEATURES
from .v101_packet_graph_recovery import (
    PHASE1_NAME, PHASE2_NAME, PHASE1_SHA256, PHASE2_SHA256,
    verify_development_capture, build_sequences, chronological_phase1_split,
    pooled_history, file_hash,
)
from .v112_tolerant_ps_complete_runtime import tolerant_packet_service_graphs
from .v115_relative_state_world_model import apply_transform, RELATIVE_SCHEMA, RAW_SCHEMA

MODEL_SHA256 = "1c326e66f487f5947f526c68469025ffb3410b6f0e63bfc3ee0e9f72ba81031c"
TRANSFORM_SHA256 = "6d5dee6ce930ed041e9921e5f5d1e8281838eb3799c96f338ed3a9d8a7e37643"
CALIBRATION_SHA256 = "c130d235cfcc59803cc27b29cfe67b6e8245b1b8296f98dd3acfe922d023b701"
MAX_PACKETS = 2_000_000
BEHAVIOUR_COUNT = 29
PRESENCE_NAMES = tuple(FEATURES[29:])
EXPECTED_PRESENCE = (
    "packet_features_present", "iat_present", "tcp_window_present",
    "payload_present", "scan_sequence_present",
)
MIN_PRESENCE = 0.95
SCALE_FLOOR = 0.05
COMPONENT_QUANTILE = 0.99
SEQUENCE_QUANTILE = 0.99


class V120ContractError(RuntimeError):
    pass


def behaviour_components(x: np.ndarray, mask: np.ndarray) -> np.ndarray:
    """History-only, scale-aware behavioural summaries for support validation.

    x is already V116 history-relative. We summarize both relative level and temporal
    innovation magnitude, while excluding sensor-presence flags from distributional
    scoring because those are checked explicitly as hard telemetry requirements.
    """
    pooled = pooled_history(x, mask)[..., :BEHAVIOUR_COUNT]
    level = pooled.mean(axis=1)
    if pooled.shape[1] < 2:
        delta = np.zeros_like(level)
    else:
        delta = np.median(np.abs(np.diff(pooled, axis=1)), axis=1)
    return np.concatenate([level, delta], axis=1).astype(np.float64, copy=False)


def presence_coverage(x: np.ndarray, mask: np.ndarray) -> np.ndarray:
    denom = np.maximum(mask.sum(axis=(1, 2), keepdims=False)[:, None], 1.0)
    numer = (x[..., BEHAVIOUR_COUNT:] * mask[..., None]).sum(axis=(1, 2))
    return (numer / denom).astype(np.float64, copy=False)


def fit_gate(train_x: np.ndarray, train_mask: np.ndarray, valid_x: np.ndarray, valid_mask: np.ndarray) -> dict:
    train = behaviour_components(train_x, train_mask)
    valid = behaviour_components(valid_x, valid_mask)
    center = np.median(train, axis=0)
    scale = 1.4826 * np.median(np.abs(train - center), axis=0)
    scale = np.maximum(scale, SCALE_FLOOR)
    vz = np.abs(valid - center) / scale
    component_cutoff = np.quantile(vz, COMPONENT_QUANTILE, axis=0, method="higher")
    component_cutoff = np.maximum(component_cutoff, 1.0)
    exceed_fraction = (vz > component_cutoff).mean(axis=1)
    threshold = float(np.quantile(exceed_fraction, SEQUENCE_QUANTILE, method="higher"))
    return {
        "schema_version": "v120-support.1",
        "method": "robust validation envelope exceedance fraction",
        "target": "input support, not attack probability",
        "interpretation": "Support abstention is not attack/OOD detection.",
        "raw_schema": RAW_SCHEMA,
        "model_schema": RELATIVE_SCHEMA,
        "features": list(FEATURES),
        "behaviour_feature_count": BEHAVIOUR_COUNT,
        "component_order": [f"level:{n}" for n in FEATURES[:BEHAVIOUR_COUNT]] + [f"delta:{n}" for n in FEATURES[:BEHAVIOUR_COUNT]],
        "center": center.tolist(),
        "scale": scale.tolist(),
        "scale_floor": SCALE_FLOOR,
        "component_quantile": COMPONENT_QUANTILE,
        "component_cutoff": component_cutoff.tolist(),
        "sequence_quantile": SEQUENCE_QUANTILE,
        "threshold": threshold,
        "presence_features": list(PRESENCE_NAMES),
        "minimum_presence": MIN_PRESENCE,
        "fit_provenance": {
            "center_scale": "CICAPT Phase-1 train only",
            "component_cutoffs": "CICAPT Phase-1 validation only",
            "sequence_threshold": "CICAPT Phase-1 validation only",
            "phase2_excluded_from_fit": True,
            "all_consumed_external_holdouts_excluded_from_fit": True,
        },
    }


def score(gate: dict, x: np.ndarray, mask: np.ndarray) -> np.ndarray:
    c = behaviour_components(x, mask)
    center = np.asarray(gate["center"], dtype=np.float64)
    scale = np.asarray(gate["scale"], dtype=np.float64)
    cutoff = np.asarray(gate["component_cutoff"], dtype=np.float64)
    z = np.abs(c - center) / scale
    return (z > cutoff).mean(axis=1)


def decisions(gate: dict, x: np.ndarray, mask: np.ndarray):
    scores = score(gate, x, mask)
    presence = presence_coverage(x, mask)
    telemetry_ok = (presence >= float(gate["minimum_presence"])).all(axis=1)
    supported = (scores <= float(gate["threshold"])) & telemetry_ok
    return scores, presence, telemetry_ok, supported


def summary_row(gate: dict, x: np.ndarray, mask: np.ndarray) -> dict:
    scores, presence, telemetry_ok, supported = decisions(gate, x, mask)
    return {
        "supported_sequences": int(supported.sum()),
        "total_sequences": int(len(supported)),
        "supported_fraction": float(supported.mean()) if len(supported) else 0.0,
        "telemetry_compatible_sequences": int(telemetry_ok.sum()),
        "telemetry_compatible_fraction": float(telemetry_ok.mean()) if len(telemetry_ok) else 0.0,
        "minimum_presence_mean": float(presence.mean(axis=0).min()) if len(presence) else 0.0,
        "median_exceedance_fraction": float(np.median(scores)) if len(scores) else 1.0,
        "max_exceedance_fraction": float(np.max(scores)) if len(scores) else 1.0,
        "threshold": float(gate["threshold"]),
    }


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--phase1", required=True, type=Path)
    ap.add_argument("--phase2", required=True, type=Path)
    ap.add_argument("--model", required=True, type=Path)
    ap.add_argument("--relative-transform", required=True, type=Path)
    ap.add_argument("--calibration", required=True, type=Path)
    ap.add_argument("--output-dir", required=True, type=Path)
    ap.add_argument("--packet-limit", type=int, default=MAX_PACKETS)
    args = ap.parse_args()

    if tuple(PRESENCE_NAMES) != EXPECTED_PRESENCE or len(FEATURES) != 34:
        raise V120ContractError("V120 requires the frozen 34-feature PS-complete contract")
    if file_hash(args.model) != MODEL_SHA256:
        raise V120ContractError("Frozen V116 model hash mismatch")
    if file_hash(args.relative_transform) != TRANSFORM_SHA256:
        raise V120ContractError("Frozen V116 transform hash mismatch")
    if file_hash(args.calibration) != CALIBRATION_SHA256:
        raise V120ContractError("Frozen V118 calibration hash mismatch")
    calibration = json.loads(args.calibration.read_text())
    if calibration.get("external_used_for_fit") is not False or calibration.get("consumed_external_used_for_fit") is not False:
        raise V120ContractError("V118 calibration provenance is not external-clean")

    p1sha = verify_development_capture(args.phase1, PHASE1_NAME, PHASE1_SHA256)
    p2sha = verify_development_capture(args.phase2, PHASE2_NAME, PHASE2_SHA256)
    t1,x1,a1,m1,n1,audit1 = tolerant_packet_service_graphs(args.phase1,args.packet_limit)
    t2,x2,a2,m2,n2,audit2 = tolerant_packet_service_graphs(args.phase2,args.packet_limit)
    sx1,sa1,sm1,sy1,_ = build_sequences(t1,x1,a1,m1)
    sx2,sa2,sm2,sy2,_ = build_sequences(t2,x2,a2,m2)
    del sa1, sa2
    train_ids,val_ids = chronological_phase1_split(len(sx1))

    transform=json.loads(args.relative_transform.read_text())
    rel1,_,_ = apply_transform(sx1,sy1,sm1,transform)
    rel2,_,_ = apply_transform(sx2,sy2,sm2,transform)
    gate = fit_gate(rel1[train_ids],sm1[train_ids],rel1[val_ids],sm1[val_ids])
    validation = summary_row(gate,rel1[val_ids],sm1[val_ids])
    phase2 = summary_row(gate,rel2,sm2)

    gates = {
        "validation_supported_fraction_at_least_0_98": bool(validation["supported_fraction"] >= 0.98),
        "phase2_supported_fraction_at_least_0_95": bool(phase2["supported_fraction"] >= 0.95),
        "validation_telemetry_compatibility_at_least_0_99": bool(validation["telemetry_compatible_fraction"] >= 0.99),
        "phase2_telemetry_compatibility_at_least_0_99": bool(phase2["telemetry_compatible_fraction"] >= 0.99),
        "support_threshold_finite": bool(np.isfinite(gate["threshold"])),
        "external_used_for_fit": False,
    }
    passed = all(v is True for v in gates.values())

    args.output_dir.mkdir(parents=True,exist_ok=True)
    gate_path=args.output_dir/'robust_support_gate.json'
    gate_path.write_text(json.dumps(gate,indent=2,allow_nan=False)+'\n')
    gate_sha=file_hash(gate_path)
    report={
        "schema_version":"v120.1",
        "status":"DEV_ROBUST_SUPPORT_PASS" if passed else "DEV_ROBUST_SUPPORT_FAIL",
        "recovery_gate_passed":passed,
        "claim_boundary":"Development-only support-contract recovery. V119 and all earlier external holdouts remain quarantined; no new external, attack, stage, or precompromise claim is created.",
        "runtime":{
            "model_sha256":MODEL_SHA256,
            "relative_transform_sha256":TRANSFORM_SHA256,
            "innovation_calibration_sha256":CALIBRATION_SHA256,
            "robust_support_gate_sha256":gate_sha,
            "alpha":float(calibration["alpha"]),
            "feature_count":len(FEATURES),
            "raw_schema":RAW_SCHEMA,
            "model_schema":RELATIVE_SCHEMA,
        },
        "development_sources":{
            "phase1":{"capture":PHASE1_NAME,"sha256":p1sha,"decoded_ipv4_packets":int(n1),"parser_audit":audit1,"train_sequences":int(len(train_ids)),"validation_sequences":int(len(val_ids))},
            "phase2":{"capture":PHASE2_NAME,"sha256":p2sha,"decoded_ipv4_packets":int(n2),"parser_audit":audit2,"sequences":int(len(sx2)),"used_for_fit":False},
        },
        "support_design":{
            "reason":"Replace brittle single-coordinate maximum veto with validation-fitted multi-coordinate envelope while retaining hard packet/sensor presence requirements.",
            "v119_statistics_used_for_fit_or_thresholding":False,
            "consumed_external_bytes_read":False,
            "gate":gate,
        },
        "validation":validation,
        "phase2_sanity":phase2,
        "gates":gates,
        "freeze":{
            "robust_support_gate_file":gate_path.name,
            "robust_support_gate_sha256":gate_sha,
            "candidate_runtime_frozen_before_new_external_selection":bool(passed),
            "new_external_holdout_selected":False,
        },
        "external_quarantine":["V99 HIKARI","V102 MAWI","V104 CTU-IDSEVAL-6","V106 USTC Miuref","V111 CTU 327-1","V113 CTU 111-1","V114 CTU 326-1","V117 Kitsune Mirai","V119 MTA FormBook"]
    }
    (args.output_dir/'summary.json').write_text(json.dumps(report,indent=2,allow_nan=False)+'\n')
    print(json.dumps({'status':report['status'],'validation':validation,'phase2':phase2,'gates':gates,'freeze':report['freeze']},indent=2))
    return 0


if __name__=='__main__':
    raise SystemExit(main())
