"""V118 development-only persistence-innovation calibration for the frozen V116 model.

A single scalar alpha is fit on CICAPT Phase-1 validation only for the convex blend
  forecast = persistence + alpha * (V116_model - persistence)
using raw reconstructed state MSE. Phase-2 is evaluation-only. All consumed external
holdouts, including V117 Kitsune Mirai, are excluded from fitting and selection.
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path

import numpy as np

from .model import GraphWorldModel
from .ps_complete import FEATURES
from .support_gate import score as support_score
from .v101_packet_graph_recovery import (
    PHASE1_NAME, PHASE2_NAME, PHASE1_SHA256, PHASE2_SHA256,
    verify_development_capture, build_sequences, chronological_phase1_split,
    persistence_prediction, infer_state, file_hash, canonical_sha256,
)
from .v112_tolerant_ps_complete_runtime import tolerant_packet_service_graphs
from .v115_relative_state_world_model import apply_transform, inverse_pooled, RELATIVE_SCHEMA, RAW_SCHEMA

MODEL_SHA256 = "1c326e66f487f5947f526c68469025ffb3410b6f0e63bfc3ee0e9f72ba81031c"
SUPPORT_SHA256 = "8a7eb42d73797d59ccb84644b93253f70c5552a7be38b205530cc9fc69044fc5"
TRANSFORM_SHA256 = "6d5dee6ce930ed041e9921e5f5d1e8281838eb3799c96f338ed3a9d8a7e37643"
MAX_PACKETS = 2_000_000


class V118ContractError(RuntimeError):
    pass


def raw_mse(pred, target) -> float:
    return float(np.mean((pred - target) ** 2, dtype=np.float64))


def fit_alpha(model_pred, persistence_pred, target) -> float:
    d = (model_pred - persistence_pred).astype(np.float64, copy=False)
    r = (target - persistence_pred).astype(np.float64, copy=False)
    denom = float(np.sum(d * d, dtype=np.float64))
    if not np.isfinite(denom) or denom <= 1e-18:
        raise V118ContractError("Degenerate innovation denominator")
    alpha = float(np.sum(d * r, dtype=np.float64) / denom)
    return float(np.clip(alpha, 0.0, 1.0))


def metrics(model_pred, persistence_pred, target, alpha: float) -> dict:
    calibrated = persistence_pred + float(alpha) * (model_pred - persistence_pred)
    mm = raw_mse(model_pred, target)
    pm = raw_mse(persistence_pred, target)
    cm = raw_mse(calibrated, target)
    return {
        "base_model_mse": mm,
        "persistence_mse": pm,
        "calibrated_mse": cm,
        "base_improvement_vs_persistence": float((pm-mm)/pm) if pm else 0.0,
        "calibrated_improvement_vs_persistence": float((pm-cm)/pm) if pm else 0.0,
        "calibrated_beats_persistence": bool(cm < pm),
        "calibrated_beats_or_matches_base_model": bool(cm <= mm + 1e-15),
    }


def raw_predictions(model, raw_sequences, adj, mask, raw_target, transform, batch_size=64):
    rel_x, _, centers = apply_transform(raw_sequences, raw_target, mask, transform)
    rel_pred = infer_state(model, rel_x, adj, mask, batch_size=batch_size)
    raw_pred = inverse_pooled(rel_pred, centers, transform)
    persistence = persistence_prediction(raw_sequences, mask)
    return rel_x, raw_pred, persistence


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--phase1", required=True, type=Path)
    ap.add_argument("--phase2", required=True, type=Path)
    ap.add_argument("--model", required=True, type=Path)
    ap.add_argument("--support-gate", required=True, type=Path)
    ap.add_argument("--relative-transform", required=True, type=Path)
    ap.add_argument("--output-dir", required=True, type=Path)
    ap.add_argument("--packet-limit", type=int, default=MAX_PACKETS)
    args = ap.parse_args()

    if file_hash(args.model) != MODEL_SHA256:
        raise V118ContractError("Frozen V116 model hash mismatch")
    if file_hash(args.support_gate) != SUPPORT_SHA256:
        raise V118ContractError("Frozen V116 support gate hash mismatch")
    if file_hash(args.relative_transform) != TRANSFORM_SHA256:
        raise V118ContractError("Frozen V116 transform hash mismatch")
    p1sha = verify_development_capture(args.phase1, PHASE1_NAME, PHASE1_SHA256)
    p2sha = verify_development_capture(args.phase2, PHASE2_NAME, PHASE2_SHA256)

    model, meta = GraphWorldModel.load(args.model)
    if model.schema != RELATIVE_SCHEMA or model.f != len(FEATURES):
        raise V118ContractError("V116 model schema mismatch")
    if meta.get("raw_input_schema") != RAW_SCHEMA:
        raise V118ContractError("V116 raw schema mismatch")
    transform = json.loads(args.relative_transform.read_text())
    gate = json.loads(args.support_gate.read_text())

    t1,x1,a1,m1,n1,audit1 = tolerant_packet_service_graphs(args.phase1,args.packet_limit)
    t2,x2,a2,m2,n2,audit2 = tolerant_packet_service_graphs(args.phase2,args.packet_limit)
    sx1,sa1,sm1,sy1,_ = build_sequences(t1,x1,a1,m1)
    sx2,sa2,sm2,sy2,_ = build_sequences(t2,x2,a2,m2)
    train_ids,val_ids = chronological_phase1_split(len(sx1))
    del train_ids

    val_raw = sx1[val_ids]; val_adj=sa1[val_ids]; val_mask=sm1[val_ids]; val_target=sy1[val_ids]
    val_rel, val_model, val_persist = raw_predictions(model,val_raw,val_adj,val_mask,val_target,transform)
    p2_rel, p2_model, p2_persist = raw_predictions(model,sx2,sa2,sm2,sy2,transform)

    alpha = fit_alpha(val_model,val_persist,val_target)
    val_metrics = metrics(val_model,val_persist,val_target,alpha)
    p2_metrics = metrics(p2_model,p2_persist,sy2,alpha)

    support_scores = support_score(gate,p2_rel,sm2)
    threshold=float(gate['threshold'])
    supported=support_scores<=threshold
    support_fraction=float(supported.mean())

    gates={
        "alpha_strictly_positive": bool(alpha > 0.0),
        "alpha_at_most_one": bool(alpha <= 1.0),
        "validation_calibrated_beats_persistence": bool(val_metrics['calibrated_beats_persistence']),
        "phase2_calibrated_beats_persistence": bool(p2_metrics['calibrated_beats_persistence']),
        "phase2_supported_fraction_at_least_0_95": bool(support_fraction >= 0.95),
        "all_metrics_finite": bool(np.isfinite([alpha,val_metrics['calibrated_mse'],p2_metrics['calibrated_mse']]).all()),
    }
    passed=all(gates.values())

    args.output_dir.mkdir(parents=True,exist_ok=True)
    calibration={
        "schema_version":"v118-calibration.1",
        "method":"global convex persistence-innovation shrinkage",
        "formula":"forecast = persistence + alpha * (frozen_v116_forecast - persistence)",
        "alpha":alpha,
        "fit_source":"CICAPT Phase-1 validation only",
        "fit_metric":"raw reconstructed pooled-state MSE",
        "model_sha256":MODEL_SHA256,
        "support_gate_sha256":SUPPORT_SHA256,
        "relative_transform_sha256":TRANSFORM_SHA256,
        "phase2_used_for_fit":False,
        "external_used_for_fit":False,
        "consumed_external_used_for_fit":False,
    }
    cal_path=args.output_dir/'innovation_calibration.json'
    cal_path.write_text(json.dumps(calibration,indent=2,allow_nan=False)+'\n')

    report={
        "schema_version":"v118.1",
        "status":"DEV_INNOVATION_CALIBRATION_PASS" if passed else "DEV_INNOVATION_CALIBRATION_FAIL",
        "recovery_gate_passed":passed,
        "claim_boundary":"Development-only innovation calibration. V117 and every consumed external holdout remain quarantined; no fresh external, stage, risk, or precompromise claim is created.",
        "base_candidate":{"version":"V116","model_sha256":MODEL_SHA256,"support_gate_sha256":SUPPORT_SHA256,"relative_transform_sha256":TRANSFORM_SHA256},
        "development_sources":{
            "phase1":{"capture":PHASE1_NAME,"sha256":p1sha,"decoded_ipv4_packets":int(n1),"parser_audit":audit1,"validation_sequences":int(len(val_ids)),"used_for_alpha_fit":True},
            "phase2":{"capture":PHASE2_NAME,"sha256":p2sha,"decoded_ipv4_packets":int(n2),"parser_audit":audit2,"sequences":int(len(sx2)),"used_for_alpha_fit":False},
        },
        "calibration":calibration,
        "calibration_sha256":file_hash(cal_path),
        "validation":val_metrics,
        "phase2_sanity":p2_metrics,
        "phase2_support":{"threshold":threshold,"supported_sequences":int(supported.sum()),"total_sequences":int(len(supported)),"supported_fraction":support_fraction,"median_score":float(np.median(support_scores)),"max_score":float(np.max(support_scores))},
        "gates":gates,
        "freeze":{"calibration_file":cal_path.name,"calibration_sha256":file_hash(cal_path),"candidate_runtime_frozen_before_new_external_selection":bool(passed),"new_external_holdout_selected":False},
        "external_quarantine":["V99 HIKARI","V102 MAWI","V104 CTU-IDSEVAL-6","V106 USTC Miuref","V111 CTU 327-1","V113 CTU 111-1","V114 CTU 326-1","V117 Kitsune Mirai"]
    }
    (args.output_dir/'summary.json').write_text(json.dumps(report,indent=2,allow_nan=False)+'\n')
    print(json.dumps({'status':report['status'],'alpha':alpha,'validation':val_metrics,'phase2':p2_metrics,'support':report['phase2_support'],'gates':gates},indent=2))
    return 0


if __name__=='__main__':
    raise SystemExit(main())
