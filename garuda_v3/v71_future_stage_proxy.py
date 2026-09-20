"""V71 forecast-state attack-stage proxy benchmark on X-IIoTID.

The SIH requirement asks the future network state to be mapped to attack stages. This
benchmark trains the Garuda residual world model on chronological development data,
trains a stage mapper on *ground-truth future network states* from training only, then
feeds the mapper Garuda's forecast states in the held-out chronological test period.

Four labels are direct lifecycle-name matches (Reconnaissance, Lateral Movement,
Command & Control, Exfiltration). X-IIoTID's ``Exploitation`` lifecycle class is mapped
to ``Initial Access proxy`` and is NEVER reported as exact MITRE Initial Access truth.
No attack label is a world-model input.
"""
from __future__ import annotations

import argparse
import json
from collections import Counter
from pathlib import Path

import numpy as np
import pandas as pd
from sklearn.ensemble import ExtraTreesClassifier
from sklearn.metrics import confusion_matrix, f1_score, precision_score, recall_score

from .v47_unseen_family import (
    build_minute_state,
    choose_network_numeric_features,
    detect_label_hierarchy,
    make_sequences,
    parse_time,
    temporal_masks,
)
from .v48_strict_runner import canonical_family_name
from .v60_residual_state_forecasting import train_residual_world_model

STAGES = (
    "Reconnaissance",
    "Initial Access proxy",
    "Lateral Movement",
    "Command & Control",
    "Exfiltration",
)
RANK = {name: i for i, name in enumerate(STAGES)}


def stage_name(raw):
    x = canonical_family_name(raw)
    if x in {"reconnaissance", "recon"}:
        return "Reconnaissance"
    if x in {"exploitation", "exploit"}:
        return "Initial Access proxy"
    if x in {"lateral movement", "lateralmovement"}:
        return "Lateral Movement"
    if x in {"c&c", "candc", "command and control", "command&control", "commandcontrol"}:
        return "Command & Control"
    if x in {"exfiltration", "exfil"}:
        return "Exfiltration"
    return None


def future_stage_targets(seq):
    out = np.full(len(seq["X"]), -1, dtype=np.int16)
    raw_support = Counter()
    for i, steps in enumerate(seq["step_families"]):
        mapped = []
        for fams in steps:
            for fam in fams:
                s = stage_name(fam)
                if s is not None:
                    mapped.append(s)
                    raw_support[s] += 1
        if mapped:
            # Deterministic "furthest progression in the future horizon" target.
            out[i] = max(RANK[s] for s in mapped)
    return out, dict(raw_support)


def exact_metrics(y_true, y_pred):
    labels = np.arange(len(STAGES))
    cm = confusion_matrix(y_true, y_pred, labels=labels)
    per = {}
    for i, stage in enumerate(STAGES):
        tp = int(cm[i, i])
        fn = int(cm[i, :].sum() - tp)
        fp = int(cm[:, i].sum() - tp)
        tn = int(cm.sum() - tp - fn - fp)
        recall = tp / (tp + fn) if tp + fn else None
        precision = tp / (tp + fp) if tp + fp else None
        per[stage] = {
            "support": int(cm[i, :].sum()),
            "tp": tp, "fp": fp, "fn": fn, "tn": tn,
            "recall": recall, "precision": precision,
        }
    supported = [i for i in labels if cm[i, :].sum() > 0]
    macro_f1 = float(f1_score(y_true, y_pred, labels=supported, average="macro", zero_division=0)) if supported else None
    macro_recall = float(recall_score(y_true, y_pred, labels=supported, average="macro", zero_division=0)) if supported else None
    macro_precision = float(precision_score(y_true, y_pred, labels=supported, average="macro", zero_division=0)) if supported else None
    accuracy = float((np.asarray(y_true) == np.asarray(y_pred)).mean()) if len(y_true) else None
    return {
        "samples": int(len(y_true)),
        "accuracy": accuracy,
        "macro_f1_supported_classes": macro_f1,
        "macro_recall_supported_classes": macro_recall,
        "macro_precision_supported_classes": macro_precision,
        "supported_test_classes": [STAGES[i] for i in supported],
        "all_five_classes_present_in_test": len(supported) == 5,
        "confusion_matrix_stage_order": list(STAGES),
        "confusion_matrix": cm.astype(int).tolist(),
        "per_stage": per,
    }


def fit_stage_mapper(future_scaled, y_stage, train_mask):
    ids = np.where(train_mask & (y_stage >= 0))[0]
    if len(ids) < 200:
        raise RuntimeError(f"Too few stage-labelled train sequences: {len(ids)}")
    if len(np.unique(y_stage[ids])) < 4:
        raise RuntimeError(f"Too few stage classes in train: {Counter(y_stage[ids].tolist())}")
    X = future_scaled[ids].reshape(len(ids), -1)
    model = ExtraTreesClassifier(
        n_estimators=500,
        max_features="sqrt",
        min_samples_leaf=2,
        class_weight="balanced",
        random_state=20260920,
        n_jobs=1,
    )
    model.fit(X, y_stage[ids])
    return model, ids


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--csv", required=True)
    p.add_argument("--output", required=True)
    p.add_argument("--seeds", nargs="+", type=int, default=[42, 43, 44])
    p.add_argument("--epochs", type=int, default=18)
    args = p.parse_args()
    if len(set(args.seeds)) < 3:
        p.error("At least three distinct seeds required")

    out = Path(args.output)
    if out.exists():
        p.error("Output exists; V71 evidence is immutable")
    out.mkdir(parents=True)

    df = pd.read_csv(args.csv, low_memory=False)
    dt, date_col, ts_col, time_method = parse_time(df)
    binary, family, binary_col, family_col, profiles = detect_label_hierarchy(df)
    family = family.map(canonical_family_name)
    feature_cols, feature_audit = choose_network_numeric_features(df)
    state, names, src_col = build_minute_state(df, dt, binary, family, feature_cols)
    seq = make_sequences(state, names)
    masks, boundaries = temporal_masks(seq["cutoff"])
    y_stage, mapped_support = future_stage_targets(seq)

    # Attack-stage evaluation only. Benign/unmapped future horizons are excluded from
    # the multiclass score rather than forced into one of the five attack stages.
    test_mask = masks["test"] & (y_stage >= 0)
    train_stage = masks["train"] & (y_stage >= 0)
    val_state = masks["calibration"]
    test_support = Counter(STAGES[int(x)] for x in y_stage[test_mask])
    train_support = Counter(STAGES[int(x)] for x in y_stage[train_stage])
    if int(test_mask.sum()) < 50:
        raise RuntimeError(f"Too few stage-labelled test sequences: {int(test_mask.sum())}")

    rows = {}
    for seed in args.seeds:
        print(f"V71 seed={seed}", flush=True)
        world = train_residual_world_model(
            seq["X"], seq["future"], masks["train"], val_state, int(seed), epochs=args.epochs
        )
        mapper, stage_train_ids = fit_stage_mapper(world["future_scaled"], y_stage, masks["train"])
        ids = np.where(test_mask)[0]
        y_true = y_stage[ids]
        predicted_future = world["pred"][ids].reshape(len(ids), -1)
        persistence_future = world["persistence"][ids].reshape(len(ids), -1)
        pred = mapper.predict(predicted_future)
        persistence_pred = mapper.predict(persistence_future)
        m = exact_metrics(y_true, pred)
        pm = exact_metrics(y_true, persistence_pred)
        rows[str(seed)] = {
            "seed": int(seed),
            "stage_mapper_train_sequences": int(len(stage_train_ids)),
            "world_validation_mse": float(world["validation_mse"]),
            "world_validation_persistence_mse": float(world["validation_persistence_mse"]),
            "world_validation_gate_passed": bool(world["state_gate_passed"]),
            "blend_alpha": float(world["blend_alpha"]),
            "trend_beta": float(world["trend_beta"]),
            "forecast_state_stage_metrics": m,
            "persistence_state_stage_metrics": pm,
            "macro_f1_delta_vs_persistence_state": (
                None if m["macro_f1_supported_classes"] is None or pm["macro_f1_supported_classes"] is None
                else float(m["macro_f1_supported_classes"] - pm["macro_f1_supported_classes"])
            ),
        }

    vals = list(rows.values())
    f1 = np.asarray([r["forecast_state_stage_metrics"]["macro_f1_supported_classes"] for r in vals], dtype=float)
    recall = np.asarray([r["forecast_state_stage_metrics"]["macro_recall_supported_classes"] for r in vals], dtype=float)
    precision = np.asarray([r["forecast_state_stage_metrics"]["macro_precision_supported_classes"] for r in vals], dtype=float)
    acc = np.asarray([r["forecast_state_stage_metrics"]["accuracy"] for r in vals], dtype=float)
    pf1 = np.asarray([r["persistence_state_stage_metrics"]["macro_f1_supported_classes"] for r in vals], dtype=float)

    report = {
        "protocol": "V71 chronological future-state lifecycle-stage proxy benchmark",
        "claim_boundary": (
            "X-IIoTID lifecycle-family labels supervise a five-stage proxy mapper. Reconnaissance, Lateral Movement, "
            "Command & Control and Exfiltration are direct lifecycle-name matches. Exploitation is reported only as "
            "'Initial Access proxy', not exact MITRE Initial Access. This is not publisher-validated CICAPT MITRE F1."
        ),
        "stage_mapping": {
            "Reconnaissance": "Reconnaissance",
            "Exploitation": "Initial Access proxy",
            "Lateral Movement": "Lateral Movement",
            "C&C": "Command & Control",
            "Exfiltration": "Exfiltration",
        },
        "target_rule": "furthest mapped lifecycle stage present within the 4-window future horizon",
        "leakage_contract": {
            "attack_labels_are_world_model_inputs": False,
            "stage_mapper_fit_on_test": False,
            "world_model_fit_on_test": False,
            "chronological_split": True,
            "embargo_seconds": boundaries["embargo_seconds"],
            "world_blend_selected_on_calibration_only": True,
        },
        "time": {"date_column": date_col, "timestamp_column": ts_col, "method": time_method, "boundaries": boundaries},
        "labels": {"binary": binary_col, "family": family_col, "profiles": profiles},
        "source_group_column": src_col,
        "network_only_features": feature_cols,
        "feature_audit": feature_audit,
        "mapped_future_occurrences_before_sequence_collapse": mapped_support,
        "train_stage_support": dict(train_support),
        "test_stage_support": dict(test_support),
        "test_stage_sequences": int(test_mask.sum()),
        "seeds": rows,
        "summary": {
            "seed_evaluations": len(vals),
            "macro_f1_mean": float(f1.mean()),
            "macro_f1_sd": float(f1.std(ddof=1)),
            "macro_recall_mean": float(recall.mean()),
            "macro_precision_mean": float(precision.mean()),
            "accuracy_mean": float(acc.mean()),
            "persistence_state_macro_f1_mean": float(pf1.mean()),
            "forecast_minus_persistence_macro_f1_pp": float(100.0 * (f1.mean() - pf1.mean())),
            "all_world_validation_gates_pass": all(r["world_validation_gate_passed"] for r in vals),
            "all_five_stages_present_in_test_all_seeds": all(r["forecast_state_stage_metrics"]["all_five_classes_present_in_test"] for r in vals),
        },
    }
    (out / "summary.json").write_text(json.dumps(report, indent=2, allow_nan=False) + "\n")
    print(json.dumps({"train_support": dict(train_support), "test_support": dict(test_support), "summary": report["summary"]}, indent=2), flush=True)


if __name__ == "__main__":
    main()
