"""V78 supported-stage unseen-fine-subtype evaluation.

Consumes a V76f support-only freeze.  Each selected X-IIoTID Class1 subtype is removed
from world-model and stage-mapper development whenever it appears in history or future;
a source-local 12-step temporal embargo is then added.  The residual Garuda world model
is fitted on the remaining network-only state sequences and a supervised lifecycle
mapper is fitted on reserve-free future states.  Evaluation is performed only on stages
for which V76f proved a subtype-disjoint holdout is supportable.

Test histories may already contain their own held-out subtype, so this is an unseen-
subtype *future-state/stage generalisation after observation* benchmark.  It is not a
clean-onset/pre-compromise test and not production zero-day evidence.  Exploitation is
reported only as an Initial Access proxy.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import math
from pathlib import Path

import numpy as np
import pandas as pd

from .v47_unseen_family import (
    HISTORY,
    HORIZON,
    build_minute_state,
    choose_network_numeric_features,
    detect_label_hierarchy,
    parse_time,
)
from .v60_residual_state_forecasting import train_residual_world_model
from .v71_future_stage_proxy import STAGES, exact_metrics, fit_stage_mapper
from .v76_stage_subtype_support_freeze import build_minute_pairs, find_subtype_column
from .v77_unseen_subtype_stage_generalization import make_sequences_with_subtypes

EMBARGO_STEPS = HISTORY + HORIZON


def sha256(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            h.update(block)
    return h.hexdigest()


def wilson(successes: int, total: int, z: float = 1.959963984540054):
    if total <= 0:
        return {"lower": None, "upper": None}
    p = successes / total
    z2 = z * z
    den = 1.0 + z2 / total
    center = (p + z2 / (2.0 * total)) / den
    margin = z * math.sqrt(p * (1.0 - p) / total + z2 / (4.0 * total * total)) / den
    return {
        "lower": float(max(0.0, center - margin)),
        "upper": float(min(1.0, center + margin)),
    }


def build_isolation(seq, selected):
    reserve_pairs = {(stage, subtype) for stage, subtype in selected.items()}
    touch = np.asarray([
        bool(reserve_pairs.intersection(set(h) | set(f)))
        for h, f in zip(seq["history_pairs"], seq["future_pairs"])
    ], dtype=bool)

    blocked = touch.copy()
    by_src = {}
    for i, (src, t) in enumerate(zip(seq["src"], seq["cutoff"])):
        by_src.setdefault(str(src), []).append((i, int(t)))
    for rows in by_src.values():
        touched_times = [t for i, t in rows if touch[i]]
        if not touched_times:
            continue
        embargo_times = set()
        for t in touched_times:
            for k in range(-EMBARGO_STEPS, EMBARGO_STEPS + 1):
                embargo_times.add(t + 60 * k)
        for i, t in rows:
            if t in embargo_times:
                blocked[i] = True
    return reserve_pairs, touch, blocked


def chronological_development_split(cutoff, allowed):
    ids = np.where(allowed)[0]
    if len(ids) < 100:
        raise RuntimeError(f"Too few reserve-free development sequences: {len(ids)}")
    times = np.unique(cutoff[ids])
    if len(times) < 20:
        raise RuntimeError(f"Too few reserve-free timestamps: {len(times)}")
    # Boundary depends only on development timestamps, never model/test metrics.
    boundary = int(times[int(0.80 * (len(times) - 1))])
    train = allowed & (cutoff <= boundary)
    validation = allowed & (cutoff > boundary)
    if int(train.sum()) < 50 or int(validation.sum()) < 20:
        raise RuntimeError(
            f"Reserve-free development split too small train={int(train.sum())} validation={int(validation.sum())}"
        )
    return train, validation, boundary


def selected_test_masks(seq, selected, reserve_pairs):
    rank = {stage: i for i, stage in enumerate(STAGES)}
    masks = {}
    diagnostic = {}
    for stage, subtype in selected.items():
        pair = (stage, subtype)
        other = reserve_pairs - {pair}
        mask = np.asarray([
            seq["y_stage"][i] == rank[stage]
            and pair in seq["future_pairs"][i]
            and not other.intersection(set(seq["history_pairs"][i]) | set(seq["future_pairs"][i]))
            for i in range(len(seq["X"]))
        ], dtype=bool)
        ids = np.where(mask)[0]
        masks[stage] = mask
        diagnostic[stage] = {
            "held_out_subtype": subtype,
            "test_sequences": int(len(ids)),
            "history_exposed": int(sum(pair in seq["history_pairs"][i] for i in ids)),
            "clean_onset": int(sum(pair not in seq["history_pairs"][i] for i in ids)),
        }
    return masks, diagnostic


def mse(pred, target, mask):
    ids = np.where(mask)[0]
    if len(ids) == 0:
        return None
    return float(np.mean((pred[ids] - target[ids]) ** 2))


def add_stage_f1(metric):
    for row in metric["per_stage"].values():
        p = row["precision"]
        r = row["recall"]
        row["f1"] = (
            None if p is None or r is None or (p + r) == 0
            else float(2.0 * p * r / (p + r))
        )
        row["recall_wilson95"] = wilson(row["tp"], row["tp"] + row["fn"])
    return metric


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--csv", required=True)
    p.add_argument("--freeze", required=True)
    p.add_argument("--output", required=True)
    p.add_argument("--seeds", nargs="+", type=int, default=[42, 43, 44])
    p.add_argument("--epochs", type=int, default=18)
    args = p.parse_args()
    if len(set(args.seeds)) < 3:
        p.error("At least three distinct seeds required")

    csv = Path(args.csv)
    freeze_path = Path(args.freeze)
    frozen = json.loads(freeze_path.read_text())
    if frozen.get("selection_used_model_metrics") is not False:
        raise RuntimeError("Freeze used model metrics")
    if frozen.get("model_scored_reserve_before_freeze") is not False:
        raise RuntimeError("Reserve was scored before freeze")
    if frozen.get("dataset_sha256") != sha256(csv):
        raise RuntimeError("Dataset hash differs from support-only freeze")

    selected = dict(frozen["selected_reserve_subtype_by_stage"])
    selected_stages = [stage for stage in STAGES if stage in selected]
    if not selected_stages:
        raise RuntimeError("Freeze contains no supportable stage holdout")
    if int(frozen["selected_stage_count"]) != len(selected_stages):
        raise RuntimeError("Freeze selected-stage count mismatch")

    out = Path(args.output)
    if out.exists():
        p.error("Output exists; V78 evidence is immutable")
    out.mkdir(parents=True)

    df = pd.read_csv(csv, low_memory=False)
    dt, date_col, ts_col, time_method = parse_time(df)
    binary, family, binary_col, family_col, profiles = detect_label_hierarchy(df)
    feature_cols, feature_audit = choose_network_numeric_features(df)
    state, state_features, src_col = build_minute_state(df, dt, binary, family, feature_cols)
    subtype_col = find_subtype_column(df, binary_col, family_col)
    if subtype_col != frozen["fine_subtype_column"]:
        raise RuntimeError(f"Subtype column drift: {subtype_col} != {frozen['fine_subtype_column']}")
    minute_pairs, subtype_src_col = build_minute_pairs(df, dt, binary, family, subtype_col)
    seq = make_sequences_with_subtypes(state, state_features, minute_pairs)

    reserve_pairs, reserve_touch, blocked = build_isolation(seq, selected)
    development = ~blocked
    train, validation, dev_boundary = chronological_development_split(seq["cutoff"], development)
    labelled_development = development & (seq["y_stage"] >= 0)
    stage_dev_support = {
        stage: int(np.sum(labelled_development & (seq["y_stage"] == i)))
        for i, stage in enumerate(STAGES)
    }

    test_masks, test_diagnostic = selected_test_masks(seq, selected, reserve_pairs)
    test_union = np.zeros(len(seq["X"]), dtype=bool)
    for stage in selected_stages:
        test_union |= test_masks[stage]
    actual_test_support = {stage: int(test_masks[stage].sum()) for stage in selected_stages}

    gate = frozen["support_gates"]
    min_test = int(gate["minimum_reserve_target_sequences_per_selected_stage"])
    min_dev = int(gate["minimum_remaining_development_sequences_per_selected_stage"])
    if any(v < min_test for v in actual_test_support.values()):
        raise RuntimeError(f"Runtime test support below frozen gate: {actual_test_support}")
    if any(stage_dev_support[s] < min_dev for s in selected_stages):
        raise RuntimeError(f"Runtime development support below frozen gate: {stage_dev_support}")

    # Strong equality check: the evaluator's test eligibility must reproduce the support
    # count that was frozen before model scoring.
    frozen_support = {s: int(frozen["reserve_stage_support"][s]) for s in selected_stages}
    if actual_test_support != frozen_support:
        raise RuntimeError(
            f"Freeze/evaluator support contract drift: frozen={frozen_support} runtime={actual_test_support}"
        )

    rows = {}
    for seed in args.seeds:
        print(f"V78 seed={seed} selected={selected_stages}", flush=True)
        world = train_residual_world_model(
            seq["X"], seq["future"], train, validation, int(seed), epochs=args.epochs
        )
        mapper, mapper_ids = fit_stage_mapper(
            world["future_scaled"], seq["y_stage"], labelled_development
        )
        ids = np.where(test_union)[0]
        truth = seq["y_stage"][ids]
        forecast_pred = mapper.predict(world["pred"][ids].reshape(len(ids), -1))
        persistence_pred = mapper.predict(world["persistence"][ids].reshape(len(ids), -1))
        fm = add_stage_f1(exact_metrics(truth, forecast_pred))
        pm = add_stage_f1(exact_metrics(truth, persistence_pred))
        state_mse = mse(world["pred"], world["future_scaled"], test_union)
        persistence_mse = mse(world["persistence"], world["future_scaled"], test_union)
        rows[str(seed)] = {
            "seed": int(seed),
            "world_validation_mse": float(world["validation_mse"]),
            "world_validation_persistence_mse": float(world["validation_persistence_mse"]),
            "world_validation_gate_passed": bool(world["state_gate_passed"]),
            "blend_alpha": float(world["blend_alpha"]),
            "trend_beta": float(world["trend_beta"]),
            "stage_mapper_train_sequences": int(len(mapper_ids)),
            "forecast_state_stage_metrics": fm,
            "persistence_state_stage_metrics": pm,
            "reserve_state_mse": state_mse,
            "reserve_persistence_mse": persistence_mse,
            "reserve_state_mse_improvement_vs_persistence": (
                None if not persistence_mse
                else float((persistence_mse - state_mse) / persistence_mse)
            ),
        }

    vals = list(rows.values())
    f1 = np.asarray([r["forecast_state_stage_metrics"]["macro_f1_supported_classes"] for r in vals])
    recall = np.asarray([r["forecast_state_stage_metrics"]["macro_recall_supported_classes"] for r in vals])
    precision = np.asarray([r["forecast_state_stage_metrics"]["macro_precision_supported_classes"] for r in vals])
    accuracy = np.asarray([r["forecast_state_stage_metrics"]["accuracy"] for r in vals])
    pf1 = np.asarray([r["persistence_state_stage_metrics"]["macro_f1_supported_classes"] for r in vals])
    state_gain = np.asarray([r["reserve_state_mse_improvement_vs_persistence"] for r in vals])

    per_stage = {}
    for stage in selected_stages:
        f_rows = [r["forecast_state_stage_metrics"]["per_stage"][stage] for r in vals]
        p_rows = [r["persistence_state_stage_metrics"]["per_stage"][stage] for r in vals]
        stage_f1 = np.asarray([r["f1"] for r in f_rows], dtype=float)
        stage_recall = np.asarray([r["recall"] for r in f_rows], dtype=float)
        persistence_f1 = np.asarray([r["f1"] for r in p_rows], dtype=float)
        per_stage[stage] = {
            **test_diagnostic[stage],
            "forecast_recall_mean": float(stage_recall.mean()),
            "forecast_recall_min": float(stage_recall.min()),
            "forecast_f1_mean": float(stage_f1.mean()),
            "forecast_f1_min": float(stage_f1.min()),
            "persistence_state_f1_mean": float(persistence_f1.mean()),
            "forecast_minus_persistence_f1_pp": float(100.0 * (stage_f1.mean() - persistence_f1.mean())),
            "seed_recall_wilson95": {
                str(seed): rows[str(seed)]["forecast_state_stage_metrics"]["per_stage"][stage]["recall_wilson95"]
                for seed in args.seeds
            },
        }

    report = {
        "protocol": "V78 supportable-stage leave-Class1-subtype-out future-state/stage generalisation",
        "claim_boundary": (
            "Only stages proven supportable by the pre-model V76f support freeze are evaluated. Selected Class1 subtypes are absent from world-model and stage-mapper development, with a source-local 12-step overlap embargo. Test history may already contain the held-out subtype, so this is future-state/stage generalisation after observing a novel subtype pattern, not clean-onset warning, pre-compromise lead time, or production zero-day proof. Exploitation is an Initial Access proxy only."
        ),
        "dataset_sha256": sha256(csv),
        "freeze_sha256": sha256(freeze_path),
        "selected_stages": selected_stages,
        "selected_stage_count": len(selected_stages),
        "unsupported_stage_audit": frozen["unsupported_stage_audit"],
        "selected_reserve_subtype_by_stage": selected,
        "verified_label_hierarchy": {
            "binary": binary_col,
            "lifecycle": family_col,
            "fine_subtype": subtype_col,
        },
        "network_only_features": feature_cols,
        "feature_audit": feature_audit,
        "source_group_column": src_col,
        "subtype_source_column": subtype_src_col,
        "time": {
            "date_column": date_col,
            "timestamp_column": ts_col,
            "method": time_method,
            "development_train_validation_boundary": dev_boundary,
        },
        "split": {
            "sequence_count": int(len(seq["X"])),
            "reserve_touch_sequences": int(reserve_touch.sum()),
            "reserve_plus_source_local_embargo_blocked_sequences": int(blocked.sum()),
            "embargo_steps_each_side": EMBARGO_STEPS,
            "development_train": int(train.sum()),
            "development_validation": int(validation.sum()),
            "development_stage_mapper": int(labelled_development.sum()),
            "development_stage_support_all_stages": stage_dev_support,
            "reserve_test_support": actual_test_support,
            "test_history_exposure": test_diagnostic,
        },
        "leakage_contract": {
            "reserve_selection_used_model_metrics": False,
            "reserve_scored_before_freeze": False,
            "reserve_subtypes_seen_by_world_model_fit": False,
            "reserve_subtypes_seen_by_world_validation": False,
            "reserve_subtypes_seen_by_stage_mapper_fit": False,
            "attack_labels_are_world_model_inputs": False,
            "test_used_for_world_blend_selection": False,
            "test_used_for_stage_mapper_fit": False,
            "source_local_overlap_embargo_applied": True,
            "test_history_may_contain_held_out_subtype": True,
            "clean_onset_claim": False,
            "pre_compromise_claim": False,
            "five_stage_unseen_subtype_claim": len(selected_stages) == 5,
        },
        "seeds": rows,
        "per_stage_summary": per_stage,
        "summary": {
            "seed_evaluations": len(vals),
            "evaluated_stage_count": len(selected_stages),
            "evaluated_test_sequences": int(test_union.sum()),
            "macro_f1_mean": float(f1.mean()),
            "macro_f1_sd": float(f1.std(ddof=1)),
            "macro_f1_min": float(f1.min()),
            "macro_recall_mean": float(recall.mean()),
            "macro_recall_min": float(recall.min()),
            "macro_precision_mean": float(precision.mean()),
            "accuracy_mean": float(accuracy.mean()),
            "persistence_state_macro_f1_mean": float(pf1.mean()),
            "forecast_minus_persistence_macro_f1_pp": float(100.0 * (f1.mean() - pf1.mean())),
            "reserve_state_mse_improvement_vs_persistence_mean": float(state_gain.mean()),
            "reserve_state_mse_improvement_vs_persistence_min": float(state_gain.min()),
            "all_world_validation_gates_pass": all(r["world_validation_gate_passed"] for r in vals),
        },
    }
    (out / "summary.json").write_text(json.dumps(report, indent=2, allow_nan=False) + "\n")
    print(json.dumps({
        "selected": selected,
        "unsupported": report["unsupported_stage_audit"],
        "split": report["split"],
        "per_stage": per_stage,
        "summary": report["summary"],
    }, indent=2), flush=True)


if __name__ == "__main__":
    main()
