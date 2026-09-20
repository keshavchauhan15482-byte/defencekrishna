"""V77 unseen fine-subtype stage generalisation benchmark.

V76 freezes one fine-grained X-IIoTID Class1 subtype for each of five lifecycle stages
using support counts only. V77 then excludes every sequence touching any frozen subtype
from world-model fitting and stage-mapper fitting (plus a 12-window overlap embargo),
trains the residual Garuda state forecaster on the remaining network-only state
sequences, and evaluates five-stage mapping on the held-out fine subtypes.

This is a leave-fine-subtype-out generalisation benchmark, not a globally future
chronological benchmark and not proof of a production zero-day. Exploitation remains an
"Initial Access proxy", not exact MITRE Initial Access ground truth.
"""
from __future__ import annotations

import argparse
import hashlib
import json
from collections import Counter
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
from .v71_future_stage_proxy import STAGES, exact_metrics, fit_stage_mapper, stage_name
from .v76_stage_subtype_support_freeze import build_minute_pairs, find_subtype_column

EMBARGO_STEPS = HISTORY + HORIZON


def sha256(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            h.update(block)
    return h.hexdigest()


def _pair_lookup(minute_pairs: pd.DataFrame):
    out = {}
    for row in minute_pairs.itertuples(index=False):
        sec = int(pd.Timestamp(row.minute).value // 10**9)
        out[(str(row.src), sec)] = frozenset(row.stage_subtypes)
    return out


def make_sequences_with_subtypes(state: pd.DataFrame, feature_cols, minute_pairs: pd.DataFrame):
    lookup = _pair_lookup(minute_pairs)
    rank = {stage: i for i, stage in enumerate(STAGES)}
    X, future, cutoff, srcs = [], [], [], []
    y_stage, history_pairs, future_pairs = [], [], []

    for src, group in state.groupby("src", sort=False):
        g = group.sort_values("minute").reset_index(drop=True)
        times = g["minute"].astype("int64").to_numpy() // 10**9
        z = g[feature_cols].to_numpy(dtype=np.float32)
        fam = g["families"].tolist()
        fine = [lookup.get((str(src), int(t)), frozenset()) for t in times]
        for i in range(HISTORY - 1, len(g) - HORIZON):
            lo = i - HISTORY + 1
            stop = i + HORIZON + 1
            span = times[lo:stop]
            if len(span) != HISTORY + HORIZON or not np.all(np.diff(span) == 60):
                continue
            X.append(z[lo:i + 1])
            future.append(z[i + 1:stop])
            cutoff.append(int(times[i]))
            srcs.append(str(src))

            hp = set()
            fp = set()
            for item in fine[lo:i + 1]:
                hp.update(item)
            for item in fine[i + 1:stop]:
                fp.update(item)
            history_pairs.append(frozenset(hp))
            future_pairs.append(frozenset(fp))

            mapped = []
            for item in fam[i + 1:stop]:
                for raw in item:
                    s = stage_name(raw)
                    if s is not None:
                        mapped.append(s)
            y_stage.append(max((rank[s] for s in mapped), default=-1))

    if not X:
        raise RuntimeError("No contiguous sequences")
    return {
        "X": np.stack(X),
        "future": np.stack(future),
        "cutoff": np.asarray(cutoff, dtype=np.int64),
        "src": np.asarray(srcs, dtype=object),
        "y_stage": np.asarray(y_stage, dtype=np.int16),
        "history_pairs": np.asarray(history_pairs, dtype=object),
        "future_pairs": np.asarray(future_pairs, dtype=object),
    }


def reserve_masks(seq, frozen):
    selected = frozen["selected_reserve_subtype_by_stage"]
    reserve_pairs = {(stage, subtype) for stage, subtype in selected.items()}
    touch = np.asarray([
        bool(reserve_pairs.intersection(set(h) | set(f)))
        for h, f in zip(seq["history_pairs"], seq["future_pairs"])
    ], dtype=bool)

    blocked = touch.copy()
    # Embargo is source-local so unrelated hosts at the same timestamp are not removed.
    by_src = {}
    for i, (src, t) in enumerate(zip(seq["src"], seq["cutoff"])):
        by_src.setdefault(str(src), []).append((i, int(t)))
    for src, rows in by_src.items():
        touched_times = [t for i, t in rows if touch[i]]
        if not touched_times:
            continue
        blocked_times = set()
        for t in touched_times:
            for k in range(-EMBARGO_STEPS, EMBARGO_STEPS + 1):
                blocked_times.add(t + 60 * k)
        for i, t in rows:
            if t in blocked_times:
                blocked[i] = True

    tests = {}
    cooccurrence = {}
    for stage_index, stage in enumerate(STAGES):
        subtype = selected[stage]
        pair = (stage, subtype)
        mask = np.asarray([
            seq["y_stage"][i] == stage_index
            and pair in seq["future_pairs"][i]
            and not reserve_pairs.intersection(seq["history_pairs"][i])
            for i in range(len(seq["X"]))
        ], dtype=bool)
        tests[stage] = mask
        cooccurrence[stage] = int(sum(
            1 for i in np.where(mask)[0]
            if len((reserve_pairs - {pair}).intersection(seq["future_pairs"][i])) > 0
        ))
    return reserve_pairs, touch, blocked, tests, cooccurrence


def chronological_train_val(cutoff, allowed):
    ids = np.where(allowed)[0]
    if len(ids) < 100:
        raise RuntimeError(f"Too few development sequences after reserve embargo: {len(ids)}")
    times = np.unique(cutoff[ids])
    if len(times) < 20:
        raise RuntimeError(f"Too few development timestamps: {len(times)}")
    boundary = int(times[int(0.80 * (len(times) - 1))])
    train = allowed & (cutoff <= boundary)
    val = allowed & (cutoff > boundary)
    if int(train.sum()) < 50 or int(val.sum()) < 20:
        raise RuntimeError(f"Development split too small train={int(train.sum())} val={int(val.sum())}")
    return train, val, boundary


def add_stage_f1(metrics):
    for stage, row in metrics["per_stage"].items():
        p = row["precision"]
        r = row["recall"]
        row["f1"] = None if p is None or r is None or (p + r) == 0 else float(2.0 * p * r / (p + r))
    return metrics


def _mse(pred, target, mask):
    ids = np.where(mask)[0]
    if len(ids) == 0:
        return None
    return float(np.mean((pred[ids] - target[ids]) ** 2))


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

    out = Path(args.output)
    if out.exists():
        p.error("Output exists; V77 evidence is immutable")
    out.mkdir(parents=True)

    csv = Path(args.csv)
    freeze_path = Path(args.freeze)
    frozen = json.loads(freeze_path.read_text())
    if frozen.get("selection_used_model_metrics") is not False or frozen.get("model_scored_reserve_before_freeze") is not False:
        raise RuntimeError("V76 freeze does not satisfy no-model-selection contract")
    if frozen.get("dataset_sha256") != sha256(csv):
        raise RuntimeError("Dataset hash does not match V76 freeze")

    df = pd.read_csv(csv, low_memory=False)
    dt, date_col, ts_col, time_method = parse_time(df)
    binary, family, binary_col, family_col, profiles = detect_label_hierarchy(df)
    feature_cols, feature_audit = choose_network_numeric_features(df)
    state, state_features, src_col = build_minute_state(df, dt, binary, family, feature_cols)
    subtype_col = find_subtype_column(df, binary_col, family_col)
    if subtype_col != frozen["fine_subtype_column"]:
        raise RuntimeError(f"Subtype column mismatch freeze={frozen['fine_subtype_column']} runtime={subtype_col}")
    minute_pairs, subtype_src_col = build_minute_pairs(df, dt, binary, family, subtype_col)
    seq = make_sequences_with_subtypes(state, state_features, minute_pairs)

    reserve_pairs, reserve_touch, blocked, stage_tests, cooccurrence = reserve_masks(seq, frozen)
    development = ~blocked
    train, val, boundary = chronological_train_val(seq["cutoff"], development)
    labelled_dev = development & (seq["y_stage"] >= 0)
    test_union = np.zeros(len(seq["X"]), dtype=bool)
    test_support = {}
    for stage in STAGES:
        test_union |= stage_tests[stage]
        test_support[stage] = int(stage_tests[stage].sum())
    if any(v < frozen["minimum_reserve_per_stage"] for v in test_support.values()):
        raise RuntimeError(f"V77 reserve support below frozen minimum: {test_support}")

    dev_stage_support = {
        stage: int(np.sum(labelled_dev & (seq["y_stage"] == i)))
        for i, stage in enumerate(STAGES)
    }
    if any(v < frozen["minimum_development_per_stage"] for v in dev_stage_support.values()):
        raise RuntimeError(f"V77 development stage support below frozen minimum: {dev_stage_support}")

    rows = {}
    for seed in args.seeds:
        print(f"V77 seed={seed}", flush=True)
        world = train_residual_world_model(seq["X"], seq["future"], train, val, int(seed), epochs=args.epochs)
        mapper, mapper_ids = fit_stage_mapper(world["future_scaled"], seq["y_stage"], labelled_dev)
        ids = np.where(test_union)[0]
        truth = seq["y_stage"][ids]
        pred = mapper.predict(world["pred"][ids].reshape(len(ids), -1))
        persist_pred = mapper.predict(world["persistence"][ids].reshape(len(ids), -1))
        metric = add_stage_f1(exact_metrics(truth, pred))
        persist_metric = add_stage_f1(exact_metrics(truth, persist_pred))
        rows[str(seed)] = {
            "seed": int(seed),
            "world_validation_mse": float(world["validation_mse"]),
            "world_validation_persistence_mse": float(world["validation_persistence_mse"]),
            "world_validation_gate_passed": bool(world["state_gate_passed"]),
            "blend_alpha": float(world["blend_alpha"]),
            "trend_beta": float(world["trend_beta"]),
            "stage_mapper_train_sequences": int(len(mapper_ids)),
            "forecast_state_stage_metrics": metric,
            "persistence_state_stage_metrics": persist_metric,
            "reserve_state_mse": _mse(world["pred"], world["future_scaled"], test_union),
            "reserve_persistence_mse": _mse(world["persistence"], world["future_scaled"], test_union),
        }

    vals = list(rows.values())
    f1 = np.asarray([r["forecast_state_stage_metrics"]["macro_f1_supported_classes"] for r in vals], dtype=float)
    pf1 = np.asarray([r["persistence_state_stage_metrics"]["macro_f1_supported_classes"] for r in vals], dtype=float)
    recall = np.asarray([r["forecast_state_stage_metrics"]["macro_recall_supported_classes"] for r in vals], dtype=float)
    precision = np.asarray([r["forecast_state_stage_metrics"]["macro_precision_supported_classes"] for r in vals], dtype=float)
    accuracy = np.asarray([r["forecast_state_stage_metrics"]["accuracy"] for r in vals], dtype=float)
    state_improvement = []
    for r in vals:
        p_mse = r["reserve_persistence_mse"]
        w_mse = r["reserve_state_mse"]
        state_improvement.append((p_mse - w_mse) / p_mse if p_mse else 0.0)

    per_stage = {}
    for stage in STAGES:
        stage_f1 = [r["forecast_state_stage_metrics"]["per_stage"][stage]["f1"] for r in vals]
        stage_rec = [r["forecast_state_stage_metrics"]["per_stage"][stage]["recall"] for r in vals]
        per_stage[stage] = {
            "test_support": int(test_support[stage]),
            "held_out_subtype": frozen["selected_reserve_subtype_by_stage"][stage],
            "f1_mean": float(np.mean(stage_f1)),
            "f1_min": float(np.min(stage_f1)),
            "recall_mean": float(np.mean(stage_rec)),
            "recall_min": float(np.min(stage_rec)),
            "other_reserved_future_cooccurrence_sequences": int(cooccurrence[stage]),
        }

    report = {
        "protocol": "V77 five-stage leave-fine-subtype-out forecast-state mapping",
        "claim_boundary": (
            "Held-out X-IIoTID Class1 subtypes were frozen by support only before model scoring and excluded from world-model and mapper fitting with source-local overlap embargo. "
            "This is a public-dataset unseen-subtype simulation, not a globally chronological future benchmark or production zero-day proof. Exploitation is an Initial Access proxy."
        ),
        "dataset_sha256": sha256(csv),
        "freeze_sha256": sha256(freeze_path),
        "verified_label_hierarchy": {"binary": binary_col, "lifecycle": family_col, "fine_subtype": subtype_col},
        "selected_reserve_subtype_by_stage": frozen["selected_reserve_subtype_by_stage"],
        "reserve_pairs": sorted([list(x) for x in reserve_pairs]),
        "network_only_features": feature_cols,
        "feature_audit": feature_audit,
        "source_group_column": src_col,
        "subtype_source_column": subtype_src_col,
        "time": {"date_column": date_col, "timestamp_column": ts_col, "method": time_method, "development_train_val_boundary": boundary},
        "split": {
            "sequence_count": int(len(seq["X"])),
            "reserve_touch_sequences": int(reserve_touch.sum()),
            "reserve_plus_embargo_blocked_sequences": int(blocked.sum()),
            "embargo_steps_each_side": EMBARGO_STEPS,
            "development_train": int(train.sum()),
            "development_validation": int(val.sum()),
            "development_stage_mapper": int(labelled_dev.sum()),
            "development_stage_support": dev_stage_support,
            "reserve_test_support": test_support,
        },
        "leakage_contract": {
            "reserve_selection_used_model_metrics": False,
            "reserve_subtypes_seen_by_world_model_fit": False,
            "reserve_subtypes_seen_by_world_validation": False,
            "reserve_subtypes_seen_by_stage_mapper_fit": False,
            "attack_labels_are_world_model_inputs": False,
            "test_used_for_blend_selection": False,
            "test_used_for_mapper_fit": False,
            "source_local_overlap_embargo_applied": True,
            "global_chronological_test_claim": False,
        },
        "seeds": rows,
        "per_stage_summary": per_stage,
        "summary": {
            "seed_evaluations": len(vals),
            "macro_f1_mean": float(f1.mean()),
            "macro_f1_sd": float(f1.std(ddof=1)),
            "macro_f1_min": float(f1.min()),
            "macro_recall_mean": float(recall.mean()),
            "macro_recall_min": float(recall.min()),
            "macro_precision_mean": float(precision.mean()),
            "accuracy_mean": float(accuracy.mean()),
            "persistence_state_macro_f1_mean": float(pf1.mean()),
            "forecast_minus_persistence_macro_f1_pp": float(100.0 * (f1.mean() - pf1.mean())),
            "reserve_state_mse_improvement_vs_persistence_mean": float(np.mean(state_improvement)),
            "all_world_validation_gates_pass": all(r["world_validation_gate_passed"] for r in vals),
            "all_five_stages_present_in_test_all_seeds": all(r["forecast_state_stage_metrics"]["all_five_classes_present_in_test"] for r in vals),
        },
    }
    (out / "summary.json").write_text(json.dumps(report, indent=2, allow_nan=False) + "\n")
    print(json.dumps({"split": report["split"], "per_stage": per_stage, "summary": report["summary"]}, indent=2), flush=True)


if __name__ == "__main__":
    main()
