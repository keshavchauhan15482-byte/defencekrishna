"""V77 frozen unseen-fine-subtype stage generalisation benchmark.

The reserve was frozen by V76f before this evaluator existed.  X-IIoTID class1 fine
subtypes ``discovering resources`` (Reconnaissance) and ``modbus register reading``
(Lateral Movement) are removed from all development sequences, together with same-source
overlap neighbours.  A residual Garuda world model and a fixed supervised stage mapper
are fit only on the remaining development data.  The stage mapper is then applied to
Garuda forecast states and to the persistence-state baseline on the frozen reserve.

This is a two-stage zero-development-exposure subtype test.  A reserve subtype may
already occur in the runtime history of its test sequence, so this is not clean-onset,
pre-compromise, or globally future-chronological evidence.
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
    make_sequences,
    norm,
    parse_time,
)
from .v48_strict_runner import canonical_family_name
from .v60_residual_state_forecasting import train_residual_world_model
from .v71_future_stage_proxy import STAGES, exact_metrics, fit_stage_mapper, future_stage_targets
from .v76_stage_subtype_support_freeze import build_minute_pairs

DEV_TRAIN_FRAC = 0.75
OVERLAP_EMBARGO_SECONDS = (HISTORY + HORIZON - 1) * 60
MIN_STAGE_TRAIN = 50
MIN_STAGE_VALIDATION = 20


def file_sha256(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            h.update(block)
    return h.hexdigest()


def load_freeze(path: Path, dataset_sha: str):
    data = json.loads(path.read_text())
    if not data.get("frozen_before_any_v77_model_scoring"):
        raise RuntimeError("V77 reserve is not marked frozen before scoring")
    if data.get("selection_used_model_metrics") is not False:
        raise RuntimeError("V77 reserve selection contract is not support-only")
    if data.get("dataset_sha256") != dataset_sha:
        raise RuntimeError(
            f"Dataset hash mismatch: freeze={data.get('dataset_sha256')} runtime={dataset_sha}"
        )
    selected = data.get("reserve_subtype_by_stage", {})
    if list(data.get("selected_stages", [])) != [s for s in STAGES if s in selected]:
        raise RuntimeError("Frozen selected-stage ordering/config is inconsistent")
    if len(selected) < 1:
        raise RuntimeError("Frozen reserve is empty")
    return data


def attach_stage_subtypes(state, pair_minutes):
    pairs = pair_minutes[["src", "minute", "stage_subtypes"]].copy()
    pairs["src"] = pairs["src"].astype(str)
    merged = state.copy()
    merged["src"] = merged["src"].astype(str)
    merged = merged.merge(pairs, on=["src", "minute"], how="left", validate="one_to_one")
    merged["stage_subtypes"] = merged["stage_subtypes"].map(
        lambda value: value if isinstance(value, tuple) else tuple()
    )
    return merged


def sequence_pair_metadata(state):
    srcs, cutoffs, histories, futures, all_pairs = [], [], [], [], []
    for src, group in state.groupby("src", sort=False):
        g = group.sort_values("minute").reset_index(drop=True)
        t = g["minute"].astype("int64").to_numpy() // 10**9
        pairs = g["stage_subtypes"].tolist()
        for i in range(HISTORY - 1, len(g) - HORIZON):
            lo = i - HISTORY + 1
            stop = i + HORIZON + 1
            span = t[lo:stop]
            if len(span) != HISTORY + HORIZON or not np.all(np.diff(span) == 60):
                continue
            history = set()
            future = set()
            for item in pairs[lo:i + 1]:
                history.update(item)
            for item in pairs[i + 1:stop]:
                future.update(item)
            srcs.append(str(src))
            cutoffs.append(int(t[i]))
            histories.append(frozenset(history))
            futures.append(frozenset(future))
            all_pairs.append(frozenset(history | future))
    return {
        "src": np.asarray(srcs, dtype=object),
        "cutoff": np.asarray(cutoffs, dtype=np.int64),
        "history_pairs": np.asarray(histories, dtype=object),
        "future_pairs": np.asarray(futures, dtype=object),
        "all_pairs": np.asarray(all_pairs, dtype=object),
    }


def overlap_dilate(meta, exposed):
    blocked = np.asarray(exposed, dtype=bool).copy()
    for src in np.unique(meta["src"]):
        ids = np.where(meta["src"] == src)[0]
        exp = ids[exposed[ids]]
        if not len(exp):
            continue
        exp_times = np.sort(meta["cutoff"][exp])
        times = meta["cutoff"][ids]
        positions = np.searchsorted(exp_times, times)
        near = np.zeros(len(ids), dtype=bool)
        left = positions - 1
        ok = left >= 0
        if ok.any():
            near[ok] |= np.abs(times[ok] - exp_times[left[ok]]) <= OVERLAP_EMBARGO_SECONDS
        right = positions
        ok = right < len(exp_times)
        if ok.any():
            near[ok] |= np.abs(times[ok] - exp_times[right[ok]]) <= OVERLAP_EMBARGO_SECONDS
        blocked[ids[near]] = True
    return blocked


def reserve_masks(meta, y_stage, freeze):
    selected = freeze["reserve_subtype_by_stage"]
    reserve_pairs = {(stage, subtype) for stage, subtype in selected.items()}
    reserve_touch = np.asarray(
        [bool(reserve_pairs.intersection(pairs)) for pairs in meta["all_pairs"]],
        dtype=bool,
    )
    dev_blocked = overlap_dilate(meta, reserve_touch)
    test_by_stage = {}
    for stage, subtype in selected.items():
        label = STAGES.index(stage)
        pair = (stage, subtype)
        other = reserve_pairs - {pair}
        test_by_stage[stage] = np.asarray([
            bool(
                y_stage[i] == label
                and pair in meta["future_pairs"][i]
                and not other.intersection(meta["all_pairs"][i])
            )
            for i in range(len(y_stage))
        ], dtype=bool)
    test = np.zeros(len(y_stage), dtype=bool)
    for mask in test_by_stage.values():
        test |= mask
    if np.any(test & ~reserve_touch):
        raise RuntimeError("Frozen reserve test contains sequence not marked reserve-touch")
    if np.any(test & ~dev_blocked):
        raise RuntimeError("Frozen reserve test escaped development block")
    return reserve_touch, dev_blocked, test_by_stage, test


def stage_stratified_dev_masks(seq, y_stage, dev_eligible):
    train = np.zeros(len(y_stage), dtype=bool)
    val = np.zeros(len(y_stage), dtype=bool)
    audit = {}
    for label, stage in enumerate(STAGES):
        ids = np.where(dev_eligible & (y_stage == label))[0]
        if len(ids) < MIN_STAGE_TRAIN + MIN_STAGE_VALIDATION:
            raise RuntimeError(f"{stage}: development support too small after reserve isolation: {len(ids)}")
        unique_times = np.unique(seq["cutoff"][ids])
        if len(unique_times) < 30:
            raise RuntimeError(f"{stage}: too few unique development cutoffs: {len(unique_times)}")
        boundary = unique_times[int(np.floor(DEV_TRAIN_FRAC * (len(unique_times) - 1)))]
        tr = ids[seq["cutoff"][ids] <= boundary]
        va = ids[seq["cutoff"][ids] > boundary + (HISTORY + HORIZON) * 60]
        if len(tr) < MIN_STAGE_TRAIN or len(va) < MIN_STAGE_VALIDATION:
            raise RuntimeError(
                f"{stage}: split support train={len(tr)} validation={len(va)} after temporal embargo"
            )
        train[tr] = True
        val[va] = True
        audit[stage] = {
            "development_total": int(len(ids)),
            "train": int(len(tr)),
            "validation": int(len(va)),
            "boundary_cutoff": int(boundary),
            "validation_starts_strictly_after_seconds": int(boundary + (HISTORY + HORIZON) * 60),
        }
    if np.any(train & val):
        raise RuntimeError("Development train/validation overlap")
    return train, val, audit


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
    dataset_sha = file_sha256(csv)
    freeze_path = Path(args.freeze)
    freeze = load_freeze(freeze_path, dataset_sha)
    freeze_sha = file_sha256(freeze_path)

    df = pd.read_csv(csv, low_memory=False)
    columns = {norm(c): c for c in df.columns}
    if not {"class1", "class2", "class3"}.issubset(columns):
        raise RuntimeError("Audited X-IIoTID hierarchy columns missing")
    dt, date_col, ts_col, time_method = parse_time(df)
    binary, family, binary_col, family_col, profiles = detect_label_hierarchy(df)
    if norm(binary_col) != "class3" or norm(family_col) != "class2":
        raise RuntimeError(f"Hierarchy drift: binary={binary_col} family={family_col}")
    family = family.map(canonical_family_name)
    subtype_col = columns["class1"]

    feature_cols, feature_audit = choose_network_numeric_features(df)
    state, names, src_col = build_minute_state(df, dt, binary, family, feature_cols)
    pair_minutes, pair_src_col = build_minute_pairs(df, dt, binary, family, subtype_col)
    if src_col != pair_src_col:
        raise RuntimeError(f"Source-column drift state={src_col} subtype={pair_src_col}")
    state = attach_stage_subtypes(state, pair_minutes)
    seq = make_sequences(state, names)
    meta = sequence_pair_metadata(state)
    if len(meta["cutoff"]) != len(seq["cutoff"]):
        raise RuntimeError("Sequence metadata length mismatch")
    if not np.array_equal(meta["cutoff"], seq["cutoff"]):
        raise RuntimeError("Sequence cutoff alignment mismatch")

    y_stage, mapped_support = future_stage_targets(seq)
    reserve_touch, dev_blocked, test_by_stage, test = reserve_masks(meta, y_stage, freeze)
    dev_eligible = (~dev_blocked) & (y_stage >= 0)
    train, val, split_audit = stage_stratified_dev_masks(seq, y_stage, dev_eligible)

    selected_stages = freeze["selected_stages"]
    test_support = {stage: int(mask.sum()) for stage, mask in test_by_stage.items()}
    for stage in selected_stages:
        frozen = int(freeze["support_at_freeze"]["reserve_target_sequences"][stage])
        if test_support[stage] != frozen:
            raise RuntimeError(
                f"Reserve support drift for {stage}: freeze={frozen} runtime={test_support[stage]}"
            )

    development_support = {
        stage: int(np.sum(dev_eligible & (y_stage == i))) for i, stage in enumerate(STAGES)
    }
    train_support = {stage: int(np.sum(train & (y_stage == i))) for i, stage in enumerate(STAGES)}
    val_support = {stage: int(np.sum(val & (y_stage == i))) for i, stage in enumerate(STAGES)}

    split_contract = {
        "freeze_config_sha256": freeze_sha,
        "dataset_sha256": dataset_sha,
        "selected_stages": selected_stages,
        "reserve_subtype_by_stage": freeze["reserve_subtype_by_stage"],
        "reserve_test_support": test_support,
        "reserve_touch_sequences": int(reserve_touch.sum()),
        "development_blocked_with_overlap_embargo": int(dev_blocked.sum()),
        "development_eligible_stage_sequences": int(dev_eligible.sum()),
        "overlap_embargo_seconds": int(OVERLAP_EMBARGO_SECONDS),
        "development_support_by_stage": development_support,
        "train_support_by_stage": train_support,
        "validation_support_by_stage": val_support,
        "stage_stratified_development_split": split_audit,
        "selection_used_model_metrics": False,
        "reserve_frozen_before_v77_evaluator": True,
    }
    (out / "split_contract.json").write_text(
        json.dumps(split_contract, indent=2, allow_nan=False) + "\n"
    )
    print(json.dumps({"split_contract": split_contract}, indent=2), flush=True)

    rows = {}
    ids = np.where(test)[0]
    y_true = y_stage[ids]
    for seed in args.seeds:
        print(f"V77 seed={seed}", flush=True)
        world = train_residual_world_model(
            seq["X"], seq["future"], train, val, int(seed), epochs=args.epochs
        )
        mapper, mapper_ids = fit_stage_mapper(world["future_scaled"], y_stage, train)
        pred = mapper.predict(world["pred"][ids].reshape(len(ids), -1))
        persistence_pred = mapper.predict(world["persistence"][ids].reshape(len(ids), -1))
        forecast_metrics = exact_metrics(y_true, pred)
        persistence_metrics = exact_metrics(y_true, persistence_pred)
        rows[str(seed)] = {
            "seed": int(seed),
            "stage_mapper_train_sequences": int(len(mapper_ids)),
            "world_validation_mse": float(world["validation_mse"]),
            "world_validation_persistence_mse": float(world["validation_persistence_mse"]),
            "world_validation_gate_passed": bool(world["state_gate_passed"]),
            "blend_alpha": float(world["blend_alpha"]),
            "trend_beta": float(world["trend_beta"]),
            "forecast_state_stage_metrics": forecast_metrics,
            "persistence_state_stage_metrics": persistence_metrics,
            "macro_f1_delta_vs_persistence_state": float(
                forecast_metrics["macro_f1_supported_classes"]
                - persistence_metrics["macro_f1_supported_classes"]
            ),
        }

    values = list(rows.values())
    forecast_f1 = np.asarray([
        r["forecast_state_stage_metrics"]["macro_f1_supported_classes"] for r in values
    ], dtype=float)
    persistence_f1 = np.asarray([
        r["persistence_state_stage_metrics"]["macro_f1_supported_classes"] for r in values
    ], dtype=float)
    forecast_recall = np.asarray([
        r["forecast_state_stage_metrics"]["macro_recall_supported_classes"] for r in values
    ], dtype=float)
    forecast_precision = np.asarray([
        r["forecast_state_stage_metrics"]["macro_precision_supported_classes"] for r in values
    ], dtype=float)
    forecast_accuracy = np.asarray([
        r["forecast_state_stage_metrics"]["accuracy"] for r in values
    ], dtype=float)
    delta = forecast_f1 - persistence_f1

    report = {
        "protocol": "V77 frozen two-stage unseen-fine-subtype generalisation",
        "frozen_reserve": freeze,
        "split_contract": split_contract,
        "leakage_contract": {
            "reserve_subtype_sequences_used_for_world_model_development": False,
            "reserve_subtype_sequences_used_for_stage_mapper_development": False,
            "same_source_overlapping_neighbours_allowed_in_development": False,
            "test_metrics_used_for_reserve_selection": False,
            "attack_labels_are_world_model_inputs": False,
            "stage_mapper_fit_on_test": False,
            "world_model_fit_on_test": False,
        },
        "evaluation_scope": (
            "Only Reconnaissance/discovering-resources and Lateral-Movement/modbus-register-reading "
            "are valid unseen-fine-subtype reserve stages on this dataset under the declared support gate."
        ),
        "claim_boundary": (
            "This is zero-development-exposure subtype stage generalisation, not a five-stage unseen-subtype "
            "benchmark, not clean-onset forecasting, not globally future-chronological evaluation, and not "
            "verified compromise lead-time evidence."
        ),
        "time": {"date_column": date_col, "timestamp_column": ts_col, "method": time_method},
        "labels": {
            "binary": binary_col,
            "lifecycle_family": family_col,
            "fine_subtype": subtype_col,
            "profiles": profiles,
        },
        "source_group_column": src_col,
        "network_only_features": feature_cols,
        "feature_audit": feature_audit,
        "mapped_future_occurrences_before_sequence_collapse": mapped_support,
        "seeds": rows,
        "summary": {
            "seed_evaluations": int(len(values)),
            "test_sequences": int(len(ids)),
            "selected_stage_count": int(len(selected_stages)),
            "forecast_macro_f1_mean": float(forecast_f1.mean()),
            "forecast_macro_f1_sd": float(forecast_f1.std(ddof=1)),
            "forecast_macro_recall_mean": float(forecast_recall.mean()),
            "forecast_macro_precision_mean": float(forecast_precision.mean()),
            "forecast_accuracy_mean": float(forecast_accuracy.mean()),
            "persistence_macro_f1_mean": float(persistence_f1.mean()),
            "forecast_minus_persistence_macro_f1_pp": float(100.0 * delta.mean()),
            "forecast_minus_persistence_macro_f1_pp_per_seed": [
                float(100.0 * x) for x in delta
            ],
            "all_world_validation_gates_pass": bool(
                all(r["world_validation_gate_passed"] for r in values)
            ),
            "forecast_beats_persistence_macro_f1_all_seeds": bool(np.all(delta > 0.0)),
        },
    }
    (out / "summary.json").write_text(json.dumps(report, indent=2, allow_nan=False) + "\n")
    print(json.dumps(report["summary"], indent=2), flush=True)
    for seed, row in rows.items():
        print("SEED", seed, json.dumps({
            "forecast": row["forecast_state_stage_metrics"],
            "persistence": row["persistence_state_stage_metrics"],
            "delta": row["macro_f1_delta_vs_persistence_state"],
        }, indent=2), flush=True)


if __name__ == "__main__":
    main()
