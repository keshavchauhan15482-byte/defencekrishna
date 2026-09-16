"""V53 offline multi-family unknown-attack early-warning stress test.

This benchmark is deliberately non-operational: it does not generate or transmit attack
traffic. It replays a public labelled dataset offline and asks whether Garuda's frozen
history-only alert fires before the first future minute containing a dangerous held-out
attack family.

The selected dangerous families are removed together from model fitting, state
validation, benign calibration and policy fitting. V53 reuses the already-published V48
fusion (75% known-attack transfer + 25% predicted transition energy, 0.25% benign
policy budget) without tuning on V53 outcomes.

Because several family names have been inspected in earlier project versions, this is a
zero-supervised-exposure stress test for the V53 model, not a fresh project-wide release
holdout and not proof of a real undisclosed zero-day or successful-compromise lead time.
"""
from __future__ import annotations

import argparse
import json
from collections import defaultdict
from pathlib import Path

import numpy as np
import pandas as pd

from .v47_unseen_family import (
    HISTORY,
    HORIZON,
    FPR_BUDGET,
    SEEDS,
    binary_metrics,
    build_minute_state,
    choose_network_numeric_features,
    detect_label_hierarchy,
    fpr_threshold,
    parse_time,
    sha256,
    temporal_masks,
    train_world_model,
    make_sequences,
)
from .v48_strict_runner import canonical_family_name
from .v48_unseen_fusion import fused_score, raw_components

EMBARGO_STEPS = HISTORY + HORIZON
FROZEN_WEIGHTS = {
    "known_attack_transfer": 0.75,
    "future_state_novelty": 0.0,
    "predicted_delta_novelty": 0.0,
    "transition_energy": 0.25,
    "history_state_novelty": 0.0,
}
FROZEN_POLICY_BUDGET = 0.0025

# Selected for destructive/advanced campaign relevance, never for observed V53 model
# performance. Missing names are reported instead of silently substituted.
REQUESTED_DANGEROUS_FAMILIES = (
    "weaponization",
    "exploitation",
    "lateral movement",
    "c&c",
    "exfiltration",
    "ransomware",
    "rdos",
)


def _sequence_sources(state, expected_cutoffs):
    """Rebuild only source/cutoff metadata in exactly the make_sequences iteration order."""
    srcs, cutoffs = [], []
    for src, group in state.groupby("src", sort=False):
        g = group.sort_values("minute").reset_index(drop=True)
        t = g["minute"].astype("int64").to_numpy() // 10**9
        for i in range(HISTORY - 1, len(g) - HORIZON):
            lo = i - HISTORY + 1
            stop = i + HORIZON + 1
            span = t[lo:stop]
            if len(span) != HISTORY + HORIZON or not np.all(np.diff(span) == 60):
                continue
            srcs.append(str(src))
            cutoffs.append(int(t[i]))
    got = np.asarray(cutoffs, dtype=np.int64)
    if len(got) != len(expected_cutoffs) or not np.array_equal(got, expected_cutoffs):
        raise RuntimeError("Sequence source metadata reconstruction diverged from make_sequences")
    return np.asarray(srcs, dtype=object)


def _touches_holdout(sequences, families):
    holdout = set(families)
    history = np.asarray([bool(holdout.intersection(s)) for s in sequences["history_families"]], dtype=bool)
    future = np.asarray([
        any(bool(holdout.intersection(step)) for step in steps)
        for steps in sequences["step_families"]
    ], dtype=bool)
    return history | future


def group_holdout_split(sequences, time_masks, families):
    """Remove every selected family plus neighboring overlapping sequences from development."""
    touched = _touches_holdout(sequences, families)
    cutoff = sequences["cutoff"]
    blocked_times = set()
    for t in cutoff[touched].tolist():
        for k in range(-EMBARGO_STEPS, EMBARGO_STEPS + 1):
            blocked_times.add(int(t + 60 * k))
    overlap = np.asarray([int(t) in blocked_times for t in cutoff], dtype=bool)
    dev_free = ~touched & ~overlap
    return {
        "train": time_masks["train"] & dev_free,
        "calibration": time_masks["calibration"] & dev_free,
        "policy": time_masks["policy"] & dev_free,
        "test_negative": time_masks["test"] & sequences["clean"] & (sequences["y"] == 0),
        "holdout_touched": touched,
        "overlap_blocked": overlap,
    }


def family_presence(sequences, family):
    hist = np.asarray([family in s for s in sequences["history_families"]], dtype=bool)
    future = np.zeros((len(hist), HORIZON), dtype=bool)
    for i, steps in enumerate(sequences["step_families"]):
        for h, fams in enumerate(steps):
            future[i, h] = family in fams
    return hist, future


def _metric_block(positive, negative, score, threshold):
    ids = np.where(positive | negative)[0]
    if int(positive.sum()) == 0 or int(negative.sum()) == 0:
        return {
            "positive_support": int(positive.sum()),
            "negative_support": int(negative.sum()),
            "recall": None,
            "fpr": None,
            "precision": None,
            "f1": None,
        }
    metrics = binary_metrics(positive[ids].astype(int), score[ids], threshold)
    metrics["positive_support"] = int(positive.sum())
    metrics["negative_support"] = int(negative.sum())
    return metrics


def clean_onset_events(sequences, sequence_src, family, score, threshold, allowed_mask=None):
    """Collapse duplicate forecast cutoffs into source+family onset events.

    Only histories with no observed attack at all are eligible. For each source/onset,
    the earliest firing cutoff wins, which is the maximum valid warning lead within the
    frozen four-minute forecast horizon.
    """
    groups = defaultdict(list)
    allowed = np.ones(len(score), dtype=bool) if allowed_mask is None else np.asarray(allowed_mask, dtype=bool)
    for i in range(len(score)):
        if not allowed[i] or not sequences["clean"][i] or family in sequences["history_families"][i]:
            continue
        first_h = None
        for h, fams in enumerate(sequences["step_families"][i]):
            if family in fams:
                first_h = h
                break
        if first_h is None:
            continue
        onset = int(sequences["cutoff"][i] + 60 * (first_h + 1))
        groups[(str(sequence_src[i]), onset)].append({
            "cutoff": int(sequences["cutoff"][i]),
            "lead_seconds": int(60 * (first_h + 1)),
            "score": float(score[i]),
            "alert": bool(score[i] > threshold),
        })

    events = []
    for (src, onset), candidates in sorted(groups.items(), key=lambda x: (x[0][1], x[0][0])):
        fired = [r for r in candidates if r["alert"]]
        best = max(fired, key=lambda r: r["lead_seconds"]) if fired else None
        events.append({
            "source": src,
            "onset_epoch": int(onset),
            "candidate_forecasts": len(candidates),
            "warning_before_onset": best is not None,
            "first_warning_cutoff_epoch": int(best["cutoff"]) if best else None,
            "lead_seconds": int(best["lead_seconds"]) if best else None,
        })

    hits = [e for e in events if e["warning_before_onset"]]
    leads = [float(e["lead_seconds"]) for e in hits]
    summary = {
        "event_support": len(events),
        "warning_hits": len(hits),
        "event_recall": (len(hits) / len(events)) if events else None,
        "lead_seconds": {
            "mean": float(np.mean(leads)) if leads else None,
            "median": float(np.median(leads)) if leads else None,
            "min": float(np.min(leads)) if leads else None,
            "max": float(np.max(leads)) if leads else None,
        },
        "lead_minutes": {
            "mean": float(np.mean(leads) / 60.0) if leads else None,
            "median": float(np.median(leads) / 60.0) if leads else None,
            "min": float(np.min(leads) / 60.0) if leads else None,
            "max": float(np.max(leads) / 60.0) if leads else None,
        },
        "hits_by_lead_seconds": {
            str(sec): int(sum(1 for v in leads if int(v) == sec))
            for sec in (60, 120, 180, 240)
        },
    }
    return summary, events


def _mean_sd(values):
    vals = [float(v) for v in values if v is not None and np.isfinite(v)]
    return {
        "mean": float(np.mean(vals)) if vals else None,
        "sd": float(np.std(vals, ddof=1)) if len(vals) > 1 else None,
    }


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--csv", required=True)
    p.add_argument("--output", required=True)
    p.add_argument("--epochs", type=int, default=12)
    p.add_argument("--seeds", nargs="+", type=int, default=list(SEEDS))
    args = p.parse_args()
    if len(set(args.seeds)) < 3:
        p.error("At least three distinct seeds required")

    out = Path(args.output)
    if out.exists():
        p.error("Output exists; V53 evidence is immutable")
    out.mkdir(parents=True)

    csv_path = Path(args.csv)
    df = pd.read_csv(csv_path, low_memory=False)
    dt, date_col, ts_col, time_method = parse_time(df)
    binary, family, binary_col, family_col, label_profiles = detect_label_hierarchy(df)
    family = family.map(canonical_family_name)
    feature_cols, feature_audit = choose_network_numeric_features(df)
    state, state_features, src_col = build_minute_state(df, dt, binary, family, feature_cols)
    sequences = make_sequences(state, state_features)
    sequence_src = _sequence_sources(state, sequences["cutoff"])
    time_masks, boundaries = temporal_masks(sequences["cutoff"])

    available = sorted({item for steps in sequences["step_families"] for fams in steps for item in fams})
    requested = [canonical_family_name(x) for x in REQUESTED_DANGEROUS_FAMILIES]
    holdout = [x for x in requested if x in available]
    missing = [x for x in requested if x not in available]
    if len(holdout) < 4:
        raise RuntimeError(f"Need >=4 dangerous held-out families; available={available}, selected={holdout}")

    split = group_holdout_split(sequences, time_masks, holdout)
    support = {
        "train": int(split["train"].sum()),
        "calibration": int(split["calibration"].sum()),
        "policy": int(split["policy"].sum()),
        "test_benign_negative": int(split["test_negative"].sum()),
        "holdout_touched_sequences": int(split["holdout_touched"].sum()),
        "overlap_blocked_sequences": int(split["overlap_blocked"].sum()),
    }
    if support["train"] < 50 or support["calibration"] < 20 or support["policy"] < 20:
        raise RuntimeError(f"Insufficient group-holdout development support: {support}")

    report = {
        "protocol": "V53 offline multi-family unknown-dangerous-attack early-warning stress test",
        "claim_boundary": (
            "Public X-IIoTID replay only. Held-out families have zero supervised/development exposure in this V53 model run, "
            "but several family identities were examined by earlier project versions; therefore this is not a fresh project-wide "
            "release holdout, not a real undisclosed zero-day, and lead time is to dataset attack-family onset rather than successful compromise."
        ),
        "safety": "No live attack traffic is generated or transmitted; this workflow operates only on offline public dataset records.",
        "source": {
            "filename": csv_path.name,
            "bytes": int(csv_path.stat().st_size),
            "sha256": sha256(csv_path),
            "rows": int(len(df)),
            "columns": int(len(df.columns)),
        },
        "history_minutes": HISTORY,
        "forecast_horizon_minutes": HORIZON,
        "seeds": list(args.seeds),
        "frozen_v48_fusion": {
            "weights": FROZEN_WEIGHTS,
            "policy_budget": FROZEN_POLICY_BUDGET,
            "tuned_on_v53_holdout": False,
        },
        "release_reference_gate": {"fpr_max": FPR_BUDGET, "recall_min": 0.80},
        "requested_dangerous_families": requested,
        "available_dataset_families": available,
        "held_out_families": holdout,
        "missing_requested_families": missing,
        "group_holdout_support": support,
        "label_columns": {"binary": binary_col, "family": family_col, "profiles": label_profiles},
        "time": {"date_column": date_col, "timestamp_column": ts_col, "method": time_method, "boundaries": boundaries},
        "network_only_feature_audit": {"raw_selected": feature_cols, "state_feature_count": len(state_features), "audit": feature_audit},
        "source_group_column": src_col,
        "state_rows": int(len(state)),
        "sequence_rows": int(len(sequences["X"])),
        "seed_results": {},
        "automatic_containment_approved": False,
    }

    union_future = np.asarray([
        any(bool(set(holdout).intersection(step)) for step in steps)
        for steps in sequences["step_families"]
    ], dtype=bool)

    for seed in args.seeds:
        print(f"V53 seed={seed} held_out={holdout}", flush=True)
        world = train_world_model(
            sequences["X"], sequences["future"], split["train"], split["calibration"], seed, epochs=args.epochs
        )
        components = raw_components(world, sequences, split, seed)
        if components is None:
            raise RuntimeError(f"Seed {seed}: insufficient benign reference")
        score = fused_score(components["evidence"], FROZEN_WEIGHTS)
        threshold = fpr_threshold(score[components["policy_benign"]], FROZEN_POLICY_BUDGET)

        state_eval = union_future | split["test_negative"]
        state_test_mse = float(np.mean((world["pred"][state_eval] - world["future_scaled"][state_eval]) ** 2))
        state_persistence_mse = float(np.mean((world["persistence"][state_eval] - world["future_scaled"][state_eval]) ** 2))

        seed_row = {
            "threshold": float(threshold),
            "state": {
                "validation_mse": world["validation_mse"],
                "validation_persistence_mse": world["validation_persistence_mse"],
                "state_gate_passed": world["state_gate_passed"],
                "stress_eval_mse": state_test_mse,
                "stress_eval_persistence_mse": state_persistence_mse,
            },
            "group": {
                "all_episode_zero_exposure": _metric_block(union_future, split["test_negative"], score, threshold),
                "strict_chronological_tail": _metric_block(time_masks["test"] & union_future, split["test_negative"], score, threshold),
            },
            "families": {},
        }

        for fam in holdout:
            hist, future_steps = family_presence(sequences, fam)
            future_any = future_steps.any(axis=1)
            all_metrics = _metric_block(future_any, split["test_negative"], score, threshold)
            strict_metrics = _metric_block(time_masks["test"] & future_any, split["test_negative"], score, threshold)
            clean_summary, clean_events = clean_onset_events(
                sequences, sequence_src, fam, score, threshold
            )
            strict_summary, strict_events = clean_onset_events(
                sequences, sequence_src, fam, score, threshold, allowed_mask=time_masks["test"]
            )
            seed_row["families"][fam] = {
                "all_episode_zero_exposure": all_metrics,
                "strict_chronological_tail": strict_metrics,
                "clean_history_onset": clean_summary,
                "strict_tail_clean_history_onset": strict_summary,
                "reference_gate_all_episode_passed": bool(
                    world["state_gate_passed"] and
                    all_metrics.get("fpr") is not None and all_metrics["fpr"] <= FPR_BUDGET and
                    all_metrics.get("recall") is not None and all_metrics["recall"] >= 0.80
                ),
            }
            (out / f"seed_{seed}_{fam.replace(' ', '_').replace('&', 'and')}_events.json").write_text(
                json.dumps({"all_clean_events": clean_events, "strict_tail_clean_events": strict_events}, indent=2, allow_nan=False) + "\n"
            )

        report["seed_results"][str(seed)] = seed_row

    family_summary = {}
    for fam in holdout:
        rows = [report["seed_results"][str(s)]["families"][fam] for s in args.seeds]
        family_summary[fam] = {
            "all_episode_recall": _mean_sd([r["all_episode_zero_exposure"].get("recall") for r in rows]),
            "strict_tail_recall": _mean_sd([r["strict_chronological_tail"].get("recall") for r in rows]),
            "fpr": _mean_sd([r["all_episode_zero_exposure"].get("fpr") for r in rows]),
            "clean_onset_event_recall": _mean_sd([r["clean_history_onset"].get("event_recall") for r in rows]),
            "clean_onset_mean_lead_minutes": _mean_sd([r["clean_history_onset"]["lead_minutes"].get("mean") for r in rows]),
            "clean_onset_median_lead_minutes": _mean_sd([r["clean_history_onset"]["lead_minutes"].get("median") for r in rows]),
            "clean_onset_event_support": rows[0]["clean_history_onset"].get("event_support"),
            "strict_tail_clean_onset_event_support": rows[0]["strict_tail_clean_history_onset"].get("event_support"),
            "reference_gate_passed_all_seeds": bool(all(r["reference_gate_all_episode_passed"] for r in rows)),
        }

    report["family_summary"] = family_summary
    report["group_summary"] = {
        "all_episode_recall": _mean_sd([
            report["seed_results"][str(s)]["group"]["all_episode_zero_exposure"].get("recall") for s in args.seeds
        ]),
        "strict_tail_recall": _mean_sd([
            report["seed_results"][str(s)]["group"]["strict_chronological_tail"].get("recall") for s in args.seeds
        ]),
        "fpr": _mean_sd([
            report["seed_results"][str(s)]["group"]["all_episode_zero_exposure"].get("fpr") for s in args.seeds
        ]),
        "state_gate_passed_all_seeds": bool(all(report["seed_results"][str(s)]["state"]["state_gate_passed"] for s in args.seeds)),
    }
    report["lead_time_claim_level"] = "attack_family_onset_only"
    report["verified_compromise_lead_time_supported"] = False
    (out / "summary.json").write_text(json.dumps(report, indent=2, allow_nan=False) + "\n")

    print(json.dumps({
        "held_out_families": holdout,
        "missing_requested_families": missing,
        "group_summary": report["group_summary"],
        "family_summary": family_summary,
        "lead_time_claim_level": report["lead_time_claim_level"],
    }, indent=2, allow_nan=False), flush=True)


if __name__ == "__main__":
    main()
