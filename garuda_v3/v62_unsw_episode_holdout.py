"""V62 independent UNSW-NB15 unseen-family episode holdout audit.

Why V62 exists
---------------
The raw UNSW shards are not suitable as train/calibration/policy/test partitions for
our family-disjoint protocol: several families have no policy support in shard 3 and
no positives in shard 4. V62 therefore defines a prospective-style temporal episode
holdout directly from raw timestamps.

For each attack family, candidate future-attack episodes are discovered only from
label/timestamp support. A candidate is admissible only when there is enough earlier
reserve-free traffic to form train/calibration/policy and enough same-window benign
negative support. The selected family/episode is chosen from those support counts only,
before any model score, recall, FPR, threshold, or test MSE is computed.

The final V57 fusion weights are frozen from X-IIoTID. The V60 persistence-anchored
residual world model is trained only on the earlier UNSW development period with the
selected family excluded. This is an independent public-dataset unseen-family/campaign
simulation, not production zero-day proof.
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path

import numpy as np
import pandas as pd

from .v47_unseen_family import EMBARGO_MINUTES, binary_metrics, build_minute_state, fpr_threshold, make_sequences
from .v48_strict_runner import canonical_family_name, reserve_exposure_mask
from .v48_unseen_fusion import raw_components
from .v54_joint_family_generalization import _future_presence
from .v57_metric_strengthening import extend_evidence, fused_extended
from .v59_unsw_independent_replication import COMMON_FEATURES, adapt_unsw, load_unsw_raw, sha256
from .v60_residual_state_forecasting import train_residual_world_model

EPISODE_GAP_SECONDS = 30 * 60
TEST_MARGIN_SECONDS = 90 * 60
MIN_TRAIN = 500
MIN_CAL = 100
MIN_POLICY = 100
MIN_POSITIVE = 20
MIN_NEGATIVE = 100


def _family_history_mask(seq, family):
    return np.asarray([family in h for h in seq["history_families"]], dtype=bool)


def _episodes_for_family(seq, family):
    future = _future_presence(seq, family)
    hist = _family_history_mask(seq, family)
    candidate = future & ~hist
    times = np.sort(np.unique(seq["cutoff"][candidate]))
    if len(times) == 0:
        return []
    episodes = []
    start = prev = int(times[0])
    for t in times[1:]:
        t = int(t)
        if t - prev > EPISODE_GAP_SECONDS:
            episodes.append((start, prev))
            start = t
        prev = t
    episodes.append((start, prev))
    return episodes


def _build_split(seq, family, episode):
    ep_start, ep_end = episode
    test_start = int(ep_start - TEST_MARGIN_SECONDS)
    test_end = int(ep_end + TEST_MARGIN_SECONDS)
    embargo = EMBARGO_MINUTES * 60

    exposure = reserve_exposure_mask(seq, [family])
    dev_eligible = (seq["cutoff"] < test_start - embargo) & ~exposure
    dev_times = np.unique(seq["cutoff"][dev_eligible])
    if len(dev_times) < 20:
        return None

    b1 = int(dev_times[int(0.60 * (len(dev_times) - 1))])
    b2 = int(dev_times[int(0.80 * (len(dev_times) - 1))])
    train = dev_eligible & (seq["cutoff"] <= b1)
    calibration = dev_eligible & (seq["cutoff"] > b1 + embargo) & (seq["cutoff"] <= b2)
    policy = dev_eligible & (seq["cutoff"] > b2 + embargo)

    test_period = (seq["cutoff"] >= test_start) & (seq["cutoff"] <= test_end)
    hist = _family_history_mask(seq, family)
    positive = test_period & _future_presence(seq, family) & ~hist
    negative = test_period & seq["clean"] & (seq["y"] == 0)
    clean_positive = positive & seq["clean"]

    return {
        "train": train,
        "calibration": calibration,
        "policy": policy,
        "test_negative": negative,
        "test_positive": positive,
        "clean_history_positive": clean_positive,
        "test_period": test_period,
        "episode_start": int(ep_start),
        "episode_end": int(ep_end),
        "test_start": test_start,
        "test_end": test_end,
        "b1": b1,
        "b2": b2,
        "embargo_seconds": int(embargo),
    }


def _support(split):
    return {
        "train": int(split["train"].sum()),
        "calibration": int(split["calibration"].sum()),
        "policy": int(split["policy"].sum()),
        "positive": int(split["test_positive"].sum()),
        "clean_history_positive": int(split["clean_history_positive"].sum()),
        "negative": int(split["test_negative"].sum()),
    }


def _support_ok(s):
    return (
        s["train"] >= MIN_TRAIN
        and s["calibration"] >= MIN_CAL
        and s["policy"] >= MIN_POLICY
        and s["positive"] >= MIN_POSITIVE
        and s["negative"] >= MIN_NEGATIVE
    )


def discover_audits(seq, available, max_audits):
    rows = []
    for family in available:
        for episode in _episodes_for_family(seq, family):
            split = _build_split(seq, family, episode)
            if split is None:
                continue
            support = _support(split)
            if not _support_ok(support):
                continue
            rows.append({
                "family": family,
                "episode": [int(episode[0]), int(episode[1])],
                "support": support,
                "split": split,
            })
    if not rows:
        raise RuntimeError("No UNSW unseen-family episode satisfies the fixed support contract")

    # Support-only selection. Prefer clean-history positives, then total positives,
    # then same-window negatives and later episodes. Never inspect model outcomes.
    rows.sort(
        key=lambda r: (
            r["support"]["clean_history_positive"],
            r["support"]["positive"],
            r["support"]["negative"],
            r["episode"][1],
        ),
        reverse=True,
    )
    selected = []
    used = set()
    for row in rows:
        if row["family"] in used:
            continue
        selected.append(row)
        used.add(row["family"])
        if len(selected) >= max_audits:
            break
    return selected, rows[:50]


def _metrics(positive, negative, score, threshold):
    ids = np.where(positive | negative)[0]
    if positive.sum() == 0 or negative.sum() == 0:
        return {"status": "insufficient_support", "positives": int(positive.sum()), "negatives": int(negative.sum())}
    return binary_metrics(positive[ids].astype(int), score[ids], threshold)


def _mse(pred, target, mask):
    ids = np.where(mask)[0]
    if len(ids) == 0:
        return None
    return float(np.mean((pred[ids] - target[ids]) ** 2))


def evaluate_one(seq, audit, seeds, epochs, frozen):
    family = audit["family"]
    split = audit["split"]
    rows = {}
    for seed in seeds:
        print(f"V62 family={family} seed={seed}", flush=True)
        world = train_residual_world_model(
            seq["X"], seq["future"], split["train"], split["calibration"], seed, epochs=epochs
        )
        base = raw_components(world, seq, split, seed)
        if base is None:
            raise RuntimeError(f"{family} seed={seed}: insufficient benign reference support")
        evidence = extend_evidence(base, seq, split)
        score = fused_extended(evidence, frozen["weights"])
        threshold = fpr_threshold(score[base["policy_benign"]], frozen["policy_budget"])

        all_test = _metrics(split["test_positive"], split["test_negative"], score, threshold)
        clean_test = _metrics(split["clean_history_positive"], split["test_negative"], score, threshold)
        state_mask = split["test_positive"] | split["test_negative"]
        test_mse = _mse(world["pred"], world["future_scaled"], state_mask)
        persistence_mse = _mse(world["persistence"], world["future_scaled"], state_mask)
        pos_mse = _mse(world["pred"], world["future_scaled"], split["test_positive"])
        pos_persistence = _mse(world["persistence"], world["future_scaled"], split["test_positive"])

        rows[str(seed)] = {
            "threshold": float(threshold),
            "selected_state_blend": {"alpha": world["blend_alpha"], "trend_beta": world["trend_beta"]},
            "validation_state_gate_passed": bool(world["state_gate_passed"]),
            "all_future_test": all_test,
            "clean_history_future_test": clean_test,
            "test_state_mse": test_mse,
            "test_persistence_mse": persistence_mse,
            "test_state_gate_passed": bool(test_mse is not None and persistence_mse is not None and test_mse < persistence_mse),
            "positive_state_mse": pos_mse,
            "positive_persistence_mse": pos_persistence,
            "positive_state_gate_passed": bool(pos_mse is not None and pos_persistence is not None and pos_mse < pos_persistence),
        }

    def stat(values):
        vals = [float(v) for v in values if v is not None]
        return {"mean": float(np.mean(vals)) if vals else None, "sd": float(np.std(vals, ddof=1)) if len(vals) > 1 else None}

    all_tests = [r["all_future_test"] for r in rows.values()]
    clean_tests = [r["clean_history_future_test"] for r in rows.values() if r["clean_history_future_test"].get("status") != "insufficient_support"]
    summary = {
        "all_future_recall": stat([m.get("recall") for m in all_tests]),
        "all_future_fpr": stat([m.get("fpr") for m in all_tests]),
        "all_future_precision": stat([m.get("precision") for m in all_tests]),
        "all_future_f1": stat([m.get("f1") for m in all_tests]),
        "clean_history_recall": stat([m.get("recall") for m in clean_tests]),
        "clean_history_fpr": stat([m.get("fpr") for m in clean_tests]),
        "validation_state_gate_passed_all_seeds": all(r["validation_state_gate_passed"] for r in rows.values()),
        "test_state_gate_passed_all_seeds": all(r["test_state_gate_passed"] for r in rows.values()),
        "positive_state_gate_passed_all_seeds": all(r["positive_state_gate_passed"] for r in rows.values()),
        "alert_gate_passed_all_seeds": all(
            r["all_future_test"].get("recall") is not None
            and r["all_future_test"].get("fpr") is not None
            and r["all_future_test"]["recall"] >= 0.80
            and r["all_future_test"]["fpr"] <= 0.01
            for r in rows.values()
        ),
    }
    return {
        "family": family,
        "episode": audit["episode"],
        "support": audit["support"],
        "split_boundaries": {k: split[k] for k in ["episode_start", "episode_end", "test_start", "test_end", "b1", "b2", "embargo_seconds"]},
        "seeds": rows,
        "summary": summary,
    }


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--dataset-root", required=True)
    p.add_argument("--frozen-config", required=True)
    p.add_argument("--output", required=True)
    p.add_argument("--seeds", nargs="+", type=int, default=[42, 43, 44])
    p.add_argument("--epochs", type=int, default=18)
    p.add_argument("--max-audits", type=int, default=2)
    args = p.parse_args()
    if len(set(args.seeds)) < 3:
        p.error("At least three distinct seeds required")

    out = Path(args.output)
    if out.exists():
        p.error("Output exists; V62 evidence is immutable")
    out.mkdir(parents=True)

    raw, shard_audit = load_unsw_raw(Path(args.dataset_root))
    adapted, y, family = adapt_unsw(raw)
    dt = pd.to_datetime(adapted["Timestamp"], unit="s", errors="coerce", utc=True)
    state, fcols, src_col = build_minute_state(adapted, dt, y, family, list(COMMON_FEATURES))
    seq = make_sequences(state, fcols)
    available = sorted({x for steps in seq["step_families"] for fams in steps for x in fams})

    selected, support_audit = discover_audits(seq, available, args.max_audits)
    frozen_path = Path(args.frozen_config)
    frozen = json.loads(frozen_path.read_text())
    results = [evaluate_one(seq, audit, tuple(args.seeds), args.epochs, frozen) for audit in selected]

    report = {
        "protocol": "V62 UNSW-NB15 support-selected temporal episode holdout with frozen V57 fusion",
        "claim_boundary": (
            "Independent public-dataset unseen-family/campaign simulation. Candidate family/episode selection uses only "
            "timestamp/support counts before model metrics. V57 fusion weights and policy budget are frozen from X-IIoTID; "
            "UNSW dataset-specific models are fitted only on earlier reserve-free traffic. Not production zero-day proof."
        ),
        "dataset": "UNSW-NB15 raw four-shard flow corpus combined by original timestamps",
        "dataset_shards": shard_audit,
        "frozen_config_sha256": sha256(frozen_path),
        "fusion_reused_without_selection": True,
        "unsw_metrics_used_for_fusion_selection": False,
        "episode_selection_uses_model_metrics": False,
        "support_contract": {
            "episode_gap_seconds": EPISODE_GAP_SECONDS,
            "test_margin_seconds": TEST_MARGIN_SECONDS,
            "min_train": MIN_TRAIN,
            "min_calibration": MIN_CAL,
            "min_policy": MIN_POLICY,
            "min_positive": MIN_POSITIVE,
            "min_negative": MIN_NEGATIVE,
        },
        "available_families": available,
        "selected_audits": [{"family": a["family"], "episode": a["episode"], "support": a["support"]} for a in selected],
        "support_candidate_audit": [
            {"family": a["family"], "episode": a["episode"], "support": a["support"]}
            for a in support_audit
        ],
        "common_network_features": list(COMMON_FEATURES),
        "source_group_column": src_col,
        "seeds": list(args.seeds),
        "results": results,
    }
    (out / "summary.json").write_text(json.dumps(report, indent=2, allow_nan=False) + "\n")
    print(json.dumps({
        "selected": report["selected_audits"],
        "summary": {r["family"]: r["summary"] for r in results},
    }, indent=2), flush=True)


if __name__ == "__main__":
    main()
